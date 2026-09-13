
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * Each file matched by a "tenant_zone" directive is loaded into a pool
 * residing in the shared memory zone of that directive, which makes its
 * configuration available to all worker processes without a reload.
 *
 * A file is the unit of loading: it owns the pool holding everything parsed
 * from it, and a reference counter.  The file inode and modification time
 * are used to detect that the file changed.  A file that is no longer
 * matched is removed from the zone at once, but its memory is only released
 * once the last request using it is done.
 *
 * A zone is not inherited on reload: what is loaded into it refers to the
 * static configuration of the cycle it was parsed in, and is of no use to
 * the next one.  The new cycle loads everything anew into a new zone, while
 * the processes of the old one keep their own mapping of the old zone, which
 * nobody changes any more, until they exit.
 *
 * Several "tenant_zone" directives may be used, each with its own zone.
 * The parts are searched in the order of their appearance in the
 * configuration, so that the first match wins and an entry shadowed by an
 * earlier part is simply never found.
 */

typedef struct {
    ngx_str_node_t  sn;        /* file name, must be first */
    ngx_queue_t     queue;

    ngx_pool_t     *pool;     /* holds the configuration */

    ngx_atomic_t    refs;
    ngx_uint_t      generation;

    ino_t           ino;
    time_t          mtime;
} ngx_http_tenant_file_t;


typedef struct {
    ngx_rbtree_t      rbtree;   /* by file name */
    ngx_rbtree_node_t sentinel;
    ngx_queue_t       queue;    /* all servers */

    ngx_atomic_t      rwlock;
    ngx_uint_t        generation;
} ngx_http_tenant_sh_t;


typedef struct {
    ngx_http_tenant_sh_t *sh;
    ngx_slab_pool_t      *shpool;

    ngx_shm_zone_t       *shm_zone;
    ngx_str_t             pattern;
} ngx_http_tenant_t;


typedef struct {
    /* of ngx_http_tenant_t *, in configuration order */
    ngx_array_t parts;
} ngx_http_tenant_main_conf_t;


static void *ngx_http_tenant_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_tenant_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_tenant_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_tenant_reload(ngx_cycle_t *cycle,
    void *data);
static ngx_int_t ngx_http_tenant_load(ngx_cycle_t *cycle,
    ngx_http_tenant_t *tz, ngx_str_t *file,
    ngx_file_info_t *fi);
static void ngx_http_tenant_detach(
    ngx_http_tenant_t *tz, ngx_http_tenant_file_t *tf);
static void ngx_http_tenant_release(
    ngx_http_tenant_t *tz, ngx_http_tenant_file_t *tf);


static ngx_command_t  ngx_http_tenant_commands[] = {

    { ngx_string("tenant_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_tenant_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_tenant_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_tenant_create_main_conf,
                                           /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_tenant_module = {
    NGX_MODULE_V1,
    &ngx_http_tenant_module_ctx,  /* module context */
    ngx_http_tenant_commands,     /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_tenant_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_tenant_main_conf_t *tmcf;

    tmcf = ngx_pcalloc(cf->pool,
                        sizeof(ngx_http_tenant_main_conf_t));
    if (tmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&tmcf->parts, cf->pool, 2,
                       sizeof(ngx_http_tenant_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return tmcf;
}


static char *
ngx_http_tenant_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tenant_main_conf_t *tmcf = conf;

    u_char             *p;
    size_t              size;
    ngx_str_t          *value, name, s;
    ngx_dynamic_conf_t *dyn;
    ngx_http_tenant_t  *tz, **dip;

    value = cf->args->elts;

    tz = ngx_pcalloc(cf->pool, sizeof(ngx_http_tenant_t));
    if (tz == NULL) {
        return NGX_CONF_ERROR;
    }

    if (ngx_strncmp(value[1].data, "zone=", 5) != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid parameter \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    name.data = value[1].data + 5;

    p = (u_char *) ngx_strchr(name.data, ':');
    if (p == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone size in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    name.len = p - name.data;

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone name in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    s.data = p + 1;
    s.len = value[1].data + value[1].len - s.data;

    size = ngx_parse_size(&s);

    if (size == (size_t) NGX_ERROR || size < 8 * ngx_pagesize) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone size in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    tz->pattern = value[2];

    if (ngx_conf_full_name(cf->cycle, &tz->pattern, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    tz->shm_zone = ngx_shared_memory_add(cf, &name, size,
                                           &ngx_http_tenant_module);
    if (tz->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (tz->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "zone \"%V\" is already used", &name);
        return NGX_CONF_ERROR;
    }

    tz->shm_zone->init = ngx_http_tenant_init_zone;
    tz->shm_zone->data = tz;

    /*
     * The zone is not inherited on reload.  A configuration loaded into it
     * refers to the static configuration of the cycle it was parsed in, so
     * it is of no use to the next one, while the processes of this one keep
     * their own mapping of the zone until they exit.
     */

    tz->shm_zone->noreuse = 1;

    /*
     * The servers themselves are not loaded while the static configuration
     * is parsed; the reload handler registered here does it once the zone
     * exists, and on every dynamic reload afterwards.
     */

    dyn = ngx_dynamic_add(cf, &tz->pattern);
    if (dyn == NULL) {
        return NGX_CONF_ERROR;
    }

    dyn->handler = ngx_http_tenant_reload;
    dyn->data = tz;

    dip = ngx_array_push(&tmcf->parts);
    if (dip == NULL) {
        return NGX_CONF_ERROR;
    }

    *dip = tz;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_tenant_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_tenant_t *tz = shm_zone->data;

    tz->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    tz->sh = ngx_slab_alloc(tz->shpool,
                            sizeof(ngx_http_tenant_sh_t));
    if (tz->sh == NULL) {
        return NGX_ERROR;
    }

    tz->shpool->data = tz->sh;

    ngx_rbtree_init(&tz->sh->rbtree, &tz->sh->sentinel,
                    ngx_str_rbtree_insert_value);
    ngx_queue_init(&tz->sh->queue);

    tz->sh->rwlock = 0;
    tz->sh->generation = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_tenant_reload(ngx_cycle_t *cycle, void *data)
{
    ngx_http_tenant_t *tz = data;

    ngx_str_t               file;
    ngx_int_t               rc;
    ngx_err_t               err;
    ngx_glob_t              gl;
    ngx_queue_t            *q, *next;
    ngx_uint_t              generation;
    ngx_file_info_t         fi;
    ngx_http_tenant_file_t *tf;

    rc = NGX_OK;

    ngx_memzero(&gl, sizeof(ngx_glob_t));

    gl.pattern = tz->pattern.data;
    gl.log = cycle->log;
    gl.test = 1;

    if (ngx_open_glob(&gl) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      ngx_open_glob_n " \"%s\" failed", gl.pattern);
        return NGX_ERROR;
    }

    ngx_rwlock_wlock(&tz->sh->rwlock);

    generation = ++tz->sh->generation;

    for ( ;; ) {
        if (ngx_read_glob(&gl, &file) != NGX_OK) {
            break;
        }

        if (ngx_file_info(file.data, &fi) == NGX_FILE_ERROR) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                          ngx_file_info_n " \"%V\" failed", &file);
            rc = NGX_ERROR;
            continue;
        }

        tf = (ngx_http_tenant_file_t *)
                 ngx_str_rbtree_lookup(&tz->sh->rbtree, &file,
                                       ngx_crc32_long(file.data, file.len));

        if (tf) {
            if (tf->ino == ngx_file_uniq(&fi)
                && tf->mtime == ngx_file_mtime(&fi))
            {
                /* unchanged */
                tf->generation = generation;
                continue;
            }

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "reloading tenant \"%V\"", &file);

            ngx_http_tenant_detach(tz, tf);

        } else {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "loading tenant \"%V\"", &file);
        }

        if (ngx_http_tenant_load(cycle, tz, &file, &fi) != NGX_OK) {
            rc = NGX_ERROR;
        }
    }

    /* servers whose files are gone are removed from the zone */

    for (q = ngx_queue_head(&tz->sh->queue);
         q != ngx_queue_sentinel(&tz->sh->queue);
         q = next)
    {
        next = ngx_queue_next(q);

        tf = ngx_queue_data(q, ngx_http_tenant_file_t, queue);

        if (tf->generation == generation) {
            continue;
        }

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "removing tenant \"%V\"", &tf->sn.str);

        ngx_http_tenant_detach(tz, tf);
    }

    ngx_rwlock_unlock(&tz->sh->rwlock);

    err = ngx_errno;

    ngx_close_glob(&gl);

    ngx_set_errno(err);

    return rc;
}


static ngx_int_t
ngx_http_tenant_load(ngx_cycle_t *cycle,
    ngx_http_tenant_t *tz, ngx_str_t *file,
    ngx_file_info_t *fi)
{
    ngx_pool_t             *pool;
    ngx_http_tenant_file_t *tf;

    /*
     * The whole server configuration, including this node, is allocated
     * from a pool in the zone, so that releasing the server is a matter
     * of destroying its pool.
     */

    pool = ngx_create_shared_pool(NGX_DEFAULT_POOL_SIZE, cycle->log,
                                  tz->shpool);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "no memory in zone \"%V\" to load \"%V\"",
                      &tz->shm_zone->shm.name, file);
        return NGX_ERROR;
    }

    tf = ngx_pcalloc(pool, sizeof(ngx_http_tenant_file_t) + file->len);
    if (tf == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    tf->sn.str.data = (u_char *) tf + sizeof(ngx_http_tenant_file_t);
    tf->sn.str.len = file->len;
    ngx_memcpy(tf->sn.str.data, file->data, file->len);

    tf->sn.node.key = ngx_crc32_long(tf->sn.str.data, tf->sn.str.len);

    tf->pool = pool;
    tf->refs = 1;
    tf->generation = tz->sh->generation;
    tf->ino = ngx_file_uniq(fi);
    tf->mtime = ngx_file_mtime(fi);

    ngx_rbtree_insert(&tz->sh->rbtree, &tf->sn.node);
    ngx_queue_insert_tail(&tz->sh->queue, &tf->queue);

    return NGX_OK;
}


/*
 * Removes a server from the zone.  Its memory is released once the last
 * request referencing it is done.  The zone must be write locked.
 */

static void
ngx_http_tenant_detach(ngx_http_tenant_t *tz,
    ngx_http_tenant_file_t *tf)
{
    ngx_rbtree_delete(&tz->sh->rbtree, &tf->sn.node);
    ngx_queue_remove(&tf->queue);

    ngx_http_tenant_release(tz, tf);
}


static void
ngx_http_tenant_release(ngx_http_tenant_t *tz,
    ngx_http_tenant_file_t *tf)
{
    if (ngx_atomic_fetch_add(&tf->refs, -1) != 1) {
        return;
    }

    ngx_destroy_pool(tf->pool);
}
