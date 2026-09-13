
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * A file is the unit of loading: it owns the pool holding everything parsed
 * from it, and is released once the last request using it is done.
 */

typedef struct {
    ngx_str_node_t  sn;     /* file name, must be first */
    ngx_queue_t     queue;

    ngx_pool_t     *pool;   /* holds the configuration */

    ngx_atomic_t    refs;
    ngx_uint_t      generation;

    ino_t           ino;
    time_t          mtime;

    /* of ngx_http_core_srv_conf_t *, parsed from this file */
    ngx_array_t    *servers;

    ngx_queue_t     names;  /* ngx_http_tenant_name_t */
} ngx_http_tenant_file_t;


/* the names of the servers listening on one address, kept in a list */

typedef struct {
    ngx_queue_t            queue;
    ngx_http_addr_conf_t  *addr_conf;

    ngx_rbtree_t           names;  /* ngx_http_tenant_name_t */
    ngx_rbtree_node_t      sentinel;
} ngx_http_tenant_addr_t;


typedef struct {
    ngx_str_node_t             sn;     /* server name, must be first */
    ngx_queue_t                queue;  /* in the file */

    ngx_http_addr_conf_t      *addr_conf;
    ngx_http_tenant_addr_t    *addr;   /* set while in the tree */

    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_tenant_file_t    *file;
} ngx_http_tenant_name_t;


typedef struct {
    ngx_rbtree_t       rbtree;  /* by file name */
    ngx_rbtree_node_t  sentinel;
    ngx_queue_t        queue;   /* all files */

    ngx_queue_t        addrs;   /* ngx_http_tenant_addr_t */

    ngx_atomic_t       rwlock;
    ngx_uint_t         generation;
} ngx_http_tenant_sh_t;


typedef struct {
    ngx_http_tenant_sh_t  *sh;
    ngx_slab_pool_t       *shpool;

    ngx_shm_zone_t        *shm_zone;

    /* of ngx_str_t, the patterns of the files loaded into this zone */
    ngx_array_t            patterns;
} ngx_http_tenant_t;


typedef struct {
    /* of ngx_http_tenant_t *, in configuration order */
    ngx_array_t  zones;
} ngx_http_tenant_main_conf_t;


/* the zones an entry point is open to, which is what "tenant" names */

typedef struct {
    /* of ngx_http_tenant_t *, NGX_CONF_UNSET_PTR while unset */
    ngx_array_t  *zones;
} ngx_http_tenant_srv_conf_t;


/* what the one block a tenant holds is parsed into */

typedef struct {
    ngx_http_conf_ctx_t  *ctx;
    void                **main_conf;
    ngx_uint_t            done;
} ngx_http_tenant_block_t;


static void *ngx_http_tenant_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_tenant_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_tenant_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_tenant_zone(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_tenant(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_tenant_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_tenant_reload_pattern(ngx_cycle_t *cycle,
    ngx_http_tenant_t *tz, ngx_str_t *pattern, ngx_uint_t generation);
static ngx_int_t ngx_http_tenant_reload(ngx_cycle_t *cycle, void *data);
static ngx_cycle_t *ngx_http_tenant_copy_cycle(ngx_cycle_t *cycle,
    ngx_pool_t *pool, ngx_pool_t *temp_pool);
static ngx_int_t ngx_http_tenant_allowed(ngx_http_addr_conf_t *addr_conf,
    ngx_http_tenant_t *tz);
static ngx_int_t ngx_http_tenant_names(ngx_cycle_t *cycle,
    ngx_http_tenant_t *tz, ngx_str_t *file, ngx_array_t *ports,
    ngx_pool_t *pool, ngx_http_tenant_file_t *tf);
static ngx_http_addr_conf_t *ngx_http_tenant_addr(ngx_cycle_t *cycle,
    struct sockaddr *sa, socklen_t socklen, int type);
static char *ngx_http_tenant_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_tenant_parse(ngx_cycle_t *cycle,
    ngx_http_tenant_t *tz, ngx_str_t *file, ngx_pool_t *pool,
    ngx_http_tenant_file_t *tf);
static ngx_http_tenant_file_t *ngx_http_tenant_load(
    ngx_cycle_t *cycle, ngx_http_tenant_t *tz, ngx_str_t *file,
    ngx_file_info_t *fi);
static ngx_int_t ngx_http_tenant_attach(
    ngx_http_tenant_t *tz, ngx_http_tenant_file_t *tf);
static ngx_http_tenant_addr_t *ngx_http_tenant_addr_node(
    ngx_http_tenant_t *tz, ngx_http_addr_conf_t *addr_conf);
static void ngx_http_tenant_detach(
    ngx_http_tenant_t *tz, ngx_http_tenant_file_t *tf);
static void ngx_http_tenant_release(ngx_http_tenant_file_t *tf);
static void ngx_http_tenant_cleanup(void *data);


static ngx_command_t  ngx_http_tenant_commands[] = {

    /* the only directive a tenant file may hold */

    { ngx_string("http"),
      NGX_TENANT_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS,
      ngx_http_tenant_block,
      0,
      0,
      NULL },

    { ngx_string("tenant_zone"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_tenant_zone,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("tenant"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_tenant,
      NGX_HTTP_SRV_CONF_OFFSET,
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

    ngx_http_tenant_create_srv_conf,       /* create server configuration */
    ngx_http_tenant_merge_srv_conf,        /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_tenant_module = {
    NGX_MODULE_V1_FLAGS(NGX_HTTP_TENANT_CONF),
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
    ngx_http_tenant_main_conf_t  *tmcf;

    tmcf = ngx_pcalloc(cf->pool,
                        sizeof(ngx_http_tenant_main_conf_t));
    if (tmcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&tmcf->zones, cf->pool, 2,
                       sizeof(ngx_http_tenant_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return tmcf;
}


static void *
ngx_http_tenant_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_tenant_srv_conf_t  *tscf;

    tscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_tenant_srv_conf_t));
    if (tscf == NULL) {
        return NULL;
    }

    tscf->zones = NGX_CONF_UNSET_PTR;

    return tscf;
}


static char *
ngx_http_tenant_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_tenant_srv_conf_t *prev = parent;
    ngx_http_tenant_srv_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->zones, prev->zones, NULL);

    return NGX_CONF_OK;
}


/*
 * "tenant_zone name:size pattern ...".  Repeating it with the same name
 * adds more patterns, the size being needed only the first time.
 */

static char *
ngx_http_tenant_zone(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tenant_main_conf_t *tmcf = conf;

    u_char              *p;
    size_t               size;
    ngx_str_t           *value, name, s, *pattern;
    ngx_uint_t           i;
    ngx_dynamic_conf_t  *dyn;
    ngx_http_tenant_t   *tz, **tzp;

    if (ngx_conf_tenant(cf)) {

        /* tenants do not nest */

        return "is not supported in a tenant";
    }

    value = cf->args->elts;

    name = value[1];

    p = (u_char *) ngx_strchr(name.data, ':');

    if (p) {
        name.len = p - name.data;

        s.data = p + 1;
        s.len = value[1].data + value[1].len - s.data;

        size = ngx_parse_size(&s);

        if (size == (size_t) NGX_ERROR || size < 8 * ngx_pagesize) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid zone size in \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

    } else {
        /* attaching more patterns to a zone declared earlier */
        size = 0;
    }

    if (name.len == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid zone name in \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    tz = NULL;
    tzp = tmcf->zones.elts;

    for (i = 0; i < tmcf->zones.nelts; i++) {
        if (tzp[i]->shm_zone->shm.name.len == name.len
            && ngx_strncmp(tzp[i]->shm_zone->shm.name.data, name.data,
                           name.len)
               == 0)
        {
            tz = tzp[i];
            break;
        }
    }

    if (tz == NULL) {

        if (size == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "no size of the tenant zone \"%V\"", &name);
            return NGX_CONF_ERROR;
        }

        tz = ngx_pcalloc(cf->pool, sizeof(ngx_http_tenant_t));
        if (tz == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_array_init(&tz->patterns, cf->pool, 2, sizeof(ngx_str_t))
            != NGX_OK)
        {
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

        /* what is loaded refers to the cycle that parsed it */

        tz->shm_zone->noreuse = 1;

        /* one handler per zone, so that one pass decides what is gone */

        dyn = ngx_dynamic_add(cf, &tz->shm_zone->shm.name);
        if (dyn == NULL) {
            return NGX_CONF_ERROR;
        }

        dyn->handler = ngx_http_tenant_reload;
        dyn->data = tz;

        tzp = ngx_array_push(&tmcf->zones);
        if (tzp == NULL) {
            return NGX_CONF_ERROR;
        }

        *tzp = tz;

    } else if (size
               && ngx_shared_memory_add(cf, &name, size,
                                        &ngx_http_tenant_module)
                  == NULL)
    {
        return NGX_CONF_ERROR;
    }

    for (i = 2; i < cf->args->nelts; i++) {

        pattern = ngx_array_push(&tz->patterns);
        if (pattern == NULL) {
            return NGX_CONF_ERROR;
        }

        *pattern = value[i];

        if (ngx_conf_full_name(cf->cycle, pattern, 0) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}


/* "tenant name", which opens this entry point to the tenants of a zone */

static char *
ngx_http_tenant(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tenant_srv_conf_t *tscf = conf;

    ngx_str_t                    *value;
    ngx_uint_t                    i;
    ngx_http_tenant_t            *tz, **tzp;
    ngx_http_tenant_main_conf_t  *tmcf;

    if (ngx_conf_tenant(cf)) {

        /*
         * An entry point is opened by the static configuration, which owns
         * the address it listens on; a tenant has none to open.
         */

        return "is not supported in a tenant";
    }

    value = cf->args->elts;

    tmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_tenant_module);

    tz = NULL;
    tzp = tmcf->zones.elts;

    for (i = 0; i < tmcf->zones.nelts; i++) {
        if (tzp[i]->shm_zone->shm.name.len == value[1].len
            && ngx_strncmp(tzp[i]->shm_zone->shm.name.data, value[1].data,
                           value[1].len)
               == 0)
        {
            tz = tzp[i];
            break;
        }
    }

    if (tz == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown tenant zone \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (tscf->zones == NGX_CONF_UNSET_PTR) {
        tscf->zones = ngx_array_create(cf->pool, 2,
                                       sizeof(ngx_http_tenant_t *));
        if (tscf->zones == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    tzp = tscf->zones->elts;

    for (i = 0; i < tscf->zones->nelts; i++) {
        if (tzp[i] == tz) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "duplicate tenant zone \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }
    }

    tzp = ngx_array_push(tscf->zones);
    if (tzp == NULL) {
        return NGX_CONF_ERROR;
    }

    *tzp = tz;

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
    ngx_queue_init(&tz->sh->addrs);

    tz->sh->rwlock = 0;
    tz->sh->generation = 0;

    return NGX_OK;
}


/*
 * Loads every file a pattern of the zone matches, marking what it loads,
 * and what it finds unchanged, with the generation of this reload.
 */

static ngx_int_t
ngx_http_tenant_reload_pattern(ngx_cycle_t *cycle, ngx_http_tenant_t *tz,
    ngx_str_t *pattern, ngx_uint_t generation)
{
    ngx_str_t                file;
    ngx_int_t                rc, rc2;
    ngx_err_t                err;
    ngx_glob_t               gl;
    ngx_file_info_t          fi;
    ngx_http_tenant_file_t  *tf, *ntf;

    ngx_memzero(&gl, sizeof(ngx_glob_t));

    gl.pattern = pattern->data;
    gl.log = cycle->log;
    gl.test = 1;

    if (ngx_open_glob(&gl) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      ngx_open_glob_n " \"%s\" failed", gl.pattern);
        return NGX_ERROR;
    }

    rc = NGX_OK;

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
            if (tf->generation == generation) {
                /* matched by an earlier pattern of this zone */
                continue;
            }

            if (tf->ino == ngx_file_uniq(&fi)
                && tf->mtime == ngx_file_mtime(&fi))
            {
                /* unchanged */
                tf->generation = generation;
                continue;
            }

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "reloading tenant \"%V\"", &file);

        } else {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "loading tenant \"%V\"", &file);
        }

        ntf = ngx_http_tenant_load(cycle, tz, &file, &fi);

        if (ntf == NULL) {
            rc = NGX_ERROR;

            if (tf) {
                /* the version loaded earlier stays in place */
                tf->generation = generation;
            }

            continue;
        }

        ntf->generation = generation;

        ngx_rwlock_wlock(&tz->sh->rwlock);

        if (tf) {
            ngx_http_tenant_detach(tz, tf);
        }

        rc2 = ngx_http_tenant_attach(tz, ntf);

        ngx_rwlock_unlock(&tz->sh->rwlock);

        if (rc2 != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "no memory in zone \"%V\" to load \"%V\"",
                          &tz->shm_zone->shm.name, &file);
            ngx_destroy_pool(ntf->pool);
            rc = NGX_ERROR;
        }
    }

    err = ngx_errno;

    ngx_close_glob(&gl);

    ngx_set_errno(err);

    return rc;
}


static ngx_int_t
ngx_http_tenant_reload(ngx_cycle_t *cycle, void *data)
{
    ngx_http_tenant_t *tz = data;

    ngx_str_t               *pattern;
    ngx_int_t                rc;
    ngx_queue_t             *q, *next;
    ngx_uint_t               i, generation;
    ngx_http_tenant_file_t  *tf;

    /*
     * The master is the only one that changes the zone, so it reads without
     * a lock and parses outside of it; workers never wait for a parse.
     */

    rc = NGX_OK;

    /* one generation for every pattern, so that none shadows another */

    generation = ++tz->sh->generation;

    pattern = tz->patterns.elts;

    for (i = 0; i < tz->patterns.nelts; i++) {
        if (ngx_http_tenant_reload_pattern(cycle, tz, &pattern[i], generation)
            != NGX_OK)
        {
            rc = NGX_ERROR;
        }
    }

    /* tenants whose files are gone are removed from the zone */

    ngx_rwlock_wlock(&tz->sh->rwlock);

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

    return rc;
}


static ngx_http_tenant_file_t *
ngx_http_tenant_load(ngx_cycle_t *cycle,
    ngx_http_tenant_t *tz, ngx_str_t *file,
    ngx_file_info_t *fi)
{
    ngx_pool_t               *pool;
    ngx_http_tenant_file_t  *tf;

    /* releasing the file is destroying its pool */

    pool = ngx_create_shared_pool(NGX_DEFAULT_POOL_SIZE, cycle->log,
                                  tz->shpool);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "no memory in zone \"%V\" to load \"%V\"",
                      &tz->shm_zone->shm.name, file);
        return NULL;
    }

    tf = ngx_pcalloc(pool, sizeof(ngx_http_tenant_file_t) + file->len + 1);
    if (tf == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    tf->sn.str.data = (u_char *) tf + sizeof(ngx_http_tenant_file_t);
    tf->sn.str.len = file->len;
    ngx_memcpy(tf->sn.str.data, file->data, file->len);

    tf->sn.node.key = ngx_crc32_long(tf->sn.str.data, tf->sn.str.len);

    tf->pool = pool;
    tf->refs = 1;
    tf->ino = ngx_file_uniq(fi);
    tf->mtime = ngx_file_mtime(fi);

    ngx_queue_init(&tf->names);

    /*
     * The copy this file keeps, so that what the parse leaves pointing at
     * it is in the pool of the file; the caller's is overwritten.
     */

    if (ngx_http_tenant_parse(cycle, tz, &tf->sn.str, pool, tf)
        != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NULL;
    }

    return tf;
}


/*
 * The http{} block a tenant file holds, at a level of its own so that
 * nothing may appear beside it.
 */

static char *
ngx_http_tenant_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_tenant_block_t *block = cf->handler_conf;

    char                       *rv;
    ngx_uint_t                  m, mi;
    ngx_conf_t                  save;
    ngx_http_module_t          *module;
    ngx_http_core_main_conf_t  *cmcf;

    if (block->done) {
        return "is duplicate";
    }

    block->done = 1;

    save = *cf;

    cf->ctx = block->ctx;
    cf->module_type = NGX_HTTP_MODULE;
    cf->cmd_type = NGX_HTTP_MAIN_CONF;

    /*
     * Made here rather than before the parse, a module may keep the name of
     * the file it is created in.
     */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;
        mi = cf->cycle->modules[m]->ctx_index;

        if (module->create_main_conf) {
            block->main_conf[mi] = module->create_main_conf(cf);
            if (block->main_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_srv_conf) {
            block->ctx->srv_conf[mi] = module->create_srv_conf(cf);
            if (block->ctx->srv_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }

        if (module->create_loc_conf) {
            block->ctx->loc_conf[mi] = module->create_loc_conf(cf);
            if (block->ctx->loc_conf[mi] == NULL) {
                return NGX_CONF_ERROR;
            }
        }
    }

    /* the variables of a tenant are its own */

    for (m = 0; cf->cycle->modules[m]; m++) {
        if (cf->cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cf->cycle->modules[m]->ctx;

        if (module->preconfiguration
            && module->preconfiguration(cf) != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    /*
     * The phase handlers of a tenant are its own, so the arrays they are
     * collected in are made here, before a module pushes onto them.
     */

    cmcf = block->main_conf[ngx_http_core_module.ctx_index];

    if (ngx_http_init_phases(cf, cmcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
}


/*
 * Parses one file into the given shared pool as a configuration of its
 * own, every level of it made by the modules themselves.
 */

static ngx_int_t
ngx_http_tenant_parse(ngx_cycle_t *cycle,
    ngx_http_tenant_t *tz, ngx_str_t *file, ngx_pool_t *pool,
    ngx_http_tenant_file_t *tf)
{
    void                      **main_conf;
    ngx_int_t                   rc;
    ngx_uint_t                  m, mi, s;
    ngx_conf_t                  cf;
    ngx_pool_t                 *temp_pool;
    ngx_cycle_t                *copy;
    ngx_http_module_t          *module;
    ngx_http_conf_ctx_t         ctx, *hctx;
    ngx_http_tenant_block_t     block;
    ngx_http_core_srv_conf_t  **cscfp;
    ngx_http_core_loc_conf_t   *clcf;
    ngx_http_core_main_conf_t  *tcmcf;

    ngx_http_output_header_filter_pt  top_header, top_early_hints;
    ngx_http_output_body_filter_pt    top_body;
    ngx_http_request_body_filter_pt   top_request_body;

    hctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    if (hctx == NULL) {
        return NGX_ERROR;
    }

    /*
     * Every pass builds the same chain, but a module failing leaves it half
     * built, so it is kept here and put back once this tenant is done with.
     */

    top_header = ngx_http_top_header_filter;
    top_early_hints = ngx_http_top_early_hints_filter;
    top_body = ngx_http_top_body_filter;
    top_request_body = ngx_http_top_request_body_filter;

    temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cycle->log);
    if (temp_pool == NULL) {
        return NGX_ERROR;
    }

    copy = ngx_http_tenant_copy_cycle(cycle, pool, temp_pool);
    if (copy == NULL) {
        goto failed;
    }

    /*
     * Every module makes its own, eligible or not; one that cannot, what it
     * keeps there being built before the fork, returns the static one.
     */

    main_conf = ngx_palloc(pool, sizeof(void *) * ngx_http_max_module);
    if (main_conf == NULL) {
        goto failed;
    }

    ngx_memcpy(main_conf, hctx->main_conf,
               sizeof(void *) * ngx_http_max_module);

    /*
     * The http{} level of this tenant, holding nothing but the defaults of
     * every module, which its servers are merged against.
     */

    ctx.main_conf = main_conf;

    ctx.srv_conf = ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module);
    if (ctx.srv_conf == NULL) {
        goto failed;
    }

    ctx.loc_conf = ngx_pcalloc(pool, sizeof(void *) * ngx_http_max_module);
    if (ctx.loc_conf == NULL) {
        goto failed;
    }

    ngx_memzero(&cf, sizeof(ngx_conf_t));

    cf.args = ngx_array_create(temp_pool, 10, sizeof(ngx_str_t));
    if (cf.args == NULL) {
        goto failed;
    }

    cf.name = "tenant";
    cf.cycle = copy;
    cf.pool = pool;
    cf.temp_pool = temp_pool;
    cf.log = cycle->log;
    cf.ctx = &ctx;

    /* the level a tenant file is parsed at holds the http{} block alone */

    block.ctx = &ctx;
    block.main_conf = main_conf;
    block.done = 0;

    cf.handler_conf = &block;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_TENANT_CONF;

    cf.dynamic = NGX_HTTP_TENANT_CONF;
    cf.static_ctx = hctx;

    if (ngx_conf_parse(&cf, file) != NGX_CONF_OK) {
        goto failed;
    }

    if (!block.done) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "no \"http\" block in \"%V\"", file);
        goto failed;
    }

    tcmcf = main_conf[ngx_http_core_module.ctx_index];

    /*
     * Each of those configurations is finished as the one of the static
     * configuration is once it has been parsed.
     */

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cycle->modules[m]->ctx;
        mi = cycle->modules[m]->ctx_index;

        if (main_conf[mi] == hctx->main_conf[mi]) {

            /* what this parse did not create it does not initialize */

            continue;
        }

        if (module->init_main_conf
            && module->init_main_conf(&cf, main_conf[mi]) != NGX_CONF_OK)
        {
            goto failed;
        }
    }

    if (tcmcf->servers.nelts == 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "no server defined in \"%V\"", file);
        goto failed;
    }

    cscfp = tcmcf->servers.elts;

    for (s = 0; s < tcmcf->servers.nelts; s++) {
        if (!cscfp[s]->listen) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "no \"listen\" in a server defined in \"%V\"", file);
            goto failed;
        }
    }

    /*
     * Merging the http{} level with itself turns the placeholders of every
     * module into its defaults; the servers are then merged against it.
     */

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cycle->modules[m]->ctx;
        mi = cycle->modules[m]->ctx_index;

        if (module->merge_srv_conf
            && module->merge_srv_conf(&cf, ctx.srv_conf[mi],
                                      ctx.srv_conf[mi])
               != NGX_CONF_OK)
        {
            goto failed;
        }

        if (module->merge_loc_conf
            && module->merge_loc_conf(&cf, ctx.loc_conf[mi],
                                      ctx.loc_conf[mi])
               != NGX_CONF_OK)
        {
            goto failed;
        }

        if (ngx_http_merge_servers(&cf, tcmcf, cycle->modules[m])
            != NGX_CONF_OK)
        {
            goto failed;
        }
    }

    /*
     * The server names are known once the servers are merged, an unnamed
     * server having been given an empty name by then.
     */

    if (ngx_http_tenant_names(cycle, tz, file, tcmcf->ports, pool, tf)
        != NGX_OK)
    {
        goto failed;
    }

    for (s = 0; s < tcmcf->servers.nelts; s++) {
        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (ngx_http_init_locations(&cf, cscfp[s], clcf) != NGX_OK
            || ngx_http_init_static_location_trees(&cf, clcf) != NGX_OK)
        {
            goto failed;
        }
    }

    /* where a phase handler is pushed onto the arrays of this tenant */

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = cycle->modules[m]->ctx;

        if (module->postconfiguration
            && module->postconfiguration(&cf) != NGX_OK)
        {
            goto failed;
        }
    }

    /* last, as ngx_http_block() does it */

    if (ngx_http_variables_init_vars(&cf) != NGX_OK) {
        goto failed;
    }

    tcmcf->variables_keys = NULL;

    /* both of which a tenant has of its own */

    if (ngx_http_init_phase_handlers(&cf, tcmcf) != NGX_OK
        || ngx_http_init_headers_in_hash(&cf, tcmcf) != NGX_OK)
    {
        goto failed;
    }

    /* the zones this file declared, as ngx_init_cycle() creates its own */

    if (ngx_init_dynamic_zones(&cf) != NGX_OK) {
        goto failed;
    }

    tf->servers = &tcmcf->servers;

    rc = NGX_OK;

    goto done;

failed:

    rc = NGX_ERROR;

done:

    ngx_http_top_header_filter = top_header;
    ngx_http_top_early_hints_filter = top_early_hints;
    ngx_http_top_body_filter = top_body;
    ngx_http_top_request_body_filter = top_request_body;

    ngx_destroy_pool(temp_pool);

    return rc;
}


/*
 * The open files and paths of the running cycle, so that a directive
 * refers to one rather than creating it.  The zones are copied, so that a
 * tenant may declare one of its own without writing into the running list.
 */

static ngx_cycle_t *
ngx_http_tenant_copy_cycle(ngx_cycle_t *cycle, ngx_pool_t *pool,
    ngx_pool_t *temp_pool)
{
    ngx_uint_t        i, n;
    ngx_cycle_t      *copy;
    ngx_shm_zone_t   *zone, *shm_zone;
    ngx_list_part_t  *part;

    copy = ngx_palloc(temp_pool, sizeof(ngx_cycle_t));
    if (copy == NULL) {
        return NULL;
    }

    *copy = *cycle;

    /* ngx_conf_full_name() completes a name from the pool of the cycle */

    copy->pool = pool;
    copy->dynamic_load = 1;

    n = 0;

    for (part = &cycle->shared_memory.part; part; part = part->next) {
        n += part->nelts;
    }

    if (ngx_list_init(&copy->shared_memory, pool, n + 1,
                      sizeof(ngx_shm_zone_t))
        != NGX_OK)
    {
        return NULL;
    }

    for (part = &cycle->shared_memory.part; part; part = part->next) {
        shm_zone = part->elts;

        for (i = 0; i < part->nelts; i++) {
            zone = ngx_list_push(&copy->shared_memory);
            if (zone == NULL) {
                return NULL;
            }

            *zone = shm_zone[i];
        }
    }

    if (ngx_array_init(&copy->dynamic, temp_pool, 1,
                       sizeof(ngx_dynamic_conf_t))
        != NGX_OK)
    {
        return NULL;
    }

    if (ngx_array_init(&copy->config_dump, temp_pool, 1,
                       sizeof(ngx_conf_dump_t))
        != NGX_OK)
    {
        return NULL;
    }

    ngx_rbtree_init(&copy->config_dump_rbtree, &copy->config_dump_sentinel,
                    ngx_str_rbtree_insert_value);

    return copy;
}


/*
 * Indexes the servers of a file by address and name.  The address must be
 * one the static configuration listens on, matched exactly, narrowing a
 * wildcard not being something a tenant can express.
 */

static ngx_int_t
ngx_http_tenant_allowed(ngx_http_addr_conf_t *addr_conf,
    ngx_http_tenant_t *tz)
{
    ngx_uint_t                   i;
    ngx_http_tenant_t          **tzp;
    ngx_http_tenant_srv_conf_t  *tscf;

    tscf = addr_conf->default_server->ctx->srv_conf[
                                           ngx_http_tenant_module.ctx_index];

    if (tscf->zones == NULL) {
        return NGX_DECLINED;
    }

    tzp = tscf->zones->elts;

    for (i = 0; i < tscf->zones->nelts; i++) {
        if (tzp[i] == tz) {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_tenant_names(ngx_cycle_t *cycle, ngx_http_tenant_t *tz,
    ngx_str_t *file, ngx_array_t *ports, ngx_pool_t *pool,
    ngx_http_tenant_file_t *tf)
{
    char                       *name;
    ngx_uint_t                  p, a, s, n;
    ngx_http_conf_port_t       *port;
    ngx_http_conf_addr_t       *addr;
    ngx_http_addr_conf_t       *addr_conf;
    ngx_http_server_name_t     *sn;
    ngx_http_tenant_name_t    *tn;
    ngx_http_core_srv_conf_t  **cscfp;

    port = ports->elts;

    for (p = 0; p < ports->nelts; p++) {

        addr = port[p].addrs.elts;

        for (a = 0; a < port[p].addrs.nelts; a++) {

            addr_conf = ngx_http_tenant_addr(cycle,
                                                      addr[a].opt.sockaddr,
                                                      addr[a].opt.socklen,
                                                      addr[a].opt.type);
            if (addr_conf == NULL) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "\"listen %V\" in \"%V\" does not match any "
                              "address the static configuration listens on",
                              &addr[a].opt.addr_text, file);
                return NGX_ERROR;
            }

            if (ngx_http_tenant_allowed(addr_conf, tz) != NGX_OK) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "\"listen %V\" in \"%V\" names an address "
                              "not open to the tenant zone \"%V\"",
                              &addr[a].opt.addr_text, file,
                              &tz->shm_zone->shm.name);
                return NGX_ERROR;
            }

            /* it has to describe the address as the static one does */

            if (addr[a].opt.ssl != addr_conf->ssl) {
                name = "ssl";

            } else if (addr[a].opt.http2 != addr_conf->http2) {
                name = "http2";

            } else if (addr[a].opt.proxy_protocol
                       != addr_conf->proxy_protocol)
            {
                name = "proxy_protocol";

            } else {
                name = NULL;
            }

            if (name) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                              "\"listen %V\" in \"%V\" differs from the "
                              "static configuration in \"%s\"",
                              &addr[a].opt.addr_text, file, name);
                return NGX_ERROR;
            }

            cscfp = addr[a].servers.elts;

            for (s = 0; s < addr[a].servers.nelts; s++) {

                sn = cscfp[s]->server_names.elts;

                for (n = 0; n < cscfp[s]->server_names.nelts; n++) {

                    if (sn[n].name.len == 0) {
                        continue;
                    }

                    tn = ngx_palloc(pool, sizeof(ngx_http_tenant_name_t));
                    if (tn == NULL) {
                        return NGX_ERROR;
                    }

                    tn->sn.str = sn[n].name;
                    tn->sn.node.key = ngx_crc32_long(sn[n].name.data,
                                                     sn[n].name.len);
                    tn->addr_conf = addr_conf;
                    tn->addr = NULL;
                    tn->cscf = cscfp[s];
                    tn->file = tf;

                    ngx_queue_insert_tail(&tf->names, &tn->queue);
                }
            }
        }
    }

    if (ngx_queue_empty(&tf->names)) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "no \"server_name\" in \"%V\"", file);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * The address configuration the static configuration keeps for an address,
 * or NULL if it does not listen on it.
 */

static ngx_http_addr_conf_t *
ngx_http_tenant_addr(ngx_cycle_t *cycle, struct sockaddr *sa,
    socklen_t socklen, int type)
{
    ngx_uint_t            i, n;
    ngx_listening_t      *ls;
    ngx_http_port_t      *hport;
    ngx_http_in_addr_t   *addr;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    ngx_http_in6_addr_t  *addr6;
    struct sockaddr_in6  *sin6;
#endif

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {

        if (ls[i].handler != ngx_http_init_connection
            || ls[i].type != type)
        {
            continue;
        }

        if (ls[i].sockaddr->sa_family != sa->sa_family
            || ngx_inet_get_port(ls[i].sockaddr) != ngx_inet_get_port(sa))
        {
            continue;
        }

        hport = ls[i].servers;

        switch (sa->sa_family) {

#if (NGX_HAVE_INET6)
        case AF_INET6:
            sin6 = (struct sockaddr_in6 *) sa;
            addr6 = hport->addrs;

            for (n = 0; n < hport->naddrs; n++) {
                if (ngx_memcmp(&addr6[n].addr6, &sin6->sin6_addr, 16) == 0) {
                    return &addr6[n].conf;
                }
            }

            break;
#endif

#if (NGX_HAVE_UNIX_DOMAIN)
        case AF_UNIX:
            addr = hport->addrs;

            if (ngx_cmp_sockaddr(ls[i].sockaddr, ls[i].socklen, sa, socklen, 1)
                == NGX_OK)
            {
                return &addr[0].conf;
            }

            break;
#endif

        default: /* AF_INET */
            sin = (struct sockaddr_in *) sa;
            addr = hport->addrs;

            for (n = 0; n < hport->naddrs; n++) {
                if (addr[n].addr == sin->sin_addr.s_addr) {
                    return &addr[n].conf;
                }
            }

            break;
        }
    }

    return NULL;
}


/*
 * Adds a file to the zone, making its servers available to the workers.
 * The zone must be write locked.
 */

static ngx_int_t
ngx_http_tenant_attach(ngx_http_tenant_t *tz,
    ngx_http_tenant_file_t *tf)
{
    ngx_queue_t              *q;
    ngx_http_tenant_addr_t  *ta;
    ngx_http_tenant_name_t  *tn;

    /*
     * The address of every name is resolved before anything is inserted, so
     * that running out of memory here leaves the zone as it was.
     */

    for (q = ngx_queue_head(&tf->names);
         q != ngx_queue_sentinel(&tf->names);
         q = ngx_queue_next(q))
    {
        tn = ngx_queue_data(q, ngx_http_tenant_name_t, queue);

        ta = ngx_http_tenant_addr_node(tz, tn->addr_conf);
        if (ta == NULL) {
            return NGX_ERROR;
        }

        tn->addr = ta;
    }

    for (q = ngx_queue_head(&tf->names);
         q != ngx_queue_sentinel(&tf->names);
         q = ngx_queue_next(q))
    {
        tn = ngx_queue_data(q, ngx_http_tenant_name_t, queue);

        ngx_rbtree_insert(&tn->addr->names, &tn->sn.node);
    }

    ngx_rbtree_insert(&tz->sh->rbtree, &tf->sn.node);
    ngx_queue_insert_tail(&tz->sh->queue, &tf->queue);

    return NGX_OK;
}


/* lives as long as the zone; an empty one is reused by the next file */

static ngx_http_tenant_addr_t *
ngx_http_tenant_addr_node(ngx_http_tenant_t *tz,
    ngx_http_addr_conf_t *addr_conf)
{
    ngx_queue_t              *q;
    ngx_http_tenant_addr_t  *ta;

    for (q = ngx_queue_head(&tz->sh->addrs);
         q != ngx_queue_sentinel(&tz->sh->addrs);
         q = ngx_queue_next(q))
    {
        ta = ngx_queue_data(q, ngx_http_tenant_addr_t, queue);

        if (ta->addr_conf == addr_conf) {
            return ta;
        }
    }

    ta = ngx_slab_alloc(tz->shpool, sizeof(ngx_http_tenant_addr_t));
    if (ta == NULL) {
        return NULL;
    }

    ta->addr_conf = addr_conf;

    ngx_rbtree_init(&ta->names, &ta->sentinel, ngx_str_rbtree_insert_value);

    ngx_queue_insert_tail(&tz->sh->addrs, &ta->queue);

    return ta;
}


/*
 * Removes a file from the zone.  Its memory is released once the last
 * request referencing it is done.  The zone must be write locked.
 */

static void
ngx_http_tenant_detach(ngx_http_tenant_t *tz,
    ngx_http_tenant_file_t *tf)
{
    ngx_queue_t              *q;
    ngx_http_tenant_name_t  *tn;

    for (q = ngx_queue_head(&tf->names);
         q != ngx_queue_sentinel(&tf->names);
         q = ngx_queue_next(q))
    {
        tn = ngx_queue_data(q, ngx_http_tenant_name_t, queue);

        ngx_rbtree_delete(&tn->addr->names, &tn->sn.node);
        tn->addr = NULL;
    }

    ngx_rbtree_delete(&tz->sh->rbtree, &tf->sn.node);
    ngx_queue_remove(&tf->queue);

    ngx_http_tenant_release(tf);
}


static void
ngx_http_tenant_release(ngx_http_tenant_file_t *tf)
{
    if (ngx_atomic_fetch_add(&tf->refs, -1) != 1) {
        return;
    }

    ngx_destroy_pool(tf->pool);
}


static void
ngx_http_tenant_cleanup(void *data)
{
    ngx_http_tenant_release(data);
}


/*
 * Looks a name up among the tenants of the address the request arrived on,
 * in the zones this entry point was opened to.  A reference to the file is
 * held until the request is done.
 */

ngx_int_t
ngx_http_tenant_find(ngx_http_request_t *r, ngx_str_t *host,
    ngx_http_core_srv_conf_t **cscfp)
{
    uint32_t                     hash;
    ngx_uint_t                   i;
    ngx_queue_t                 *q;
    ngx_pool_cleanup_t          *cln;
    ngx_http_addr_conf_t        *addr_conf;
    ngx_http_tenant_t           *tz, **tzp;
    ngx_http_tenant_addr_t      *ta;
    ngx_http_tenant_file_t      *tf;
    ngx_http_tenant_name_t      *tn;
    ngx_http_core_srv_conf_t    *cscf;
    ngx_http_tenant_srv_conf_t  *tscf;

    if (host->len == 0) {
        return NGX_DECLINED;
    }

    tscf = ngx_http_get_module_srv_conf(r, ngx_http_tenant_module);

    if (tscf->zones == NULL) {
        return NGX_DECLINED;
    }

    addr_conf = r->http_connection->addr_conf;

    hash = ngx_crc32_long(host->data, host->len);

    tzp = tscf->zones->elts;

    for (i = 0; i < tscf->zones->nelts; i++) {
        tz = tzp[i];

        cscf = NULL;
        tf = NULL;

        ngx_rwlock_rlock(&tz->sh->rwlock);

        for (q = ngx_queue_head(&tz->sh->addrs);
             q != ngx_queue_sentinel(&tz->sh->addrs);
             q = ngx_queue_next(q))
        {
            ta = ngx_queue_data(q, ngx_http_tenant_addr_t, queue);

            if (ta->addr_conf != addr_conf) {
                continue;
            }

            tn = (ngx_http_tenant_name_t *)
                     ngx_str_rbtree_lookup(&ta->names, host, hash);

            if (tn) {
                cscf = tn->cscf;
                tf = tn->file;

                (void) ngx_atomic_fetch_add(&tf->refs, 1);
            }

            break;
        }

        ngx_rwlock_unlock(&tz->sh->rwlock);

        if (cscf == NULL) {
            continue;
        }

        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            ngx_http_tenant_release(tf);
            return NGX_ERROR;
        }

        cln->handler = ngx_http_tenant_cleanup;
        cln->data = tf;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "tenant \"%V\" in \"%V\"",
                       host, &tf->sn.str);

        *cscfp = cscf;

        return NGX_OK;
    }

    return NGX_DECLINED;
}
