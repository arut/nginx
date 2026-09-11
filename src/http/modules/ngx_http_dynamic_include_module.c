
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*
 * Each file matched by a "dynamic_include" directive is loaded into a pool
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
 * Several "dynamic_include" directives may be used, each with its own zone.
 * The parts are searched in the order of their appearance in the
 * configuration, so that the first match wins and an entry shadowed by an
 * earlier part is simply never found.
 */

typedef struct {
    ngx_str_node_t                 sn;        /* file name, must be first */
    ngx_queue_t                    queue;

    ngx_pool_t                    *pool;     /* holds the configuration */

    ngx_atomic_t                   refs;
    ngx_uint_t                     generation;

    ino_t                          ino;
    time_t                         mtime;

    /* of ngx_http_core_srv_conf_t *, parsed from this file */
    ngx_array_t                   *servers;

    ngx_queue_t                    names;    /* ngx_http_dynamic_name_t */
} ngx_http_dynamic_file_t;


/*
 * The names of the servers listening on one address of the static
 * configuration.  There are as many of these as there are addresses the
 * dynamic servers listen on, which is why they are kept in a list.
 */

typedef struct {
    ngx_queue_t                    queue;
    ngx_http_addr_conf_t          *addr_conf;

    ngx_rbtree_t                   names;    /* ngx_http_dynamic_name_t */
    ngx_rbtree_node_t              sentinel;
} ngx_http_dynamic_addr_t;


typedef struct {
    ngx_str_node_t                 sn;        /* server name, must be first */
    ngx_queue_t                    queue;     /* in the file */

    ngx_http_addr_conf_t          *addr_conf;
    ngx_http_dynamic_addr_t       *addr;      /* set while in the tree */

    ngx_http_core_srv_conf_t      *cscf;
    ngx_http_dynamic_file_t       *file;
} ngx_http_dynamic_name_t;


typedef struct {
    ngx_rbtree_t                   rbtree;   /* by file name */
    ngx_rbtree_node_t              sentinel;
    ngx_queue_t                    queue;    /* all files */

    ngx_queue_t                    addrs;    /* ngx_http_dynamic_addr_t */

    ngx_atomic_t                   rwlock;
    ngx_uint_t                     generation;
} ngx_http_dynamic_include_sh_t;


typedef struct {
    ngx_http_dynamic_include_sh_t *sh;
    ngx_slab_pool_t               *shpool;

    ngx_shm_zone_t                *shm_zone;
    ngx_str_t                      pattern;
} ngx_http_dynamic_include_t;


typedef struct {
    /* of ngx_http_dynamic_include_t *, in configuration order */
    ngx_array_t                    parts;
} ngx_http_dynamic_include_main_conf_t;


static void *ngx_http_dynamic_include_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_dynamic_include(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static ngx_int_t ngx_http_dynamic_include_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_dynamic_include_reload(ngx_cycle_t *cycle,
    void *data);
static ngx_cycle_t *ngx_http_dynamic_include_copy_cycle(ngx_cycle_t *cycle,
    ngx_pool_t *pool, ngx_pool_t *temp_pool);
static ngx_int_t ngx_http_dynamic_include_names(ngx_cycle_t *cycle,
    ngx_str_t *file, ngx_array_t *ports, ngx_pool_t *pool,
    ngx_http_dynamic_file_t *df);
static ngx_http_addr_conf_t *ngx_http_dynamic_include_addr(ngx_cycle_t *cycle,
    struct sockaddr *sa, socklen_t socklen, int type);
static ngx_int_t ngx_http_dynamic_include_parse(ngx_cycle_t *cycle,
    ngx_http_dynamic_include_t *di, ngx_str_t *file, ngx_pool_t *pool,
    ngx_http_dynamic_file_t *df);
static ngx_http_dynamic_file_t *ngx_http_dynamic_include_load(
    ngx_cycle_t *cycle, ngx_http_dynamic_include_t *di, ngx_str_t *file,
    ngx_file_info_t *fi);
static ngx_int_t ngx_http_dynamic_include_attach(
    ngx_http_dynamic_include_t *di, ngx_http_dynamic_file_t *df);
static ngx_http_dynamic_addr_t *ngx_http_dynamic_include_addr_node(
    ngx_http_dynamic_include_t *di, ngx_http_addr_conf_t *addr_conf);
static void ngx_http_dynamic_include_detach(
    ngx_http_dynamic_include_t *di, ngx_http_dynamic_file_t *df);
static void ngx_http_dynamic_include_release(ngx_http_dynamic_file_t *df);
static void ngx_http_dynamic_include_cleanup(void *data);


static ngx_command_t  ngx_http_dynamic_include_commands[] = {

    { ngx_string("dynamic_include"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_dynamic_include,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_dynamic_include_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    ngx_http_dynamic_include_create_main_conf,
                                           /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_dynamic_include_module = {
    NGX_MODULE_V1,
    &ngx_http_dynamic_include_module_ctx,  /* module context */
    ngx_http_dynamic_include_commands,     /* module directives */
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
ngx_http_dynamic_include_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_dynamic_include_main_conf_t  *dimcf;

    dimcf = ngx_pcalloc(cf->pool,
                        sizeof(ngx_http_dynamic_include_main_conf_t));
    if (dimcf == NULL) {
        return NULL;
    }

    if (ngx_array_init(&dimcf->parts, cf->pool, 2,
                       sizeof(ngx_http_dynamic_include_t *))
        != NGX_OK)
    {
        return NULL;
    }

    return dimcf;
}


static char *
ngx_http_dynamic_include(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_dynamic_include_main_conf_t *dimcf = conf;

    u_char                      *p;
    size_t                       size;
    ngx_str_t                   *value, name, s;
    ngx_dynamic_conf_t          *dyn;
    ngx_http_dynamic_include_t  *di, **dip;

    value = cf->args->elts;

    di = ngx_pcalloc(cf->pool, sizeof(ngx_http_dynamic_include_t));
    if (di == NULL) {
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

    di->pattern = value[2];

    if (ngx_conf_full_name(cf->cycle, &di->pattern, 0) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    di->shm_zone = ngx_shared_memory_add(cf, &name, size,
                                           &ngx_http_dynamic_include_module);
    if (di->shm_zone == NULL) {
        return NGX_CONF_ERROR;
    }

    if (di->shm_zone->data) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "zone \"%V\" is already used", &name);
        return NGX_CONF_ERROR;
    }

    di->shm_zone->init = ngx_http_dynamic_include_init_zone;
    di->shm_zone->data = di;

    /*
     * The zone is not inherited on reload.  A configuration loaded into it
     * refers to the static configuration of the cycle it was parsed in, so
     * it is of no use to the next one, while the processes of this one keep
     * their own mapping of the zone until they exit.
     */

    di->shm_zone->noreuse = 1;

    /*
     * The servers themselves are not loaded while the static configuration
     * is parsed; the reload handler registered here does it once the zone
     * exists, and on every dynamic reload afterwards.
     */

    dyn = ngx_dynamic_add(cf, &di->pattern);
    if (dyn == NULL) {
        return NGX_CONF_ERROR;
    }

    dyn->handler = ngx_http_dynamic_include_reload;
    dyn->data = di;

    dip = ngx_array_push(&dimcf->parts);
    if (dip == NULL) {
        return NGX_CONF_ERROR;
    }

    *dip = di;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_dynamic_include_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_dynamic_include_t *di = shm_zone->data;

    di->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    di->sh = ngx_slab_alloc(di->shpool,
                            sizeof(ngx_http_dynamic_include_sh_t));
    if (di->sh == NULL) {
        return NGX_ERROR;
    }

    di->shpool->data = di->sh;

    ngx_rbtree_init(&di->sh->rbtree, &di->sh->sentinel,
                    ngx_str_rbtree_insert_value);
    ngx_queue_init(&di->sh->queue);
    ngx_queue_init(&di->sh->addrs);

    di->sh->rwlock = 0;
    di->sh->generation = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_dynamic_include_reload(ngx_cycle_t *cycle, void *data)
{
    ngx_http_dynamic_include_t *di = data;

    ngx_str_t                   file;
    ngx_int_t                   rc, rc2;
    ngx_err_t                   err;
    ngx_glob_t                  gl;
    ngx_queue_t                *q, *next;
    ngx_uint_t                  generation;
    ngx_file_info_t             fi;
    ngx_http_dynamic_file_t    *df, *ndf;

    /*
     * The master process is the only one that changes the zone, so it reads
     * it without a lock and takes the write lock only around the changes.
     * A file is parsed outside of the lock, which keeps the workers from
     * waiting for it.
     */

    rc = NGX_OK;

    ngx_memzero(&gl, sizeof(ngx_glob_t));

    gl.pattern = di->pattern.data;
    gl.log = cycle->log;
    gl.test = 1;

    if (ngx_open_glob(&gl) != NGX_OK) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      ngx_open_glob_n " \"%s\" failed", gl.pattern);
        return NGX_ERROR;
    }

    generation = ++di->sh->generation;

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

        df = (ngx_http_dynamic_file_t *)
                 ngx_str_rbtree_lookup(&di->sh->rbtree, &file,
                                       ngx_crc32_long(file.data, file.len));

        if (df) {
            if (df->ino == ngx_file_uniq(&fi)
                && df->mtime == ngx_file_mtime(&fi))
            {
                /* unchanged */
                df->generation = generation;
                continue;
            }

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "reloading dynamic configuration \"%V\"", &file);

        } else {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "loading dynamic configuration \"%V\"", &file);
        }

        ndf = ngx_http_dynamic_include_load(cycle, di, &file, &fi);

        if (ndf == NULL) {
            rc = NGX_ERROR;

            if (df) {
                /* the version loaded earlier stays in place */
                df->generation = generation;
            }

            continue;
        }

        ndf->generation = generation;

        ngx_rwlock_wlock(&di->sh->rwlock);

        if (df) {
            ngx_http_dynamic_include_detach(di, df);
        }

        rc2 = ngx_http_dynamic_include_attach(di, ndf);

        ngx_rwlock_unlock(&di->sh->rwlock);

        if (rc2 != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                          "no memory in zone \"%V\" to load \"%V\"",
                          &di->shm_zone->shm.name, &file);
            ngx_destroy_pool(ndf->pool);
            rc = NGX_ERROR;
        }
    }

    /* servers whose files are gone are removed from the zone */

    ngx_rwlock_wlock(&di->sh->rwlock);

    for (q = ngx_queue_head(&di->sh->queue);
         q != ngx_queue_sentinel(&di->sh->queue);
         q = next)
    {
        next = ngx_queue_next(q);

        df = ngx_queue_data(q, ngx_http_dynamic_file_t, queue);

        if (df->generation == generation) {
            continue;
        }

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "removing dynamic configuration \"%V\"", &df->sn.str);

        ngx_http_dynamic_include_detach(di, df);
    }

    ngx_rwlock_unlock(&di->sh->rwlock);

    err = ngx_errno;

    ngx_close_glob(&gl);

    ngx_set_errno(err);

    return rc;
}


static ngx_http_dynamic_file_t *
ngx_http_dynamic_include_load(ngx_cycle_t *cycle,
    ngx_http_dynamic_include_t *di, ngx_str_t *file,
    ngx_file_info_t *fi)
{
    ngx_pool_t               *pool;
    ngx_http_dynamic_file_t  *df;

    /*
     * Everything parsed from the file, including this node, is allocated
     * from a pool in the zone, so that releasing the file is a matter of
     * destroying its pool.
     */

    pool = ngx_create_shared_pool(NGX_DEFAULT_POOL_SIZE, cycle->log,
                                  di->shpool);
    if (pool == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "no memory in zone \"%V\" to load \"%V\"",
                      &di->shm_zone->shm.name, file);
        return NULL;
    }

    df = ngx_pcalloc(pool, sizeof(ngx_http_dynamic_file_t) + file->len + 1);
    if (df == NULL) {
        ngx_destroy_pool(pool);
        return NULL;
    }

    df->sn.str.data = (u_char *) df + sizeof(ngx_http_dynamic_file_t);
    df->sn.str.len = file->len;
    ngx_memcpy(df->sn.str.data, file->data, file->len);

    df->sn.node.key = ngx_crc32_long(df->sn.str.data, df->sn.str.len);

    df->pool = pool;
    df->refs = 1;
    df->ino = ngx_file_uniq(fi);
    df->mtime = ngx_file_mtime(fi);

    ngx_queue_init(&df->names);

    /*
     * The name is parsed from the copy of it this file keeps, so that what
     * the parse leaves pointing at it, the file name a server reports in a
     * diagnostic among other things, points into the pool of the file.  The
     * name the caller has is in the memory the directory is read into, which
     * the next name read replaces.
     */

    if (ngx_http_dynamic_include_parse(cycle, di, &df->sn.str, pool, df)
        != NGX_OK)
    {
        ngx_destroy_pool(pool);
        return NULL;
    }

    return df;
}


/*
 * Parses one file into the given shared pool.  The file is parsed in the
 * http{} context of the static configuration, with a copy of the cycle so
 * that nothing is appended to the lists of the running one, and with the
 * core main configuration shadowed so that the servers the file defines
 * are collected here instead of in the static configuration.
 */

static ngx_int_t
ngx_http_dynamic_include_parse(ngx_cycle_t *cycle,
    ngx_http_dynamic_include_t *di, ngx_str_t *file, ngx_pool_t *pool,
    ngx_http_dynamic_file_t *df)
{
    void                       **main_conf;
    ngx_uint_t                   m, mi, s;
    ngx_conf_t                   cf;
    ngx_pool_t                  *temp_pool;
    ngx_cycle_t                 *copy;
    ngx_http_module_t           *module;
    ngx_http_conf_ctx_t          ctx, *hctx;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_main_conf_t   *dcmcf;

    hctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];
    if (hctx == NULL) {
        return NGX_ERROR;
    }

    temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, cycle->log);
    if (temp_pool == NULL) {
        return NGX_ERROR;
    }

    copy = ngx_http_dynamic_include_copy_cycle(cycle, pool, temp_pool);
    if (copy == NULL) {
        goto failed;
    }

    /*
     * A module keeping something at the main level that this file may add
     * to makes a configuration of its own from that of the static
     * configuration, which is what cf->ctx holds while it does.  Every
     * other module shares the one of the static configuration, as it does
     * at the levels below.
     */

    main_conf = ngx_palloc(pool, sizeof(void *) * ngx_http_max_module);
    if (main_conf == NULL) {
        goto failed;
    }

    ngx_memcpy(main_conf, hctx->main_conf,
               sizeof(void *) * ngx_http_max_module);

    ctx.main_conf = hctx->main_conf;
    ctx.srv_conf = hctx->srv_conf;
    ctx.loc_conf = hctx->loc_conf;

    ngx_memzero(&cf, sizeof(ngx_conf_t));

    cf.args = ngx_array_create(temp_pool, 10, sizeof(ngx_str_t));
    if (cf.args == NULL) {
        goto failed;
    }

    cf.name = "dynamic";
    cf.cycle = copy;
    cf.pool = pool;
    cf.temp_pool = temp_pool;
    cf.log = cycle->log;
    cf.ctx = &ctx;
    cf.module_type = NGX_HTTP_MODULE;
    cf.cmd_type = NGX_HTTP_MAIN_CONF;
    /*
     * At this level the file has only the main configurations of its own,
     * so a directive kept at one of the levels below, which here are those
     * of the static configuration, is refused rather than written there.
     */

    cf.dynamic = NGX_HTTP_DYN_CONF;

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (!ngx_module_dynconf(cycle->modules[m], NGX_HTTP_DYN_CONF)) {
            continue;
        }

        module = cycle->modules[m]->ctx;
        mi = cycle->modules[m]->ctx_index;

        if (module->create_main_conf == NULL) {
            continue;
        }

        main_conf[mi] = module->create_main_conf(&cf);
        if (main_conf[mi] == NULL) {
            goto failed;
        }
    }

    ctx.main_conf = main_conf;

    if (ngx_conf_parse(&cf, file) != NGX_CONF_OK) {
        goto failed;
    }

    /*
     * Each of those configurations is finished as the one of the static
     * configuration is once it has been parsed.
     */

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (!ngx_module_dynconf(cycle->modules[m], NGX_HTTP_DYN_CONF)) {
            continue;
        }

        module = cycle->modules[m]->ctx;
        mi = cycle->modules[m]->ctx_index;

        if (main_conf[mi] == hctx->main_conf[mi]) {

            /*
             * The module kept the configuration it was given: what this
             * parse did not create, it does not initialize either, which
             * would be initializing the static configuration a second
             * time, into the pool of this file.
             */

            continue;
        }

        if (module->init_main_conf
            && module->init_main_conf(&cf, main_conf[mi]) != NGX_CONF_OK)
        {
            goto failed;
        }
    }

    dcmcf = main_conf[ngx_http_core_module.ctx_index];

    if (dcmcf->servers.nelts == 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "no server defined in \"%V\"", file);
        goto failed;
    }

    cscfp = dcmcf->servers.elts;

    for (s = 0; s < dcmcf->servers.nelts; s++) {
        if (!cscfp[s]->listen) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "no \"listen\" in a server defined in \"%V\"", file);
            goto failed;
        }
    }

    /* merge the servers with the static http{} level */

    for (m = 0; cycle->modules[m]; m++) {
        if (cycle->modules[m]->type != NGX_HTTP_MODULE) {
            continue;
        }

        if (!ngx_module_dynconf(cycle->modules[m], NGX_HTTP_DYN_CONF)) {
            continue;
        }

        if (ngx_http_merge_servers(&cf, dcmcf, cycle->modules[m])
            != NGX_CONF_OK)
        {
            goto failed;
        }
    }

    /*
     * The server names are known once the servers are merged, an unnamed
     * server having been given an empty name by then.
     */

    if (ngx_http_dynamic_include_names(cycle, file, dcmcf->ports, pool, df)
        != NGX_OK)
    {
        goto failed;
    }

    for (s = 0; s < dcmcf->servers.nelts; s++) {
        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (ngx_http_init_locations(&cf, cscfp[s], clcf) != NGX_OK
            || ngx_http_init_static_location_trees(&cf, clcf) != NGX_OK)
        {
            goto failed;
        }
    }

    /*
     * Last, as ngx_http_block() does it: the handlers of the variables this
     * file indexed are set, a name it used and nothing defines is reported,
     * and the hash a request looks a name up in is built.
     */

    if (ngx_http_variables_init_vars(&cf) != NGX_OK) {
        goto failed;
    }

    dcmcf->variables_keys = NULL;

    /* the zones this file declared, as ngx_init_cycle() creates its own */

    if (ngx_init_dynamic_zones(&cf) != NGX_OK) {
        goto failed;
    }

    ngx_destroy_pool(temp_pool);

    df->servers = &dcmcf->servers;

    return NGX_OK;

failed:

    ngx_destroy_pool(temp_pool);

    return NGX_ERROR;
}


/*
 * A copy of the running cycle, used while parsing.  Its lists of open files
 * and paths are those of the running cycle, so that a directive referring to
 * one finds the one the static configuration declares, which is memory the
 * workers can see because it predates the fork.  Creating a new one is
 * refused where it happens, which is what "dynamic_load" marks.
 *
 * The zones are copied rather than shared, so that the file may declare one
 * of its own: a list cannot be appended to without writing into the part the
 * copy shares with the running cycle, and what a file adds has to be in its
 * pool, where a request finds it.  Copying keeps every pointer to a zone of
 * the running cycle valid, and a zone the file declares is its own, so
 * another file may declare one of the same name.
 *
 * The lists a parse does append to get a copy of their own: the reload
 * handlers, so that nothing is registered twice, and the configuration dump,
 * whose entries live in the pool of this parse.
 */

static ngx_cycle_t *
ngx_http_dynamic_include_copy_cycle(ngx_cycle_t *cycle, ngx_pool_t *pool,
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

    /*
     * The pool of a cycle is where a name is completed with a prefix, as
     * ngx_conf_full_name() does it, so it is the pool of the file: what a
     * directive keeps of such a name is read while a request is served.
     */

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
 * Indexes the servers of a file by the address they listen on and their
 * name.  A dynamic configuration cannot create a listening socket, so every
 * address has to be one the static configuration already listens on.  The
 * match is exact: a wildcard address in the static configuration does not
 * admit a specific address here, because narrowing a wildcard is not
 * something a dynamic server can express.
 *
 * The entries are only linked into the file here; they enter the zone once
 * the file is attached to it.
 */

static ngx_int_t
ngx_http_dynamic_include_names(ngx_cycle_t *cycle, ngx_str_t *file,
    ngx_array_t *ports, ngx_pool_t *pool, ngx_http_dynamic_file_t *df)
{
    char                       *name;
    ngx_uint_t                  p, a, s, n;
    ngx_http_conf_port_t       *port;
    ngx_http_conf_addr_t       *addr;
    ngx_http_addr_conf_t       *addr_conf;
    ngx_http_server_name_t     *sn;
    ngx_http_dynamic_name_t    *dn;
    ngx_http_core_srv_conf_t  **cscfp;

    port = ports->elts;

    for (p = 0; p < ports->nelts; p++) {

        addr = port[p].addrs.elts;

        for (a = 0; a < port[p].addrs.nelts; a++) {

            addr_conf = ngx_http_dynamic_include_addr(cycle,
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

            /*
             * It has to describe the address the way the static
             * configuration does, so that a dynamic server on an address
             * that terminates SSL says so.
             */

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

                    dn = ngx_palloc(pool, sizeof(ngx_http_dynamic_name_t));
                    if (dn == NULL) {
                        return NGX_ERROR;
                    }

                    dn->sn.str = sn[n].name;
                    dn->sn.node.key = ngx_crc32_long(sn[n].name.data,
                                                     sn[n].name.len);
                    dn->addr_conf = addr_conf;
                    dn->addr = NULL;
                    dn->cscf = cscfp[s];
                    dn->file = df;

                    ngx_queue_insert_tail(&df->names, &dn->queue);
                }
            }
        }
    }

    if (ngx_queue_empty(&df->names)) {
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
ngx_http_dynamic_include_addr(ngx_cycle_t *cycle, struct sockaddr *sa,
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
ngx_http_dynamic_include_attach(ngx_http_dynamic_include_t *di,
    ngx_http_dynamic_file_t *df)
{
    ngx_queue_t              *q;
    ngx_http_dynamic_addr_t  *da;
    ngx_http_dynamic_name_t  *dn;

    /*
     * The address of every name is resolved before anything is inserted, so
     * that running out of memory here leaves the zone as it was.
     */

    for (q = ngx_queue_head(&df->names);
         q != ngx_queue_sentinel(&df->names);
         q = ngx_queue_next(q))
    {
        dn = ngx_queue_data(q, ngx_http_dynamic_name_t, queue);

        da = ngx_http_dynamic_include_addr_node(di, dn->addr_conf);
        if (da == NULL) {
            return NGX_ERROR;
        }

        dn->addr = da;
    }

    for (q = ngx_queue_head(&df->names);
         q != ngx_queue_sentinel(&df->names);
         q = ngx_queue_next(q))
    {
        dn = ngx_queue_data(q, ngx_http_dynamic_name_t, queue);

        ngx_rbtree_insert(&dn->addr->names, &dn->sn.node);
    }

    ngx_rbtree_insert(&di->sh->rbtree, &df->sn.node);
    ngx_queue_insert_tail(&di->sh->queue, &df->queue);

    return NGX_OK;
}


/*
 * The names of one address of the static configuration.  Once created, it
 * lives as long as the zone: there are only as many of these as there are
 * addresses, and an empty one is reused by the next file.
 */

static ngx_http_dynamic_addr_t *
ngx_http_dynamic_include_addr_node(ngx_http_dynamic_include_t *di,
    ngx_http_addr_conf_t *addr_conf)
{
    ngx_queue_t              *q;
    ngx_http_dynamic_addr_t  *da;

    for (q = ngx_queue_head(&di->sh->addrs);
         q != ngx_queue_sentinel(&di->sh->addrs);
         q = ngx_queue_next(q))
    {
        da = ngx_queue_data(q, ngx_http_dynamic_addr_t, queue);

        if (da->addr_conf == addr_conf) {
            return da;
        }
    }

    da = ngx_slab_alloc(di->shpool, sizeof(ngx_http_dynamic_addr_t));
    if (da == NULL) {
        return NULL;
    }

    da->addr_conf = addr_conf;

    ngx_rbtree_init(&da->names, &da->sentinel, ngx_str_rbtree_insert_value);

    ngx_queue_insert_tail(&di->sh->addrs, &da->queue);

    return da;
}


/*
 * Removes a file from the zone.  Its memory is released once the last
 * request referencing it is done.  The zone must be write locked.
 */

static void
ngx_http_dynamic_include_detach(ngx_http_dynamic_include_t *di,
    ngx_http_dynamic_file_t *df)
{
    ngx_queue_t              *q;
    ngx_http_dynamic_name_t  *dn;

    for (q = ngx_queue_head(&df->names);
         q != ngx_queue_sentinel(&df->names);
         q = ngx_queue_next(q))
    {
        dn = ngx_queue_data(q, ngx_http_dynamic_name_t, queue);

        ngx_rbtree_delete(&dn->addr->names, &dn->sn.node);
        dn->addr = NULL;
    }

    ngx_rbtree_delete(&di->sh->rbtree, &df->sn.node);
    ngx_queue_remove(&df->queue);

    ngx_http_dynamic_include_release(df);
}


static void
ngx_http_dynamic_include_release(ngx_http_dynamic_file_t *df)
{
    if (ngx_atomic_fetch_add(&df->refs, -1) != 1) {
        return;
    }

    ngx_destroy_pool(df->pool);
}


static void
ngx_http_dynamic_include_cleanup(void *data)
{
    ngx_http_dynamic_include_release(data);
}


/*
 * Looks for a server with the given name among those loaded for the address
 * the request arrived on.  The parts are searched in the order of their
 * appearance in the configuration, so that the first match wins.
 *
 * A reference to the file the server was found in is held until the request
 * is done, which keeps its configuration from being released under it.
 */

ngx_int_t
ngx_http_dynamic_include_find(ngx_http_request_t *r, ngx_str_t *host,
    ngx_http_core_srv_conf_t **cscfp)
{
    uint32_t                               hash;
    ngx_uint_t                             i;
    ngx_queue_t                           *q;
    ngx_pool_cleanup_t                    *cln;
    ngx_http_addr_conf_t                  *addr_conf;
    ngx_http_dynamic_addr_t               *da;
    ngx_http_dynamic_file_t               *df;
    ngx_http_dynamic_name_t               *dn;
    ngx_http_core_srv_conf_t              *cscf;
    ngx_http_dynamic_include_t            *di, **dip;
    ngx_http_dynamic_include_main_conf_t  *dimcf;

    if (host->len == 0) {
        return NGX_DECLINED;
    }

    dimcf = ngx_http_get_module_main_conf(r, ngx_http_dynamic_include_module);

    addr_conf = r->http_connection->addr_conf;

    hash = ngx_crc32_long(host->data, host->len);

    dip = dimcf->parts.elts;

    for (i = 0; i < dimcf->parts.nelts; i++) {
        di = dip[i];

        cscf = NULL;
        df = NULL;

        ngx_rwlock_rlock(&di->sh->rwlock);

        for (q = ngx_queue_head(&di->sh->addrs);
             q != ngx_queue_sentinel(&di->sh->addrs);
             q = ngx_queue_next(q))
        {
            da = ngx_queue_data(q, ngx_http_dynamic_addr_t, queue);

            if (da->addr_conf != addr_conf) {
                continue;
            }

            dn = (ngx_http_dynamic_name_t *)
                     ngx_str_rbtree_lookup(&da->names, host, hash);

            if (dn) {
                cscf = dn->cscf;
                df = dn->file;

                (void) ngx_atomic_fetch_add(&df->refs, 1);
            }

            break;
        }

        ngx_rwlock_unlock(&di->sh->rwlock);

        if (cscf == NULL) {
            continue;
        }

        cln = ngx_pool_cleanup_add(r->pool, 0);
        if (cln == NULL) {
            ngx_http_dynamic_include_release(df);
            return NGX_ERROR;
        }

        cln->handler = ngx_http_dynamic_include_cleanup;
        cln->data = df;

        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "dynamic server \"%V\" in \"%V\"",
                       host, &df->sn.str);

        *cscfp = cscf;

        return NGX_OK;
    }

    return NGX_DECLINED;
}
