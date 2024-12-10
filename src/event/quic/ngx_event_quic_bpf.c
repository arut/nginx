
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_quic_connection.h>


#define NGX_QUIC_BPF_VARNAME  "NGINX_BPF_MAPS"
#define NGX_QUIC_BPF_VARSEP    ';'
#define NGX_QUIC_BPF_ADDRSEP   '#'


#define ngx_quic_bpf_get_conf(cycle)                                          \
    (ngx_quic_bpf_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_quic_bpf_module)

#define ngx_quic_bpf_get_old_conf(cycle)                                      \
    cycle->old_cycle->conf_ctx ? ngx_quic_bpf_get_conf(cycle->old_cycle)      \
                               : NULL

#define ngx_core_get_conf(cycle)                                              \
    (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module)


typedef struct {
    ngx_queue_t           queue;

    int                   listen_map;
    int                   worker_map;
    int                   nlisten_map;

    struct sockaddr      *sockaddr;
    socklen_t             socklen;

    ngx_array_t           listening;

    ngx_uint_t            nlisten;
    ngx_uint_t            old_nlisten;
} ngx_quic_bpf_group_t;


typedef struct {
    ngx_socket_t          fd;
    ngx_listening_t      *listening;
    ngx_connection_t     *connection;
} ngx_quic_bpf_listening_t;


typedef struct {
    ngx_flag_t            enabled;
    ngx_uint_t            max_connection_ids;
    ngx_uint_t            max_workers;
    ngx_queue_t           groups;
} ngx_quic_bpf_conf_t;


static void *ngx_quic_bpf_create_conf(ngx_cycle_t *cycle);
static char *ngx_quic_bpf_init_conf(ngx_cycle_t *cycle, void *conf);
static ngx_int_t ngx_quic_bpf_module_init(ngx_cycle_t *cycle);

static void ngx_quic_bpf_cleanup(void *data);
static ngx_inline void ngx_quic_bpf_close(ngx_log_t *log, int fd,
    const char *name);

static ngx_quic_bpf_group_t *ngx_quic_bpf_find_group(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_quic_bpf_group_t *ngx_quic_bpf_alloc_group(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_quic_bpf_group_t *ngx_quic_bpf_create_group(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_int_t ngx_quic_bpf_inherit_fd(ngx_cycle_t *cycle, int fd);
static ngx_quic_bpf_group_t *ngx_quic_bpf_get_group(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_int_t ngx_quic_bpf_group_add_socket(ngx_cycle_t *cycle,
    ngx_listening_t *ls);
static ngx_int_t ngx_quic_bpf_add_worker_socket(ngx_cycle_t *cycle,
    ngx_quic_bpf_group_t *grp, ngx_listening_t *ls);

static ngx_int_t ngx_quic_bpf_export_maps(ngx_cycle_t *cycle);
static ngx_int_t ngx_quic_bpf_import_maps(ngx_cycle_t *cycle);

extern ngx_bpf_program_t  ngx_quic_reuseport_helper;


static ngx_command_t  ngx_quic_bpf_commands[] = {

    { ngx_string("quic_bpf"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      0,
      offsetof(ngx_quic_bpf_conf_t, enabled),
      NULL },

      ngx_null_command
};


static ngx_core_module_t  ngx_quic_bpf_module_ctx = {
    ngx_string("quic_bpf"),
    ngx_quic_bpf_create_conf,
    ngx_quic_bpf_init_conf
};


ngx_module_t  ngx_quic_bpf_module = {
    NGX_MODULE_V1,
    &ngx_quic_bpf_module_ctx,              /* module context */
    ngx_quic_bpf_commands,                 /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_quic_bpf_module_init,              /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_quic_bpf_create_conf(ngx_cycle_t *cycle)
{
    ngx_quic_bpf_conf_t  *bcf;

    bcf = ngx_pcalloc(cycle->pool, sizeof(ngx_quic_bpf_conf_t));
    if (bcf == NULL) {
        return NULL;
    }

    bcf->enabled = NGX_CONF_UNSET;

    ngx_queue_init(&bcf->groups);

    return bcf;
}


static char *
ngx_quic_bpf_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_quic_bpf_conf_t *bcf = conf;

    ngx_quic_bpf_conf_t  *obcf;

    ngx_conf_init_value(bcf->enabled, 0);

    if (cycle->old_cycle->conf_ctx == NULL) {
        return NGX_CONF_OK;
    }

    obcf = ngx_quic_bpf_get_conf(cycle->old_cycle);
    if (obcf == NULL) {
        return NGX_CONF_OK;
    }

    if (obcf->enabled != bcf->enabled) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "cannot change \"quic_bpf\" after reload, ignoring");
        bcf->enabled = obcf->enabled;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_quic_bpf_module_init(ngx_cycle_t *cycle)
{
    ngx_uint_t            i;
    ngx_listening_t      *ls;
    ngx_core_conf_t      *ccf;
    ngx_event_conf_t     *ecf;
    ngx_pool_cleanup_t   *cln;
    ngx_quic_bpf_conf_t  *bcf;

    if (ngx_test_config) {
        /*
         * during config test, SO_REUSEPORT socket option is
         * not set, thus making further processing meaningless
         */
        return NGX_OK;
    }

    bcf = ngx_quic_bpf_get_conf(cycle);
    if (!bcf->enabled) {
        return NGX_OK;
    }

    ccf = ngx_core_get_conf(cycle);
    ecf = ngx_event_get_conf(cycle->conf_ctx, ngx_event_core_module);

    bcf->max_connection_ids = ecf->connections * NGX_QUIC_MAX_SERVER_IDS;
    bcf->max_workers = ccf->worker_processes * 4;

    cln = ngx_pool_cleanup_add(cycle->pool, 0);
    if (cln == NULL) {
        goto failed;
    }

    cln->data = bcf;
    cln->handler = ngx_quic_bpf_cleanup;

    ls = cycle->listening.elts;

    if (ngx_inherited && ngx_is_init_cycle(cycle->old_cycle)) {
        if (ngx_quic_bpf_import_maps(cycle) != NGX_OK) {
            goto failed;
        }
    }

    ls = cycle->listening.elts;

    for (i = 0; i < cycle->listening.nelts; i++) {
        if (ls[i].quic && ls[i].reuseport) {
            if (ngx_quic_bpf_group_add_socket(cycle, &ls[i]) != NGX_OK) {
                goto failed;
            }
        }
    }

    if (ngx_quic_bpf_export_maps(cycle) != NGX_OK) {
        goto failed;
    }

    return NGX_OK;

failed:

    if (ngx_is_init_cycle(cycle->old_cycle)) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "ngx_quic_bpf_module failed to initialize, check limits");

        /* refuse to start */
        return NGX_ERROR;
    }

    /*
     * returning error now will lead to master process exiting immediately
     * leaving worker processes orphaned, what is really unexpected.
     * Instead, just issue a not about failed initialization and try
     * to cleanup a bit. Still program can be already loaded to kernel
     * for some reuseport groups, and there is no way to revert, so
     * behaviour may be inconsistent.
     */

    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "ngx_quic_bpf_module failed to initialize properly, ignored."
                  "please check limits and note that nginx state now "
                  "can be inconsistent and restart may be required");

    return NGX_OK;
}


static void
ngx_quic_bpf_cleanup(void *data)
{
    ngx_quic_bpf_conf_t  *bcf = (ngx_quic_bpf_conf_t *) data;

    ngx_uint_t                 i;
    ngx_queue_t               *q;
    ngx_quic_bpf_group_t      *grp;
    ngx_quic_bpf_listening_t  *bls;

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_bpf_group_t, queue);

        ngx_quic_bpf_close(ngx_cycle->log, grp->listen_map, "listen");
        ngx_quic_bpf_close(ngx_cycle->log, grp->worker_map, "worker");
        ngx_quic_bpf_close(ngx_cycle->log, grp->nlisten_map, "nlisten");

        bls = grp->listening.elts;

        for (i = 0; i < grp->listening.nelts; i++) {
            if (bls[i].fd != (ngx_socket_t) -1) {
                if (ngx_close_socket(bls[i].fd) == -1) {
                    ngx_log_error(NGX_LOG_ALERT, ngx_cycle->log,
                                  ngx_socket_errno,
                                  ngx_close_socket_n " failed");
                }
            }
        }
    }
}


static ngx_inline void
ngx_quic_bpf_close(ngx_log_t *log, int fd, const char *name)
{
    if (close(fd) != -1) {
        return;
    }

    ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                  "QUIC BPF close %s map fd:%d failed", name, fd);
}


static ngx_quic_bpf_group_t *
ngx_quic_bpf_find_group(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    ngx_queue_t           *q;
    ngx_quic_bpf_conf_t   *bcf;
    ngx_quic_bpf_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);

    if (!bcf->enabled || !ls->quic || !ls->reuseport) {
        return NULL;
    }

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_bpf_group_t, queue);

        if (ngx_cmp_sockaddr(ls->sockaddr, ls->socklen,
                             grp->sockaddr, grp->socklen, 1)
            == 0)
        {
            return grp;
        }
    }

    return NULL;
}


static ngx_quic_bpf_group_t *
ngx_quic_bpf_alloc_group(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    ngx_quic_bpf_conf_t    *bcf;
    ngx_quic_bpf_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);

    grp = ngx_pcalloc(cycle->pool, sizeof(ngx_quic_bpf_group_t));
    if (grp == NULL) {
        return NULL;
    }

    grp->listen_map = -1;
    grp->worker_map = -1;
    grp->nlisten_map = -1;

    grp->sockaddr = ls->sockaddr;
    grp->socklen = ls->socklen;

    if (ngx_array_init(&grp->listening, cycle->pool, 1,
                       sizeof(ngx_quic_bpf_listening_t))
        != NGX_OK)
    {
        return NULL;
    }

    ngx_queue_insert_tail(&bcf->groups, &grp->queue);

    return grp;
}


static ngx_quic_bpf_group_t *
ngx_quic_bpf_create_group(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    int                    progfd, failed;
    ngx_quic_bpf_conf_t   *bcf;
    ngx_quic_bpf_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);

    grp = ngx_quic_bpf_alloc_group(cycle, ls);
    if (grp == NULL) {
        return NULL;
    }

    grp->listen_map = ngx_bpf_map_create(cycle->log, BPF_MAP_TYPE_SOCKMAP,
                                         sizeof(uint32_t), sizeof(uint64_t),
                                         bcf->max_workers, 0);
    if (grp->listen_map == -1) {
        goto failed;
    }

    if (ngx_quic_bpf_inherit_fd(cycle, grp->listen_map) != NGX_OK) {
        goto failed;
    }

    ngx_bpf_program_link(&ngx_quic_reuseport_helper,
                         "ngx_quic_listen", grp->listen_map);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf listen map created fd:%d", grp->listen_map);


    grp->worker_map = ngx_bpf_map_create(cycle->log, BPF_MAP_TYPE_SOCKHASH,
                                     NGX_QUIC_SERVER_CID_LEN, sizeof(uint64_t),
                                     bcf->max_connection_ids, 0);
    if (grp->worker_map == -1) {
        goto failed;
    }

    if (ngx_quic_bpf_inherit_fd(cycle, grp->worker_map) != NGX_OK) {
        goto failed;
    }

    ngx_bpf_program_link(&ngx_quic_reuseport_helper,
                         "ngx_quic_worker", grp->worker_map);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf worker map created fd:%d", grp->worker_map);


    grp->nlisten_map = ngx_bpf_map_create(cycle->log, BPF_MAP_TYPE_ARRAY,
                                     sizeof(uint32_t), sizeof(uint32_t), 1, 0);
    if (grp->nlisten_map == -1) {
        goto failed;
    }

    if (ngx_quic_bpf_inherit_fd(cycle, grp->nlisten_map) != NGX_OK) {
        goto failed;
    }

    ngx_bpf_program_link(&ngx_quic_reuseport_helper,
                         "ngx_quic_nlisten", grp->nlisten_map);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                   "quic bpf nlisten map created fd:%d", grp->nlisten_map);


    progfd = ngx_bpf_load_program(cycle->log, &ngx_quic_reuseport_helper);
    if (progfd < 0) {
        goto failed;
    }

    failed = 0;

    if (setsockopt(ls->fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF,
                   &progfd, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_socket_errno,
                      "quic bpf setsockopt(SO_ATTACH_REUSEPORT_EBPF) failed");
        failed = 1;
    }

    ngx_quic_bpf_close(cycle->log, progfd, "program");

    if (failed) {
        goto failed;
    }

    return grp;

failed:

    if (grp->listen_map != -1) {
        ngx_quic_bpf_close(cycle->log, grp->listen_map, "listen");
    }

    if (grp->worker_map != -1) {
        ngx_quic_bpf_close(cycle->log, grp->worker_map, "worker");
    }

    if (grp->nlisten_map != -1) {
        ngx_quic_bpf_close(cycle->log, grp->nlisten_map, "nlisten");
    }

    ngx_queue_remove(&grp->queue);

    return NULL;
}


static ngx_int_t
ngx_quic_bpf_inherit_fd(ngx_cycle_t *cycle, int fd)
{
    int  flags;

    flags = fcntl(fd, F_GETFD);
    if (flags == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "fcntl(F_GETFD) failed");
        return NGX_ERROR;
    }

    flags &= ~FD_CLOEXEC;

    if (fcntl(fd, F_SETFD, flags) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "fcntl(F_SETFD) failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_quic_bpf_group_t *
ngx_quic_bpf_get_group(ngx_cycle_t *cycle, ngx_listening_t *ls)
{
    ngx_quic_bpf_conf_t   *old_bcf;
    ngx_quic_bpf_group_t  *grp, *ogrp;

    grp = ngx_quic_bpf_find_group(cycle, ls);
    if (grp) {
        return grp;
    }

    old_bcf = ngx_quic_bpf_get_old_conf(cycle);
    if (old_bcf == NULL) {
        return ngx_quic_bpf_create_group(cycle, ls);
    }

    ogrp = ngx_quic_bpf_find_group(cycle->old_cycle, ls);
    if (ogrp == NULL) {
        return ngx_quic_bpf_create_group(cycle, ls);
    }

    grp = ngx_quic_bpf_alloc_group(cycle, ls);
    if (grp == NULL) {
        return NULL;
    }

    grp->old_nlisten = ogrp->nlisten;

    grp->listen_map = dup(ogrp->listen_map);
    if (grp->listen_map == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "failed to duplicate QUIC BPF listen map");

        goto failed;
    }

    grp->worker_map = dup(ogrp->worker_map);
    if (grp->worker_map == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "failed to duplicate QUIC BPF worker map");
        goto failed;
    }

    grp->nlisten_map = dup(ogrp->nlisten_map);
    if (grp->nlisten_map == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "failed to duplicate QUIC BPF nlisten map");
        goto failed;
    }

    return grp;

failed:

    if (grp->listen_map != -1) {
        ngx_quic_bpf_close(cycle->log, grp->listen_map, "listen");
    }

    if (grp->worker_map != -1) {
        ngx_quic_bpf_close(cycle->log, grp->worker_map, "worker");
    }

    if (grp->nlisten_map != -1) {
        ngx_quic_bpf_close(cycle->log, grp->nlisten_map, "nlisten");
    }

    ngx_queue_remove(&grp->queue);

    return NULL;
}


static ngx_int_t
ngx_quic_bpf_group_add_socket(ngx_cycle_t *cycle,  ngx_listening_t *ls)
{
    uint32_t               zero, key;
    ngx_quic_bpf_group_t  *grp;

    grp = ngx_quic_bpf_get_group(cycle, ls);
    if (grp == NULL) {
        return NGX_ERROR;
    }

    if (ngx_quic_bpf_add_worker_socket(cycle, grp, ls) != NGX_OK) {
        return NGX_ERROR;
    }

    key = ls->worker;

    if (ngx_bpf_map_update(grp->listen_map, &key, &ls->fd, BPF_ANY) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "failed to update QUIC BPF listen map");
        return NGX_ERROR;
    }

    if (grp->nlisten >= ls->worker + 1) {
        return NGX_OK;
    }

    grp->nlisten = ls->worker + 1;

    if (grp->nlisten <= grp->old_nlisten) {
        return NGX_OK;
    }

    zero = 0;
    key = grp->nlisten;

    if (ngx_bpf_map_update(grp->nlisten_map, &zero, &key, BPF_ANY) == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "failed to update QUIC BPF nlisten map");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_quic_bpf_add_worker_socket(ngx_cycle_t *cycle, ngx_quic_bpf_group_t *grp,
    ngx_listening_t *ls)
{
    int                        value;
    ngx_uint_t                 i, n;
    ngx_socket_t               s;
    ngx_quic_bpf_listening_t  *bls;

    s = ngx_socket(ls->sockaddr->sa_family, SOCK_DGRAM, 0);
    if (s == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_socket_errno,
                      ngx_socket_n " failed");
        return NGX_ERROR;
    }

    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      ngx_nonblocking_n " worker socket failed");
        goto failed;
    }

    value = 1;

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                (const void *) &value, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      "setsockopt(SO_REUSEADDR) worker socket failed");
        goto failed;
    }

    if (setsockopt(s, SOL_SOCKET, SO_REUSEPORT,
                   (const void *) &value, sizeof(int))
        == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      "setsockopt(SO_REUSEPORT) worker socket failed");
        goto failed;
    }

#if (NGX_HAVE_IP_PKTINFO)
    if (ls->wildcard && ls->sockaddr->sa_family == AF_INET) {
        if (setsockopt(s, IPPROTO_IP, IP_PKTINFO,
                       (const void *) &value, sizeof(int))
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                          "setsockopt(IP_PKTINFO) worker socket failed");
            goto failed;
        }
    }
#endif

#if (NGX_HAVE_INET6 && NGX_HAVE_IPV6_RECVPKTINFO)
    if (ls->wildcard && ls->sockaddr->sa_family == AF_INET6) {
        if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO,
                       (const void *) &value, sizeof(int))
            == -1)
        {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                          "setsockopt(IPV6_RECVPKTINFO) worker socket failed");
        }
    }
#endif

    if (bind(s, ls->sockaddr, ls->socklen) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      "bind() failed");
        goto failed;
    }

    if (ls->worker >= grp->listening.nelts) {
        n = ls->worker + 1 - grp->listening.nelts;

        bls = ngx_array_push_n(&grp->listening, n);
        if (bls == NULL) {
            goto failed;
        }

        ngx_memzero(bls, n * sizeof(ngx_quic_bpf_listening_t));

        for (i = 0; i < n; i++) {
            bls[i].fd = (ngx_socket_t) -1;
        }
    }

    bls = grp->listening.elts;
    bls[ls->worker].fd = s;
    bls[ls->worker].listening  = ls;

    return NGX_OK;

failed:

    if (ngx_close_socket(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_socket_errno,
                      ngx_close_socket_n " failed");
    }

    return NGX_ERROR;
}

static ngx_int_t
ngx_quic_bpf_export_maps(ngx_cycle_t *cycle)
{
    u_char                *p, *buf;
    size_t                 len;
    ngx_str_t             *var;
    ngx_queue_t           *q;
    ngx_core_conf_t       *ccf;
    ngx_quic_bpf_conf_t   *bcf;
    ngx_quic_bpf_group_t  *grp;

    bcf = ngx_quic_bpf_get_conf(cycle);
    if (!bcf->enabled) {
        return NGX_OK;
    }

    ccf = ngx_core_get_conf(cycle);

    len = sizeof(NGX_QUIC_BPF_VARNAME) + 1;

    q = ngx_queue_head(&bcf->groups);

    while (q != ngx_queue_sentinel(&bcf->groups)) {

        grp = ngx_queue_data(q, ngx_quic_bpf_group_t, queue);

        q = ngx_queue_next(q);

        if (grp->nlisten == 0) {
            /*
             * map was inherited, but it is not used in this configuration;
             * do not pass such map further and drop the group to prevent
             * interference with changes during reload
             */

            ngx_quic_bpf_close(cycle->log, grp->listen_map, "listen");
            ngx_quic_bpf_close(cycle->log, grp->worker_map, "worker");
            ngx_quic_bpf_close(cycle->log, grp->nlisten_map, "nlisten");

            ngx_queue_remove(&grp->queue);
            continue;
        }

        len += (NGX_INT32_LEN + 1) * 3 + NGX_SOCKADDR_STRLEN + 1;
    }

    len++;

    buf = ngx_palloc(cycle->pool, len);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(buf, NGX_QUIC_BPF_VARNAME "=", sizeof(NGX_QUIC_BPF_VARNAME));

    for (q = ngx_queue_head(&bcf->groups);
         q != ngx_queue_sentinel(&bcf->groups);
         q = ngx_queue_next(q))
    {
        grp = ngx_queue_data(q, ngx_quic_bpf_group_t, queue);

        p = ngx_sprintf(p, "%ud", grp->listen_map);
        *p++ = NGX_QUIC_BPF_ADDRSEP;
        p = ngx_sprintf(p, "%ud", grp->worker_map);
        *p++ = NGX_QUIC_BPF_ADDRSEP;
        p = ngx_sprintf(p, "%ud", grp->nlisten_map);
        *p++ = NGX_QUIC_BPF_ADDRSEP;

        p += ngx_sock_ntop(grp->sockaddr, grp->socklen, p,
                           NGX_SOCKADDR_STRLEN, 1);
        *p++ = NGX_QUIC_BPF_VARSEP;
    }

    *p = '\0';

    var = ngx_array_push(&ccf->env);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->data = buf;
    var->len = sizeof(NGX_QUIC_BPF_VARNAME) - 1;

    return NGX_OK;
}


static ngx_int_t
ngx_quic_bpf_import_maps(ngx_cycle_t *cycle)
{
    int                    fds[3];
    u_char                *inherited, *p, *v;
    uint32_t               zero, nlisten;
    ngx_int_t              fd;
    ngx_uint_t             nfd;
    ngx_addr_t             tmp;
    ngx_quic_bpf_conf_t   *bcf;
    ngx_quic_bpf_group_t  *grp;

    inherited = (u_char *) getenv(NGX_QUIC_BPF_VARNAME);

    if (inherited == NULL) {
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "using inherited QUIC BPF maps from \"%s\"", inherited);

    bcf = ngx_quic_bpf_get_conf(cycle);

    zero = 0;
    nfd = 0;

    for (p = inherited, v = p; *p; p++) {

        switch (*p) {

        case NGX_QUIC_BPF_ADDRSEP:

            if (nfd > 2) {
                goto failed;
            }

            fd = ngx_atoi(v, p - v);
            if (fd == NGX_ERROR) {
                goto failed;
            }

            fds[nfd++] = fd;
            v = p + 1;
            break;

        case NGX_QUIC_BPF_VARSEP:

            if (nfd != 3) {
                goto failed;
            }

            grp = ngx_pcalloc(cycle->pool, sizeof(ngx_quic_bpf_group_t));
            if (grp == NULL) {
                return NGX_ERROR;
            }

            if (ngx_array_init(&grp->listening, cycle->pool, 1,
                               sizeof(ngx_quic_bpf_listening_t))
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            grp->listen_map = fds[0];
            grp->worker_map = fds[1];
            grp->nlisten_map = fds[2];

            if (ngx_parse_addr_port(cycle->pool, &tmp, v, p - v) != NGX_OK) {
                goto failed;
            }

            grp->sockaddr = ngx_pcalloc(cycle->pool, tmp.socklen);
            if (grp->sockaddr == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(grp->sockaddr, tmp.sockaddr, tmp.socklen);
            grp->socklen = tmp.socklen;

            if (ngx_bpf_map_lookup(fds[2], &zero, &nlisten) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "failed to lookup QUIC BPF listen number");
                return NGX_ERROR;
            }

            grp->old_nlisten = nlisten;

            ngx_queue_insert_tail(&bcf->groups, &grp->queue);

            ngx_log_debug5(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "quic bpf sockmap inherited with "
                           "fds:%d/%d/%d address:%*s",
                           fds[0], fds[1], fds[2], p - v, v);

            nfd = 0;
            v = p + 1;
            break;

        default:
            break;
        }
    }

    return NGX_OK;

failed:

    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "failed to parse inherited QUIC BPF variable");

    return NGX_ERROR;
}


ngx_int_t
ngx_quic_bpf_get_client_connection(ngx_connection_t *lc, ngx_connection_t **pc)
{
    ngx_event_t               *rev;
    ngx_connection_t          *c;
    ngx_quic_bpf_group_t      *grp;
    ngx_quic_bpf_listening_t  *bpf_listening, *bls;

    grp = ngx_quic_bpf_find_group((ngx_cycle_t *) ngx_cycle, lc->listening);

    if (grp == NULL || ngx_worker >= grp->listening.nelts) {
        return NGX_OK;
    }

    bpf_listening = grp->listening.elts;
    bls = &bpf_listening[ngx_worker];

    if (bls->fd == (ngx_socket_t) -1) {
        return NGX_OK;
    }

    if (bls->connection == NULL) {
        c = ngx_get_connection(bls->fd, lc->log);
        if (c == NULL) {
            return NGX_ERROR;
        }

        c->type = SOCK_DGRAM;
        c->log = lc->log;
        c->listening = bls->listening;

        rev = c->read;
        rev->quic = 1;
        rev->log = c->log;
        rev->handler = ngx_quic_recvmsg;

        if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
            ngx_free_connection(c);
            return NGX_ERROR;
        }

        bls->connection = c;

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, lc->log, 0,
                       "quic bpf worker socket connection fd:%d", bls->fd);

    }

    *pc = ngx_get_connection(bls->fd, lc->log);
    if (*pc == NULL) {
        return NGX_ERROR;
    }

    (*pc)->shared = 1;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, lc->log, 0,
                   "quic bpf client connection fd:%d", bls->fd);

    return NGX_OK;
}


ngx_int_t
ngx_quic_bpf_insert(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_socket_t *qsock)
{
    ngx_quic_bpf_group_t  *grp;

    if (qsock->sid.len != NGX_QUIC_SERVER_CID_LEN) {
        /* route by address */
        return NGX_OK;
    }

    grp = ngx_quic_bpf_find_group((ngx_cycle_t *) ngx_cycle, c->listening);
    if (grp == NULL) {
        return NGX_OK;
    }

    if (ngx_bpf_map_update(grp->worker_map, qsock->sid.id, &c->fd, BPF_ANY)
        == -1)
    {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "failed to update QUIC BPF worker map");
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_quic_bpf_delete(ngx_connection_t *c, ngx_quic_connection_t *qc,
    ngx_quic_socket_t *qsock)
{
    ngx_quic_bpf_group_t  *grp;

    if (qsock->sid.len != NGX_QUIC_SERVER_CID_LEN) {
        /* route by address */
        return NGX_OK;
    }

    grp = ngx_quic_bpf_find_group((ngx_cycle_t *) ngx_cycle, c->listening);
    if (grp == NULL) {
        return NGX_OK;
    }

    if (ngx_bpf_map_delete(grp->worker_map, qsock->sid.id) == -1) {
        ngx_log_error(NGX_LOG_ALERT, c->log, ngx_errno,
                      "failed to update QUIC BPF worker map");
        return NGX_ERROR;
    }

    return NGX_OK;
}
