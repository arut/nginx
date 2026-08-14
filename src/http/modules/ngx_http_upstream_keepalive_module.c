
/*
 * Copyright (C) Maxim Dounin
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_uint_t                         max_cached;
    ngx_uint_t                         requests;
    ngx_msec_t                         time;
    ngx_msec_t                         timeout;

    ngx_queue_t                        cache;
    ngx_queue_t                        free;

    ngx_http_upstream_init_peer_pt     original_init_peer;

    ngx_uint_t                         local; /* unsigned  local:1; */

} ngx_http_upstream_keepalive_srv_conf_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_queue_t                        queue;
    ngx_connection_t                  *connection;

    socklen_t                          socklen;
    ngx_sockaddr_t                     sockaddr;

    ngx_http_upstream_conf_t          *tag;

    /* number of streams currently multiplexed on the connection */
    ngx_uint_t                         active;

    /*
     * a multiplexed connection: the protocol module manages its presence here
     * through peer.notify() while it is in use, and get/free take the
     * multiplexing path for it instead of the single-use keepalive path
     */
    unsigned                           multiplex:1;

    /* the multiplexed connection currently has a free stream slot */
    unsigned                           available:1;

} ngx_http_upstream_keepalive_cache_t;


typedef struct {
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    ngx_http_upstream_t               *upstream;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
#endif

    ngx_event_notify_peer_pt           original_notify;

} ngx_http_upstream_keepalive_peer_data_t;


static ngx_int_t ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static void ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev);
static void ngx_http_upstream_keepalive_set_idle(ngx_connection_t *c,
    ngx_http_upstream_keepalive_cache_t *item, ngx_msec_t timeout);
static void ngx_http_upstream_keepalive_close(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_upstream_keepalive_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void ngx_http_upstream_notify_keepalive_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);

static void *ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf);
static char *ngx_http_upstream_keepalive_init_main_conf(ngx_conf_t *cf,
    void *conf);
static char *ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_upstream_keepalive_commands[] = {

    { ngx_string("keepalive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE12,
      ngx_http_upstream_keepalive,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("keepalive_time"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, time),
      NULL },

    { ngx_string("keepalive_timeout"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, timeout),
      NULL },

    { ngx_string("keepalive_requests"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_upstream_keepalive_srv_conf_t, requests),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_upstream_keepalive_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    ngx_http_upstream_keepalive_init_main_conf, /* init main configuration */

    ngx_http_upstream_keepalive_create_conf, /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_upstream_keepalive_module = {
    NGX_MODULE_V1,
    &ngx_http_upstream_keepalive_module_ctx, /* module context */
    ngx_http_upstream_keepalive_commands,    /* module directives */
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


static ngx_int_t
ngx_http_upstream_init_keepalive_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init keepalive peer");

    kcf = ngx_http_conf_upstream_srv_conf(us,
                                          ngx_http_upstream_keepalive_module);

    kp = ngx_palloc(r->pool, sizeof(ngx_http_upstream_keepalive_peer_data_t));
    if (kp == NULL) {
        return NGX_ERROR;
    }

    if (kcf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    kp->conf = kcf;
    kp->upstream = r->upstream;
    kp->data = r->upstream->peer.data;
    kp->original_get_peer = r->upstream->peer.get;
    kp->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = kp;
    r->upstream->peer.get = ngx_http_upstream_get_keepalive_peer;
    r->upstream->peer.free = ngx_http_upstream_free_keepalive_peer;

#if (NGX_HTTP_SSL)
    kp->original_set_session = r->upstream->peer.set_session;
    kp->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_upstream_keepalive_set_session;
    r->upstream->peer.save_session = ngx_http_upstream_keepalive_save_session;
#endif

    /*
     * always install our notify handler (even if the balancer has none): a
     * multiplexing protocol module signals stream-capacity changes through it
     */
    kp->original_notify = r->upstream->peer.notify;
    r->upstream->peer.notify = ngx_http_upstream_notify_keepalive_peer;

    return NGX_OK;
}


static ngx_int_t
ngx_http_upstream_get_keepalive_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_cache_t      *item;

    ngx_int_t          rc;
    ngx_queue_t       *q, *cache;
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer");

    /* ask balancer */

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    cache = &kp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
        c = item->connection;

        if (kp->conf->local && item->tag != kp->upstream->conf) {
            continue;
        }

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            if (item->multiplex) {

                /* multiplexed connection: new, shared path */

                if (c->close) {

                    /*
                     * going away (e.g. the peer sent GOAWAY) but still cached
                     * while its remaining streams finish -- do not hand it out;
                     * its last stream closes it (see free below)
                     */

                    continue;
                }

                if (!item->available) {

                    /* out of stream slots right now */

                    continue;
                }

                /*
                 * Only a buffered request may share it: an unbuffered request
                 * would head-of-line block the other streams, so skip such a
                 * connection and look for (or open) a dedicated one.
                 */

                if (!kp->upstream->conf->buffering) {
                    continue;
                }

                item->active++;

                /*
                 * Leave it in the cache so that other requests can share it
                 * too.  If it is already serving streams (not idle), hand it
                 * out as is; if idle, fall through to reactivate it.
                 */

                if (!c->idle) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                                   "get keepalive peer: "
                                   "multiplexing connection %p", c);
                    pc->connection = c;
                    pc->cached = 1;
                    return NGX_DONE;
                }

            } else {

                /* single-use connection: original keepalive path */

                ngx_queue_remove(q);
                ngx_queue_insert_head(&kp->conf->free, q);
            }

            goto found;
        }
    }

    return NGX_OK;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get keepalive peer: using connection %p", c);

    c->idle = 0;
    c->sent = 0;
    c->data = NULL;
    c->log = pc->log;
    c->read->log = pc->log;
    c->write->log = pc->log;
    c->pool->log = pc->log;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    pc->connection = c;
    pc->cached = 1;

    return NGX_DONE;
}


static void
ngx_http_upstream_free_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;
    ngx_http_upstream_keepalive_cache_t      *item;

    ngx_queue_t          *q, *cache;
    ngx_connection_t     *c;
    ngx_http_upstream_t  *u;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;

    /*
     * A multiplexed connection is put in the cache once (below) and stays
     * there while it serves streams.  Find it there: while other streams are
     * still using it, this stream must only detach, never close it -- even on
     * failure -- since the connection is shared.  Only once the last stream is
     * gone is it returned to idle watching (if healthy) or dropped and closed.
     */

    if (c != NULL) {
        cache = &kp->conf->cache;

        for (q = ngx_queue_head(cache);
             q != ngx_queue_sentinel(cache);
             q = ngx_queue_next(q))
        {
            item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t,
                                  queue);

            if (item->connection != c) {
                continue;
            }

            if (item->active > 0) {
                item->active--;
            }

            if (item->active > 0) {

                /* other streams remain: keep the shared connection for them */

                ngx_log_debug2(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                               "free keepalive peer: multiplexed "
                               "connection %p, %ui streams left",
                               c, item->active);

                pc->connection = NULL;
                kp->original_free_peer(pc, kp->data, state);
                return;
            }

            /* the last stream finished */

            if (!(state & NGX_PEER_FAILED)
                && !c->close
                && !c->read->eof
                && !c->read->error
                && !c->write->error
                && !c->read->timedout
                && !c->write->timedout)
            {
                /* healthy: watch the connection again, keep it cached */

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                               "free keepalive peer: "
                               "multiplexed connection %p now idle", c);

                item->available = 1;

                ngx_http_upstream_keepalive_set_idle(c, item,
                                                     kp->conf->timeout);
                pc->connection = NULL;

            } else {

                /* failed: drop from the cache, let the caller close it */

                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                               "free keepalive peer: "
                               "multiplexed connection %p failed", c);

                ngx_queue_remove(&item->queue);
                ngx_queue_insert_head(&kp->conf->free, &item->queue);
            }

            kp->original_free_peer(pc, kp->data, state);
            return;
        }
    }

    if (state & NGX_PEER_FAILED
        || c == NULL
        || c->read->eof
        || c->read->error
        || c->read->timedout
        || c->write->error
        || c->write->timedout)
    {
        goto invalid;
    }

    if (c->requests >= kp->conf->requests) {
        goto invalid;
    }

    if (ngx_current_msec - c->start_time > kp->conf->time) {
        goto invalid;
    }

    if (!u->keepalive) {
        goto invalid;
    }

    if (!u->request_body_sent) {
        goto invalid;
    }

    if (ngx_terminate || ngx_exiting) {
        goto invalid;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto invalid;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (ngx_queue_empty(&kp->conf->free)) {

        /*
         * All cache items are in use.  Evict the least recently used cached
         * connection to make room -- but skip a multiplexed connection that is
         * still serving streams (active > 0): closing it would free the shared
         * connection while its streams are still attached.
         */

        for (q = ngx_queue_last(&kp->conf->cache);
             q != ngx_queue_sentinel(&kp->conf->cache);
             q = ngx_queue_prev(q))
        {
            item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t,
                                  queue);

            if (item->active == 0) {
                break;
            }
        }

        if (q == ngx_queue_sentinel(&kp->conf->cache)) {

            /* every cached connection is a busy multiplexed one */

            goto invalid;
        }

        ngx_queue_remove(q);

        ngx_http_upstream_keepalive_close(item->connection);

    } else {
        q = ngx_queue_head(&kp->conf->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);
    }

    ngx_queue_insert_head(&kp->conf->cache, q);

    item->connection = c;
    item->tag = u->conf;
    item->active = 0;
    item->multiplex = 0;
    item->available = 0;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);

    pc->connection = NULL;

    ngx_http_upstream_keepalive_set_idle(c, item, kp->conf->timeout);

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


static void
ngx_http_upstream_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
ngx_http_upstream_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;
    ngx_http_upstream_keepalive_cache_t     *item;

    int                n;
    char               buf[1];
    ngx_connection_t  *c;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive close handler");

    c = ev->data;

    if (c->close || c->read->timedout) {
        goto close;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        ev->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }

        return;
    }

close:

    item = c->data;
    conf = item->conf;

    ngx_http_upstream_keepalive_close(c);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&conf->free, &item->queue);
}


/*
 * Put a cached connection into the idle state: watch it for a close by the
 * peer and arm the keepalive timeout.  Used both when a connection is first
 * cached and when the last stream of a multiplexed connection finishes.
 */

static void
ngx_http_upstream_keepalive_set_idle(ngx_connection_t *c,
    ngx_http_upstream_keepalive_cache_t *item, ngx_msec_t timeout)
{
    c->read->delayed = 0;
    ngx_add_timer(c->read, timeout);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_http_upstream_keepalive_dummy_handler;
    c->read->handler = ngx_http_upstream_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    if (c->read->ready) {
        ngx_http_upstream_keepalive_close_handler(c->read);
    }
}


static void
ngx_http_upstream_keepalive_close(ngx_connection_t *c)
{
    ngx_pool_t  *pool;

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_upstream_keepalive_close;
            return;
        }
    }

#endif

    pool = c->pool;

    ngx_close_connection(c);

    ngx_destroy_pool(pool);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_upstream_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_http_upstream_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void
ngx_http_upstream_notify_keepalive_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_upstream_keepalive_peer_data_t  *kp = data;

    ngx_queue_t                          *q, *cache;
    ngx_connection_t                     *c;
    ngx_http_upstream_keepalive_cache_t  *item;

    if (type != NGX_HTTP_UPSTREAM_NOTIFY_MPX_SPARE
        && type != NGX_HTTP_UPSTREAM_NOTIFY_MPX_FULL)
    {
        if (kp->original_notify) {
            kp->original_notify(pc, kp->data, type);
        }

        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "notify keepalive peer: %s",
                   type == NGX_HTTP_UPSTREAM_NOTIFY_MPX_SPARE ? "multiplex"
                                                              : "full");

    /*
     * A multiplexing protocol module reports a stream-capacity change for
     * pc->connection (the real connection; the module points pc->connection at
     * it around this call).  Keep it in the cache while it is in use so other
     * requests can multiplex onto it, and track whether it currently has a
     * free stream slot.
     */

    c = pc->connection;
    cache = &kp->conf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

        if (item->connection == c) {
            item->available = (type == NGX_HTTP_UPSTREAM_NOTIFY_MPX_SPARE);
            return;
        }
    }

    if (type == NGX_HTTP_UPSTREAM_NOTIFY_MPX_FULL) {
        return;
    }

    /*
     * First time this connection has spare capacity: cache it now, in use, so
     * concurrent requests can share it (rather than waiting for it to finish).
     * If there is no free slot, leave it -- it will be cached the usual way
     * when its request finishes; we do not evict an in-use connection.
     */

    if (ngx_queue_empty(&kp->conf->free)) {
        return;
    }

    q = ngx_queue_head(&kp->conf->free);
    ngx_queue_remove(q);
    ngx_queue_insert_head(cache, q);

    item = ngx_queue_data(q, ngx_http_upstream_keepalive_cache_t, queue);

    item->connection = c;
    item->tag = kp->upstream->conf;
    item->active = 1;               /* the request that established it */
    item->multiplex = 1;
    item->available = 1;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);
}


static void *
ngx_http_upstream_keepalive_create_conf(ngx_conf_t *cf)
{
    ngx_http_upstream_keepalive_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_upstream_keepalive_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_peer = NULL;
     *     conf->local = 0;
     */

    conf->time = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->requests = NGX_CONF_UNSET_UINT;
    conf->max_cached = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_upstream_keepalive_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_uint_t                                i, j;
    ngx_http_upstream_srv_conf_t            **uscfp;
    ngx_http_upstream_main_conf_t            *umcf;
    ngx_http_upstream_keepalive_cache_t      *cached;
    ngx_http_upstream_keepalive_srv_conf_t   *kcf;

    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    uscfp = umcf->upstreams.elts;

    for (i = 0; i < umcf->upstreams.nelts; i++) {

        /* skip implicit upstreams */
        if (uscfp[i]->srv_conf == NULL) {
            continue;
        }

        kcf = ngx_http_conf_upstream_srv_conf(uscfp[i],
                                            ngx_http_upstream_keepalive_module);

        if (kcf->max_cached == 0) {
            continue;
        }

        ngx_conf_init_msec_value(kcf->time, 3600000);
        ngx_conf_init_msec_value(kcf->timeout, 60000);
        ngx_conf_init_uint_value(kcf->requests, 1000);

        if (kcf->max_cached == NGX_CONF_UNSET_UINT) {
            kcf->local = 1;
            kcf->max_cached = 32;
        }

        kcf->original_init_peer = uscfp[i]->peer.init;

        uscfp[i]->peer.init = ngx_http_upstream_init_keepalive_peer;

        /* allocate cache items and add to free queue */

        cached = ngx_pcalloc(cf->pool,
                 sizeof(ngx_http_upstream_keepalive_cache_t) * kcf->max_cached);
        if (cached == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_queue_init(&kcf->cache);
        ngx_queue_init(&kcf->free);

        for (j = 0; j < kcf->max_cached; j++) {
            ngx_queue_insert_head(&kcf->free, &cached[j].queue);
            cached[j].conf = kcf;
        }
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upstream_keepalive_srv_conf_t  *kcf = conf;

    ngx_int_t    n;
    ngx_str_t   *value;

    if (kcf->max_cached != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    kcf->max_cached = n;

    if (cf->args->nelts == 3) {
        if (ngx_strcmp(value[2].data, "local") == 0) {
            kcf->local = 1;

        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid parameter \"%V\"", &value[2]);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}
