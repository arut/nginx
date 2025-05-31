
/*
 * Copyright (C) Roman Arutyunyan
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

    ngx_uint_t                         cached;
    ngx_queue_t                        cache;

    ngx_http_upstream_init_pt          original_init_upstream;
    ngx_http_upstream_init_peer_pt     original_init_peer;

} ngx_http_v3_upstream_srv_conf_t;


typedef struct {
    ngx_http_v3_upstream_srv_conf_t   *conf;

    void                              *data;

    ngx_event_get_peer_pt              original_get_peer;
    ngx_event_free_peer_pt             original_free_peer;
    ngx_event_set_peer_session_pt      original_set_session;
    ngx_event_save_peer_session_pt     original_save_session;
} ngx_http_v3_upstream_peer_data_t;


static void ngx_http_v3_upstream_try_cache(ngx_connection_t *c);
static void ngx_http_v3_upstream_uncache(ngx_connection_t *c);
static void ngx_http_v3_upstream_handler(ngx_connection_t *c);
static ngx_int_t ngx_http_v3_upstream_handle_connection(ngx_connection_t *c);

static ngx_int_t ngx_http_v3_upstream_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_v3_upstream_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_v3_upstream_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state);

static ngx_int_t ngx_http_v3_upstream_set_session(
    ngx_peer_connection_t *pc, void *data);
static void ngx_http_v3_upstream_save_session(ngx_peer_connection_t *pc,
    void *data);

static void *ngx_http_v3_upstream_create_conf(ngx_conf_t *cf);
static char *ngx_http_v3_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_v3_upstream_commands[] = {

    { ngx_string("http3_keepalive"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_http_v3_upstream_keepalive,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("http3_keepalive_time"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_upstream_srv_conf_t, time),
      NULL },

    { ngx_string("http3_keepalive_timeout"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_upstream_srv_conf_t, timeout),
      NULL },

    { ngx_string("http3_keepalive_requests"),
      NGX_HTTP_UPS_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_v3_upstream_srv_conf_t, requests),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_v3_upstream_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_v3_upstream_create_conf,      /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_v3_upstream_module = {
    NGX_MODULE_V1,
    &ngx_http_v3_upstream_module_ctx,      /* module context */
    ngx_http_v3_upstream_commands,         /* module directives */
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


ngx_int_t
ngx_http_v3_upstream_create_stream(ngx_http_request_t *r)
{
    ngx_connection_t                 *c, *sc;
    ngx_http_upstream_t              *u;
    ngx_http_v3_session_t            *h3c;
    ngx_http_v3_upstream_srv_conf_t  *h3ucf;

    u = r->upstream;
    c = u->peer.connection;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 upstream init connection");

    c->ssl->handler = ngx_http_v3_upstream_handler;

    if (ngx_http_v3_init_session(c) != NGX_OK) {
        return NGX_ERROR;
    }

    h3c = c->data;

    if (u->conf->upstream && u->conf->upstream->srv_conf) {
        /* explicit upstream */
        h3ucf = ngx_http_conf_upstream_srv_conf(u->conf->upstream,
                                                ngx_http_v3_upstream_module);

        if (h3ucf->requests != NGX_CONF_UNSET_UINT) {
            h3c->data = h3ucf;
        }
    }

    if (ngx_http_v3_send_settings(c) != NGX_OK) {
        return NGX_ERROR;
    }

    /* TODO dynamic table */

    sc = ngx_quic_open_stream(c, 1);
    if (sc == NULL) {
        ngx_quic_set_app_error(c, NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR,
                               "failed to open stream");
        return NGX_ERROR;
    }

    sc->data = r;
    sc->requests++;

    c->requests++;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    u->peer.connection = sc;
    u->writer.connection = sc;

    if (ngx_http_v3_upstream_handle_connection(c) != NGX_OK) {
        ngx_close_connection(sc);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_http_v3_upstream_try_cache(ngx_connection_t *c)
{
    ngx_http_v3_session_t            *h3c;
    ngx_http_v3_upstream_srv_conf_t  *h3ucf;

    h3c = c->data;
    h3ucf = h3c->data;

    if (!h3c->cached
        && h3ucf
        && h3ucf->cached < h3ucf->max_cached
        && c->requests < h3ucf->requests
        && ngx_current_msec - c->start_time < h3ucf->time
        && ngx_quic_can_open_stream(c, 1) == NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 upstream cache");

        ngx_queue_insert_head(&h3ucf->cache, &h3c->queue);
        h3c->cached = 1;
        h3ucf->cached++;
    }
}


static void
ngx_http_v3_upstream_uncache(ngx_connection_t *c)
{
    ngx_http_v3_session_t            *h3c;
    ngx_http_v3_upstream_srv_conf_t  *h3ucf;

    h3c = c->data;
    h3ucf = h3c->data;

    if (h3c->cached) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "http3 upstream uncache");

        ngx_queue_remove(&h3c->queue);
        h3c->cached = 0;
        h3ucf->cached--;
    }
}


static void
ngx_http_v3_upstream_handler(ngx_connection_t *c)
{
    if (c->close) {
        ngx_http_v3_upstream_uncache(c);
        ngx_http_v3_close_connection(c);
        return;
    }

    if (ngx_http_v3_upstream_handle_connection(c) != NGX_OK) {
        ngx_http_v3_upstream_uncache(c);
        ngx_http_v3_close_connection(c);
        return;
    }
}


static ngx_int_t
ngx_http_v3_upstream_handle_connection(ngx_connection_t *c)
{
    ngx_connection_t                 *sc;
    ngx_http_v3_session_t            *h3c;
    ngx_http_v3_upstream_srv_conf_t  *h3ucf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http3 upstream handle connection");

    if (c->read->timedout) {
        ngx_quic_set_app_error(c, NGX_HTTP_V3_ERR_NO_ERROR,
                               "keepalive shutdown");
        return NGX_DONE;
    }

    for ( ;; ) {

        if (ngx_quic_get_error(c)) {
            return NGX_DONE;
        }

        sc = ngx_quic_accept_stream(c);
        if (sc == NULL) {
            break;
        }

        if (!(sc->quic->stream->id & NGX_QUIC_STREAM_UNIDIRECTIONAL)) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "upstream opened a quic bidi stream");
            return NGX_ERROR;
        }

        ngx_http_v3_init_uni_stream(sc);
    }

    ngx_http_v3_upstream_try_cache(c);

    if (ngx_quic_has_streams(c, 1, 1) == NGX_DECLINED) {
        h3c = c->data;
        h3ucf = h3c->data;

        if (h3ucf == NULL || h3ucf->max_cached == 0) {
            ngx_quic_set_app_error(c, NGX_HTTP_V3_ERR_NO_ERROR, "shutdown");
            return NGX_DONE;
        }

        if (!c->read->timer_set) {
            ngx_add_timer(c->read, h3ucf->timeout);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_upstream_init(ngx_conf_t *cf, ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_v3_upstream_srv_conf_t  *h3ucf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0, "http3 upstream init");

    h3ucf = ngx_http_conf_upstream_srv_conf(us, ngx_http_v3_upstream_module);

    ngx_conf_init_msec_value(h3ucf->time, 3600000);
    ngx_conf_init_msec_value(h3ucf->timeout, 60000);
    ngx_conf_init_uint_value(h3ucf->requests, 1000);

    if (h3ucf->original_init_upstream(cf, us) != NGX_OK) {
        return NGX_ERROR;
    }

    h3ucf->original_init_peer = us->peer.init;

    us->peer.init = ngx_http_v3_upstream_init_peer;

    ngx_queue_init(&h3ucf->cache);

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_upstream_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us)
{
    ngx_http_v3_upstream_srv_conf_t   *h3ucf;
    ngx_http_v3_upstream_peer_data_t  *h3p;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http3 init peer");

    h3ucf = ngx_http_conf_upstream_srv_conf(us, ngx_http_v3_upstream_module);

    h3p = ngx_palloc(r->pool, sizeof(ngx_http_v3_upstream_peer_data_t));
    if (h3p == NULL) {
        return NGX_ERROR;
    }

    if (h3ucf->original_init_peer(r, us) != NGX_OK) {
        return NGX_ERROR;
    }

    h3p->conf = h3ucf;
    h3p->data = r->upstream->peer.data;
    h3p->original_get_peer = r->upstream->peer.get;
    h3p->original_free_peer = r->upstream->peer.free;

    r->upstream->peer.data = h3p;
    r->upstream->peer.get = ngx_http_v3_upstream_get_peer;
    r->upstream->peer.free = ngx_http_v3_upstream_free_peer;

    h3p->original_set_session = r->upstream->peer.set_session;
    h3p->original_save_session = r->upstream->peer.save_session;
    r->upstream->peer.set_session = ngx_http_v3_upstream_set_session;
    r->upstream->peer.save_session = ngx_http_v3_upstream_save_session;

    return NGX_OK;
}


static ngx_int_t
ngx_http_v3_upstream_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_v3_upstream_peer_data_t  *h3p = data;

    ngx_int_t                          rc;
    ngx_queue_t                       *q, *cache;
    ngx_connection_t                  *c, *sc;
    ngx_http_v3_session_t             *h3c;
    ngx_http_v3_upstream_srv_conf_t   *h3ucf;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0, "http3 get peer");

    /* ask balancer */

    rc = h3p->original_get_peer(pc, h3p->data);

    if (rc != NGX_OK) {
        return rc;
    }

    /* search cache for suitable connection */

    h3ucf = h3p->conf;
    cache = &h3ucf->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        h3c = ngx_queue_data(q, ngx_http_v3_session_t, queue);
        c = h3c->connection;

        if (ngx_memn2cmp((u_char *) c->sockaddr, (u_char *) pc->sockaddr,
                         c->socklen, pc->socklen)
            == 0)
        {
            ngx_http_v3_upstream_uncache(c);

            sc = ngx_quic_open_stream(c, 1);
            if (sc == NULL) {
                ngx_quic_set_app_error(c, NGX_HTTP_V3_ERR_STREAM_CREATION_ERROR,
                                       "failed to open stream");
                continue;
            }

            sc->requests++;
            c->requests++;

            if (c->read->timer_set) {
                ngx_del_timer(c->read);
            }

            ngx_http_v3_upstream_try_cache(c);
            goto found;
        }
    }

    return NGX_OK;

found:

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "http3 get peer: using connection %p", c);

    pc->connection = sc;

    return NGX_DONE;
}


static void
ngx_http_v3_upstream_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_v3_upstream_peer_data_t  *h3p = data;

    h3p->original_free_peer(pc, h3p->data, state);
}


static ngx_int_t
ngx_http_v3_upstream_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_v3_upstream_peer_data_t  *h3p = data;

    return h3p->original_set_session(pc, h3p->data);
}


static void
ngx_http_v3_upstream_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_v3_upstream_peer_data_t  *h3p = data;

    h3p->original_save_session(pc, h3p->data);
    return;
}


static void *
ngx_http_v3_upstream_create_conf(ngx_conf_t *cf)
{
    ngx_http_v3_upstream_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_v3_upstream_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->original_init_upstream = NULL;
     *     conf->original_init_peer = NULL;
     *     conf->max_cached = 0;
     */
    conf->time = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->requests = NGX_CONF_UNSET_UINT;

    return conf;
}


static char *
ngx_http_v3_upstream_keepalive(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_v3_upstream_srv_conf_t  *h3ucf = conf;

    ngx_int_t                      n;
    ngx_str_t                     *value;
    ngx_http_upstream_srv_conf_t  *uscf;

    if (h3ucf->max_cached) {
        return "is duplicate";
    }

    /* read options */

    value = cf->args->elts;

    n = ngx_atoi(value[1].data, value[1].len);

    if (n == NGX_ERROR || n == 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"%V\" directive",
                           &value[1], &cmd->name);
        return NGX_CONF_ERROR;
    }

    h3ucf->max_cached = n;

    /* init upstream handler */

    uscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_upstream_module);

    h3ucf->original_init_upstream = uscf->peer.init_upstream
                                  ? uscf->peer.init_upstream
                                  : ngx_http_upstream_init_round_robin;

    uscf->peer.init_upstream = ngx_http_v3_upstream_init;

    return NGX_CONF_OK;
}
