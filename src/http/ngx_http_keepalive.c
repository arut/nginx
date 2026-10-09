
/*
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_http_keepalive_cache_t      *cache;

    ngx_http_upstream_t             *upstream;

    void                            *data;

    ngx_event_get_peer_pt            original_get_peer;
    ngx_event_free_peer_pt           original_free_peer;

#if (NGX_HTTP_SSL)
    ngx_event_set_peer_session_pt    original_set_session;
    ngx_event_save_peer_session_pt   original_save_session;
#endif

    ngx_event_notify_peer_pt         original_notify;
} ngx_http_keepalive_peer_data_t;


static ngx_int_t ngx_http_keepalive_get_peer(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_keepalive_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state);

static void ngx_http_keepalive_dummy_handler(ngx_event_t *ev);
static void ngx_http_keepalive_close_handler(ngx_event_t *ev);
static void ngx_http_keepalive_close(ngx_connection_t *c);

#if (NGX_HTTP_SSL)
static ngx_int_t ngx_http_keepalive_set_session(ngx_peer_connection_t *pc,
    void *data);
static void ngx_http_keepalive_save_session(ngx_peer_connection_t *pc,
    void *data);
#endif

static void ngx_http_keepalive_notify_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t type);


ngx_http_keepalive_cache_t *
ngx_http_keepalive_cache_add(ngx_conf_t *cf, ngx_array_t *caches,
    ngx_str_t *name, void *tag)
{
    ngx_uint_t                    i;
    ngx_http_keepalive_cache_t   *cache, **cp;

    cp = caches->elts;

    for (i = 0; i < caches->nelts; i++) {

        if (cp[i]->name.len != name->len
            || ngx_strncmp(cp[i]->name.data, name->data, name->len) != 0)
        {
            continue;
        }

        if (cp[i]->tag != tag) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "the keepalive cache \"%V\" is already declared "
                               "for a different use", name);
            return NULL;
        }

        return cp[i];
    }

    cache = ngx_pcalloc(cf->pool, sizeof(ngx_http_keepalive_cache_t));
    if (cache == NULL) {
        return NULL;
    }

    cache->name = *name;
    cache->tag = tag;

    cache->max = NGX_CONF_UNSET_UINT;
    cache->requests = NGX_CONF_UNSET_UINT;
    cache->inactive = NGX_CONF_UNSET_MSEC;
    cache->time = NGX_CONF_UNSET_MSEC;

    cp = ngx_array_push(caches);
    if (cp == NULL) {
        return NULL;
    }

    *cp = cache;

    return cache;
}


char *
ngx_http_keepalive_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    char  *confp = conf;

    time_t                       t;
    ngx_str_t                   *value, s;
    ngx_int_t                    n;
    ngx_uint_t                   i;
    ngx_array_t                 *caches;
    ngx_http_keepalive_cache_t  *cache;

    caches = (ngx_array_t *) (confp + cmd->offset);

    value = cf->args->elts;

    cache = ngx_http_keepalive_cache_add(cf, caches, &value[1], cmd->post);
    if (cache == NULL) {
        return NGX_CONF_ERROR;
    }

    if (cache->defined) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "duplicate keepalive cache \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    cache->defined = 1;

    for (i = 2; i < cf->args->nelts; i++) {

        if (ngx_strncmp(value[i].data, "max=", 4) == 0) {

            n = ngx_atoi(value[i].data + 4, value[i].len - 4);
            if (n <= 0) {
                goto failed;
            }

            cache->max = (ngx_uint_t) n;

            continue;
        }

        if (ngx_strncmp(value[i].data, "inactive=", 9) == 0) {

            s.len = value[i].len - 9;
            s.data = value[i].data + 9;

            t = ngx_parse_time(&s, 0);
            if (t == (time_t) NGX_ERROR) {
                goto failed;
            }

            cache->inactive = (ngx_msec_t) t;

            continue;
        }

        if (ngx_strncmp(value[i].data, "requests=", 9) == 0) {

            n = ngx_atoi(value[i].data + 9, value[i].len - 9);
            if (n <= 0) {
                goto failed;
            }

            cache->requests = (ngx_uint_t) n;

            continue;
        }

        if (ngx_strncmp(value[i].data, "time=", 5) == 0) {

            s.len = value[i].len - 5;
            s.data = value[i].data + 5;

            t = ngx_parse_time(&s, 0);
            if (t == (time_t) NGX_ERROR) {
                goto failed;
            }

            cache->time = (ngx_msec_t) t;

            continue;
        }

    failed:

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid \"%V\" parameter \"%V\"",
                           &cmd->name, &value[i]);
        return NGX_CONF_ERROR;
    }

    if (cache->max == NGX_CONF_UNSET_UINT) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "\"%V\" must have the \"max\" parameter",
                           &cmd->name);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


char *
ngx_http_keepalive_caches_init(ngx_conf_t *cf, ngx_array_t *caches)
{
    ngx_uint_t                        i, j;
    ngx_http_keepalive_cache_t      **cp;
    ngx_http_keepalive_cache_item_t  *items;

    cp = caches->elts;

    for (i = 0; i < caches->nelts; i++) {

        if (!cp[i]->defined) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown keepalive cache \"%V\"", &cp[i]->name);
            return NGX_CONF_ERROR;
        }

        ngx_conf_init_msec_value(cp[i]->inactive, 60000);
        ngx_conf_init_msec_value(cp[i]->time, 3600000);
        ngx_conf_init_uint_value(cp[i]->requests, 1000);

        items = ngx_pcalloc(cf->pool,
                   sizeof(ngx_http_keepalive_cache_item_t) * cp[i]->max);
        if (items == NULL) {
            return NGX_CONF_ERROR;
        }

        ngx_queue_init(&cp[i]->cache);
        ngx_queue_init(&cp[i]->free);

        for (j = 0; j < cp[i]->max; j++) {
            ngx_queue_insert_head(&cp[i]->free, &items[j].queue);
            items[j].cache = cp[i];
        }
    }

    return NGX_CONF_OK;
}


ngx_int_t
ngx_http_keepalive_init_peer(ngx_http_request_t *r, ngx_http_upstream_t *u)
{
    ngx_http_keepalive_peer_data_t  *kp;

    if (u->conf->keepalive_cache == NULL) {
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "init http keepalive peer, cache: \"%V\"",
                   &u->conf->keepalive_cache->name);

    kp = ngx_palloc(r->pool, sizeof(ngx_http_keepalive_peer_data_t));
    if (kp == NULL) {
        return NGX_ERROR;
    }

    kp->cache = u->conf->keepalive_cache;
    kp->upstream = u;
    kp->data = u->peer.data;
    kp->original_get_peer = u->peer.get;
    kp->original_free_peer = u->peer.free;

    u->peer.data = kp;
    u->peer.get = ngx_http_keepalive_get_peer;
    u->peer.free = ngx_http_keepalive_free_peer;

#if (NGX_HTTP_SSL)
    kp->original_set_session = u->peer.set_session;
    kp->original_save_session = u->peer.save_session;
    u->peer.set_session = ngx_http_keepalive_set_session;
    u->peer.save_session = ngx_http_keepalive_save_session;
#endif

    if (u->peer.notify) {
        kp->original_notify = u->peer.notify;
        u->peer.notify = ngx_http_keepalive_notify_peer;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_keepalive_get_peer(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_keepalive_peer_data_t  *kp = data;

    ngx_int_t                         rc;
    ngx_queue_t                      *q, *cache;
    ngx_connection_t                 *c;
    ngx_http_keepalive_cache_item_t  *item;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "get http keepalive peer");

    rc = kp->original_get_peer(pc, kp->data);

    if (rc != NGX_OK) {
        return rc;
    }

    cache = &kp->cache->cache;

    for (q = ngx_queue_head(cache);
         q != ngx_queue_sentinel(cache);
         q = ngx_queue_next(q))
    {
        item = ngx_queue_data(q, ngx_http_keepalive_cache_item_t, queue);
        c = item->connection;

        if (item->variant != kp->upstream->keepalive_variant) {
            continue;
        }

        if (ngx_memn2cmp((u_char *) &item->sockaddr, (u_char *) pc->sockaddr,
                         item->socklen, pc->socklen)
            == 0)
        {
            ngx_queue_remove(q);
            ngx_queue_insert_head(&kp->cache->free, q);

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
ngx_http_keepalive_free_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t state)
{
    ngx_http_keepalive_peer_data_t  *kp = data;

    ngx_queue_t                      *q;
    ngx_connection_t                 *c;
    ngx_http_upstream_t              *u;
    ngx_http_keepalive_cache_item_t  *item;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free http keepalive peer");

    /* cache valid connections */

    u = kp->upstream;
    c = pc->connection;

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

    if (c->requests >= kp->cache->requests) {
        goto invalid;
    }

    if (ngx_current_msec - c->start_time > kp->cache->time) {
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

    if (ngx_queue_empty(&kp->cache->free)) {

        q = ngx_queue_last(&kp->cache->cache);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_keepalive_cache_item_t, queue);

        ngx_http_keepalive_close(item->connection);

    } else {
        q = ngx_queue_head(&kp->cache->free);
        ngx_queue_remove(q);

        item = ngx_queue_data(q, ngx_http_keepalive_cache_item_t, queue);
    }

    ngx_queue_insert_head(&kp->cache->cache, q);

    item->connection = c;

    pc->connection = NULL;

    c->read->delayed = 0;
    ngx_add_timer(c->read, kp->cache->inactive);

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    c->write->handler = ngx_http_keepalive_dummy_handler;
    c->read->handler = ngx_http_keepalive_close_handler;

    c->data = item;
    c->idle = 1;
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;

    item->socklen = pc->socklen;
    ngx_memcpy(&item->sockaddr, pc->sockaddr, pc->socklen);
    item->variant = u->keepalive_variant;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, pc->log, 0,
                   "free keepalive peer: saving connection %p", c);

    if (c->read->ready) {
        ngx_http_keepalive_close_handler(c->read);
    }

invalid:

    kp->original_free_peer(pc, kp->data, state);
}


static void
ngx_http_keepalive_dummy_handler(ngx_event_t *ev)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "keepalive dummy handler");
}


static void
ngx_http_keepalive_close_handler(ngx_event_t *ev)
{
    ngx_http_keepalive_cache_t       *cache;
    ngx_http_keepalive_cache_item_t  *item;

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
    cache = item->cache;

    ngx_http_keepalive_close(c);

    ngx_queue_remove(&item->queue);
    ngx_queue_insert_head(&cache->free, &item->queue);
}


static void
ngx_http_keepalive_close(ngx_connection_t *c)
{

#if (NGX_HTTP_SSL)

    if (c->ssl) {
        c->ssl->no_wait_shutdown = 1;
        c->ssl->no_send_shutdown = 1;

        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
            c->ssl->handler = ngx_http_keepalive_close;
            return;
        }
    }

#endif

    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
}


#if (NGX_HTTP_SSL)

static ngx_int_t
ngx_http_keepalive_set_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_keepalive_peer_data_t  *kp = data;

    return kp->original_set_session(pc, kp->data);
}


static void
ngx_http_keepalive_save_session(ngx_peer_connection_t *pc, void *data)
{
    ngx_http_keepalive_peer_data_t  *kp = data;

    kp->original_save_session(pc, kp->data);
    return;
}

#endif


static void
ngx_http_keepalive_notify_peer(ngx_peer_connection_t *pc, void *data,
    ngx_uint_t type)
{
    ngx_http_keepalive_peer_data_t  *kp = data;

    kp->original_notify(pc, kp->data, type);
}
