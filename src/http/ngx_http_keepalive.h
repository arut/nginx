
/*
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_KEEPALIVE_H_INCLUDED_
#define _NGX_HTTP_KEEPALIVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


struct ngx_http_keepalive_cache_s {
    ngx_str_t                        name;

    ngx_uint_t                       max;
    ngx_msec_t                       inactive;
    ngx_msec_t                       time;
    ngx_uint_t                       requests;

    ngx_queue_t                      cache;
    ngx_queue_t                      free;

    void                            *tag;

    unsigned                         defined:1;
};


typedef struct {
    ngx_http_keepalive_cache_t      *cache;

    ngx_queue_t                      queue;
    ngx_connection_t                *connection;

    socklen_t                        socklen;
    ngx_sockaddr_t                   sockaddr;

    ngx_uint_t                       variant;
} ngx_http_keepalive_cache_item_t;


ngx_http_keepalive_cache_t *ngx_http_keepalive_cache_add(ngx_conf_t *cf,
    ngx_array_t *caches, ngx_str_t *name, void *tag);
char *ngx_http_keepalive_cache_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_keepalive_caches_init(ngx_conf_t *cf, ngx_array_t *caches);

ngx_int_t ngx_http_keepalive_init_peer(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


#endif /* _NGX_HTTP_KEEPALIVE_H_INCLUDED_ */
