
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_V3_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_V3_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


ngx_int_t ngx_http_v3_upstream_create_stream(ngx_http_request_t *r);


#endif /* _NGX_HTTP_V3_UPSTREAM_H_INCLUDED_ */
