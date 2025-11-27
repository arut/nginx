
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_addr_t            *addr;
    ngx_msec_t             timeout;
} ngx_http_doh_loc_conf_t;


typedef struct {
    ngx_str_t              request;
    ngx_str_t              qname;
    ngx_uint_t             qtype;
    ngx_uint_t             qclass;
    ngx_peer_connection_t  peer;
} ngx_http_doh_ctx_t;


typedef struct {
    ngx_uint_t             type;
    ngx_str_t              name;
} ngx_http_doh_qtype_t;


typedef struct {
    ngx_uint_t             class;
    ngx_str_t              name;
} ngx_http_doh_qclass_t;


static ngx_int_t ngx_http_doh_handler(ngx_http_request_t *r);
static void ngx_http_doh_init(ngx_http_request_t *r);
static ngx_int_t ngx_http_doh_set_request(ngx_http_request_t *r,
    ngx_http_doh_ctx_t *ctx);
static ngx_int_t ngx_http_doh_parse_request(ngx_http_request_t *r,
    ngx_http_doh_ctx_t *ctx);
static void ngx_http_doh_read_handler(ngx_event_t *rev);
static void ngx_http_doh_write_handler(ngx_event_t *rev);
static void ngx_http_doh_cleanup(void *data);
static ngx_int_t ngx_http_doh_qname_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_doh_qtype_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_doh_qclass_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_doh_add_variables(ngx_conf_t *cf);
static void *ngx_http_doh_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_doh_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_doh_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_doh_commands[] = {

    { ngx_string("doh_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_http_doh_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("doh_read_timeout"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_doh_loc_conf_t, timeout),
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_doh_module_ctx = {
    ngx_http_doh_add_variables,            /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_doh_create_loc_conf,          /* create location configuration */
    ngx_http_doh_merge_loc_conf            /* merge location configuration */
};


ngx_module_t  ngx_http_doh_module = {
    NGX_MODULE_V1,
    &ngx_http_doh_module_ctx,              /* module context */
    ngx_http_doh_commands,                 /* module directives */
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


static ngx_http_variable_t  ngx_http_doh_vars[] = {

    { ngx_string("doh_qname"), NULL, ngx_http_doh_qname_variable, 0, 0, 0 },

    { ngx_string("doh_qtype"), NULL, ngx_http_doh_qtype_variable, 0, 0, 0 },

    { ngx_string("doh_qclass"), NULL, ngx_http_doh_qclass_variable, 0, 0, 0 },

      ngx_http_null_variable
};


static ngx_http_doh_qtype_t  ngx_http_doh_qtypes[] = {

    { 1,   ngx_string("A") },
    { 2,   ngx_string("NS") },
    { 3,   ngx_string("MD") },
    { 4,   ngx_string("MF") },
    { 5,   ngx_string("CNAME") },
    { 6,   ngx_string("SOA") },
    { 7,   ngx_string("MB") },
    { 8,   ngx_string("MG") },
    { 9,   ngx_string("MR") },
    { 10,  ngx_string("NULL") },
    { 11,  ngx_string("WKS") },
    { 12,  ngx_string("PTR") },
    { 13,  ngx_string("HINFO") },
    { 14,  ngx_string("MINFO") },
    { 15,  ngx_string("MX") },
    { 16,  ngx_string("TXT") },
    { 17,  ngx_string("RP") },
    { 18,  ngx_string("AFSDB") },
    { 19,  ngx_string("X25") },
    { 20,  ngx_string("ISDN") },
    { 21,  ngx_string("RT") },
    { 22,  ngx_string("NSAP") },
    { 23,  ngx_string("NSAP-PTR") },
    { 24,  ngx_string("SIG") },
    { 25,  ngx_string("KEY") },
    { 26,  ngx_string("PX") },
    { 27,  ngx_string("GPOS") },
    { 28,  ngx_string("AAAA") },
    { 29,  ngx_string("LOC") },
    { 30,  ngx_string("NXT") },
    { 31,  ngx_string("EID") },
    { 32,  ngx_string("NIMLOC") },
    { 33,  ngx_string("SRV") },
    { 34,  ngx_string("ATMA") },
    { 35,  ngx_string("NAPTR") },
    { 36,  ngx_string("KX") },
    { 37,  ngx_string("CERT") },
    { 38,  ngx_string("A6") },
    { 39,  ngx_string("DNAME") },
    { 40,  ngx_string("SINK") },
    { 41,  ngx_string("OPT") },
    { 42,  ngx_string("APL") },
    { 43,  ngx_string("DS") },
    { 44,  ngx_string("SSHFP") },
    { 45,  ngx_string("IPSECKEY") },
    { 46,  ngx_string("RRSIG") },
    { 47,  ngx_string("NSEC") },
    { 48,  ngx_string("DNSKEY") },
    { 49,  ngx_string("DHCID") },
    { 50,  ngx_string("NSEC3") },
    { 51,  ngx_string("NSEC3PARAM") },
    { 52,  ngx_string("TLSA") },
    { 53,  ngx_string("SMIMEA") },

    { 55,  ngx_string("HIP") },
    { 56,  ngx_string("NINFO") },
    { 57,  ngx_string("RKEY") },
    { 58,  ngx_string("TALINK") },
    { 59,  ngx_string("CDS") },
    { 60,  ngx_string("CDNSKEY") },
    { 61,  ngx_string("OPENPGPKEY") },
    { 62,  ngx_string("CSYNC") },
    { 63,  ngx_string("ZONEMD") },
    { 64,  ngx_string("SVCB") },
    { 65,  ngx_string("HTTPS") },

    { 99,  ngx_string("SPF") },
    { 100, ngx_string("UINFO") },
    { 101, ngx_string("UID") },
    { 102, ngx_string("GID") },
    { 103, ngx_string("UNSPEC") },
    { 104, ngx_string("NID") },
    { 105, ngx_string("L32") },
    { 106, ngx_string("L64") },
    { 107, ngx_string("LP") },
    { 108, ngx_string("EUI48") },
    { 109, ngx_string("EUI64") },

    { 249, ngx_string("TKEY") },
    { 250, ngx_string("TSIG") },
    { 251, ngx_string("IXFR") },
    { 252, ngx_string("AXFR") },
    { 253, ngx_string("MAILB") },
    { 254, ngx_string("MAILA") },
    { 255, ngx_string("*") },
    { 256, ngx_string("URI") },
    { 257, ngx_string("CAA") },

    { 259, ngx_string("DOA") },

    { 32768, ngx_string("TA") },
    { 32769, ngx_string("DLV") },

    { 0,   ngx_null_string }
};


static ngx_http_doh_qclass_t  ngx_http_doh_qclasses[] = {

    { 1,   ngx_string("IN") },
    { 2,   ngx_string("CS") },
    { 3,   ngx_string("CH") },
    { 4,   ngx_string("HS") },

    { 255, ngx_string("*") },

    { 0,   ngx_null_string }
};


static ngx_str_t  ngx_http_doh_type = ngx_string("application/dns-message");


static ngx_int_t
ngx_http_doh_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    r->request_body_in_single_buf = 1;

    rc = ngx_http_read_client_request_body(r, ngx_http_doh_init);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}


static void
ngx_http_doh_init(ngx_http_request_t *r)
{
    ssize_t                   n;
    ngx_int_t                 rc;
    ngx_connection_t         *c;
    ngx_http_cleanup_t       *cln;
    ngx_http_doh_ctx_t       *ctx;
    ngx_http_doh_loc_conf_t  *dlcf;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_doh_ctx_t));
    if (ctx == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_http_doh_set_request(r, ctx) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "doh request n:%uz %xV", ctx->request.len, &ctx->request);

    if (ngx_http_doh_parse_request(r, ctx) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_doh_module);

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_doh_module);

    ctx->peer.type = SOCK_DGRAM;
    ctx->peer.sockaddr = dlcf->addr->sockaddr;
    ctx->peer.socklen = dlcf->addr->socklen;
    ctx->peer.name = &dlcf->addr->name;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = r->connection->log;
    ctx->peer.log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    cln->handler = ngx_http_doh_cleanup;
    cln->data = ctx;

    c = ctx->peer.connection;

    n = c->send(c, ctx->request.data, ctx->request.len);

    if (n != (ssize_t) ctx->request.len) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    c->read->handler = ngx_http_doh_read_handler;
    c->write->handler = ngx_http_doh_write_handler;
    c->data = r;

    dlcf = ngx_http_get_module_loc_conf(r, ngx_http_doh_module);

    ngx_add_timer(c->read, dlcf->timeout);
}


static ngx_int_t
ngx_http_doh_set_request(ngx_http_request_t *r, ngx_http_doh_ctx_t *ctx)
{
    size_t        len;
    u_char       *p;
    ngx_buf_t    *buf;
    ngx_str_t     src, dst;
    ngx_chain_t  *cl;

    if (r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD)) {

        if (ngx_http_arg(r, (u_char *) "dns", 3, &src) != NGX_OK) {
            return NGX_ERROR;
        }

        dst.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(src.len));
        if (dst.data == NULL) {
            return NGX_ERROR;
        }

        if (ngx_decode_base64(&dst, &src) != NGX_OK) {
            return NGX_ERROR;
        }

        ctx->request = dst;

        return NGX_OK;
    }

    /* NGX_HTTP_POST */

    if (r->request_body == NULL
        || r->request_body->bufs == NULL
        || r->request_body->temp_file)
    {
        return NGX_ERROR;
    }

    cl = r->request_body->bufs;
    buf = cl->buf;

    if (cl->next == NULL) {
        ctx->request.data = buf->pos;
        ctx->request.len = buf->last - buf->pos;
        return NGX_OK;
    }

    len = buf->last - buf->pos;
    cl = cl->next;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        len += buf->last - buf->pos;
    }

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ctx->request.data = p;
    cl = r->request_body->bufs;

    for ( /* void */ ; cl; cl = cl->next) {
        buf = cl->buf;
        p = ngx_cpymem(p, buf->pos, buf->last - buf->pos);
    }

    ctx->request.len = len;

    return NGX_OK;
}


static ngx_int_t
ngx_http_doh_parse_request(ngx_http_request_t *r, ngx_http_doh_ctx_t *ctx)
{
    u_char  *p, *q, *quest, *qname;
    size_t   n, nquest;

    /* RFC 1035 */

    p = ctx->request.data;
    n = ctx->request.len;

    /* Header section */

    if (n < 12) {
        return NGX_OK;
    }

    /* QDCOUNT */

    if (p[4] == 0 && p[5] == 0) {
        return NGX_OK;
    }

    /* Question section */

    quest = p + 12;
    nquest = n - 12;

    p = quest;
    n = nquest;

    for ( ;; ) {

        if (n == 0) {
            return NGX_OK;
        }

        if (*p == 0) {
            break;
        }

        if (1 + (size_t) *p > n) {
            return NGX_OK;
        }

        n -= 1 + (size_t) *p;
        p += 1 + (size_t) *p;
    }

    qname = ngx_pnalloc(r->pool, p - quest);
    if (qname == NULL) {
        return NGX_ERROR;
    }

    q = qname;
    p = quest;
    n = nquest;

    while (*p) {

        if (q != qname) {
            *q++ = '.';
        }

        q = ngx_cpymem(q, p + 1, *p);

        n -= 1 + (size_t) *p;
        p += 1 + (size_t) *p;
    }

    ctx->qname.data = qname;
    ctx->qname.len = q - qname;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "doh qname \"%V\"", &ctx->qname);

    if (n >= 3) {
        ctx->qtype = (ngx_uint_t) p[1] * 256 + p[2];

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "doh qtype:%ui", ctx->qtype);

        p += 3;
        n -= 3;

        if (n >= 2) {
            ctx->qclass = (ngx_uint_t) p[0] * 256 + p[1];

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                           "doh qclass:%ui", ctx->qclass);
        }
    }

    return NGX_OK;
}


static void
ngx_http_doh_read_handler(ngx_event_t *rev)
{
    u_char                    *p;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_connection_t          *c;
    ngx_http_request_t        *r;
    ngx_http_complex_value_t   cv;

    static u_char              buffer[65535];

    c = rev->data;
    r = c->data;

    if (rev->timedout) {
        ngx_http_finalize_request(r, NGX_HTTP_GATEWAY_TIME_OUT);
        return;
    }

    n = c->recv(c, buffer, sizeof(buffer));

    if (n == NGX_AGAIN) {
        return;
    }

    if (n <= 0) {
        ngx_http_finalize_request(r, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "doh response n:%uz %*xs", n, n, buffer);

    p = ngx_pnalloc(r->pool, n);
    if (p == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memcpy(p, buffer, n);

    ngx_memzero(&cv, sizeof(ngx_http_complex_value_t));

    cv.value.len = n;
    cv.value.data = p;

    rc = ngx_http_send_response(r, NGX_HTTP_OK, &ngx_http_doh_type, &cv);

    ngx_http_finalize_request(r, rc);
}


static void
ngx_http_doh_write_handler(ngx_event_t *wev)
{
    /* dummy */
}


static void
ngx_http_doh_cleanup(void *data)
{
    ngx_http_doh_ctx_t *ctx = data;

    if (ctx->peer.connection) {
        ngx_close_connection(ctx->peer.connection);
        ctx->peer.connection = NULL;
    }
}


static ngx_int_t
ngx_http_doh_qname_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_doh_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_doh_module);

    if (ctx == NULL || ctx->qname.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ctx->qname.len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = ctx->qname.data;

    return NGX_OK;
}


static ngx_int_t
ngx_http_doh_qtype_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    u_char                *p;
    ngx_http_doh_ctx_t    *ctx;
    ngx_http_doh_qtype_t  *qt;

    ctx = ngx_http_get_module_ctx(r, ngx_http_doh_module);

    if (ctx == NULL || ctx->qtype == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    for (qt = ngx_http_doh_qtypes; qt->type; qt++) {
        if (qt->type == ctx->qtype) {
            v->len = qt->name.len;
            v->data = qt->name.data;
            return NGX_OK;
        }
    }

    /* RFC 3597 */

    p = ngx_pnalloc(r->pool, sizeof("TYPE65535") - 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "TYPE%ui", ctx->qtype) - p;
    v->data = p;

    return NGX_OK;
}


static ngx_int_t
ngx_http_doh_qclass_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    u_char                 *p;
    ngx_http_doh_ctx_t     *ctx;
    ngx_http_doh_qclass_t  *qc;

    ctx = ngx_http_get_module_ctx(r, ngx_http_doh_module);

    if (ctx == NULL || ctx->qclass == 0) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    for (qc = ngx_http_doh_qclasses; qc->class; qc++) {
        if (qc->class == ctx->qclass) {
            v->len = qc->name.len;
            v->data = qc->name.data;
            return NGX_OK;
        }
    }

    /* RFC 3597 */

    p = ngx_pnalloc(r->pool, sizeof("CLASS65535") - 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "CLASS%ui", ctx->qclass) - p;
    v->data = p;

    return NGX_OK;
}

static ngx_int_t
ngx_http_doh_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_doh_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}


static void *
ngx_http_doh_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_doh_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_doh_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->addr = NULL;
     */

    conf->timeout = NGX_CONF_UNSET_MSEC;

    return conf;
}


static char *
ngx_http_doh_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_doh_loc_conf_t *prev = parent;
    ngx_http_doh_loc_conf_t *conf = child;

    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 5000);

    return NGX_CONF_OK;
}


static char *
ngx_http_doh_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_doh_loc_conf_t *dlcf = conf;

    ngx_str_t                 *value;
    ngx_url_t                  u;
    ngx_http_core_loc_conf_t  *clcf;

    if (dlcf->addr) {
        return "is duplicate";
    }

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    clcf->handler = ngx_http_doh_handler;

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));

    u.url = value[1];

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in doh upstream \"%V\"", u.err, &u.url);
        }

        return NGX_CONF_ERROR;
    }

    dlcf->addr = &u.addrs[0];

    return NGX_CONF_OK;
}
