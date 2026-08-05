
/*
 * Copyright (C) Roman Arutyunyan
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ngx_sha1.h>


#define NGX_HTTP_FUNC_MAX_ARGS   2

#define NGX_HTTP_FUNC_FILE_MAX   1024

#define NGX_HTTP_FUNC_NO_NUMBER  0
#define NGX_HTTP_FUNC_OPT_NUMBER 1
#define NGX_HTTP_FUNC_NUMBER     2

#define NGX_HTTP_FUNC_BASE64     0
#define NGX_HTTP_FUNC_BASE64URL  1

#define NGX_HTTP_FUNC_SHA256     0
#define NGX_HTTP_FUNC_SHA1       1
#define NGX_HTTP_FUNC_MD5        2
#define NGX_HTTP_FUNC_SHA512     3

#define NGX_HTTP_FUNC_ADD        0
#define NGX_HTTP_FUNC_MOD        1

#define NGX_HTTP_FUNC_LT         0
#define NGX_HTTP_FUNC_LE         1
#define NGX_HTTP_FUNC_GT         2
#define NGX_HTTP_FUNC_GE         3
#define NGX_HTTP_FUNC_EQ         4


typedef struct {
    ngx_http_complex_value_t  *args[NGX_HTTP_FUNC_MAX_ARGS];
    ngx_uint_t                 type;
    ngx_uint_t                 number;
} ngx_http_func_ctx_t;


typedef struct {
    ngx_str_t                  name;
    ngx_http_get_variable_pt   handler;
    ngx_uint_t                 nargs;      /* number of value arguments */
    ngx_uint_t                 number;     /* trailing numeric argument */
    ngx_uint_t                 type;       /* handler-specific selector */
} ngx_http_func_function_t;


static char *ngx_http_func(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_http_func_ctx_t *ngx_http_func_parser(ngx_conf_t *cf,
    ngx_http_func_function_t *ff);
static ngx_http_complex_value_t *ngx_http_func_complex_value(ngx_conf_t *cf,
    ngx_str_t *s);
static void ngx_http_func_value(ngx_http_variable_value_t *v, u_char *data,
    size_t len);

static ngx_int_t ngx_http_func_random_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_random_string_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_escape_uri_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_unescape_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_escape_html_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_escape_json_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_hex_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_unhex_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_base64_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_unbase64_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_tolower_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_toupper_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_length_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_file_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_operands(ngx_http_request_t *r,
    ngx_http_func_ctx_t *ctx, ngx_int_t *a, ngx_int_t *b);
static ngx_int_t ngx_http_func_arith_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_compare_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_str_eq_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_md5_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_sha1_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_crc32_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#if (NGX_OPENSSL)
static const EVP_MD *ngx_http_func_evp_md(ngx_uint_t type);
static ngx_int_t ngx_http_func_digest_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_hmac_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_func_secure_eq_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
#endif


static ngx_command_t  ngx_http_func_commands[] = {

    { ngx_string("func"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_2MORE,
      ngx_http_func,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


/*
 * Arguments are positional.  Value arguments are complex values; "random"
 * and "random_string" take a plain number instead.
 *
 * func random               $out [N]         a number in [0, N), or unbounded
 * func random_string        $out N           N random bytes
 *
 * func escape_uri           $out $in         ngx_escape_uri(), URI
 * func escape_uri_args      $out $in         ngx_escape_uri(), args
 * func escape_uri_component $out $in         ngx_escape_uri(), component
 * func escape_uri_html      $out $in         ngx_escape_uri(), HTML
 * func escape_html          $out $in         ngx_escape_html(), "&lt;" style
 * func escape_json          $out $in
 *
 * func unescape             $out $in         unescape everything
 * func unescape_uri         $out $in         keep the URI delimiters escaped
 * func unescape_redirect    $out $in         keep unsafe characters escaped
 *
 * func hex                  $out $in
 * func unhex                $out $in
 * func base64               $out $in
 * func base64url            $out $in
 * func unbase64             $out $in
 * func unbase64url          $out $in
 *
 * func tolower              $out $in
 * func toupper              $out $in
 * func length               $out $in         the length in bytes, decimal
 *
 * func file                 $out $name       up to 1024 bytes of the file
 *     $name, read through open_file_cache; a relative $name is taken
 *     relative to the prefix; the variable is left not found if the file
 *     cannot be opened or is a directory
 *
 * func add                  $out $a $b       $a + $b
 * func mod                  $out $a $b       $a % $b
 * func eq                   $out $a $b       "1" if $a == $b, else "0"
 * func lt                   $out $a $b       "1" if $a <  $b, else "0"
 * func le                   $out $a $b       "1" if $a <= $b, else "0"
 * func gt                   $out $a $b       "1" if $a >  $b, else "0"
 * func ge                   $out $a $b       "1" if $a >= $b, else "0"
 * func str_eq               $out $a $b       "1" if the bytes are equal
 *
 * func md5                  $out $in
 * func sha1                 $out $in
 * func crc32                $out $in
 * func sha256               $out $in              (requires OpenSSL)
 * func sha512               $out $in              (requires OpenSSL)
 * func hmac_sha256          $out $in $key         (requires OpenSSL)
 * func hmac_sha512          $out $in $key         (requires OpenSSL)
 * func hmac_sha1            $out $in $key         (requires OpenSSL)
 * func hmac_md5             $out $in $key         (requires OpenSSL)
 * func secure_eq            $out $a $b            (requires OpenSSL)
 *     "1" if $a and $b are equal, else "0"; the comparison time does not
 *     depend on how far the values match, for verifying signatures.  Note
 *     that two empty values compare equal, so guard against an absent
 *     signature separately if that matters.
 *
 * Functions producing binary output (md5, sha1, sha256, sha512, hmac_*,
 * crc32, random_string) are meant to be composed with "hex" or "base64":
 *
 *     func hmac_sha256  $sig    $uri $secret;
 *     func base64url    $sig64  $sig;
 *
 * "eq" and the other comparisons are numeric; "str_eq" compares bytes.
 * Unlike "if", they are usable at any point of request processing, which
 * matters for values that only exist after the upstream response.
 *
 * The following leave the variable not found: "unhex", "unbase64" and
 * "unbase64url" on invalid input; the arithmetic and comparison functions
 * on a non-numeric operand, on division by zero and on overflow.  Operands
 * are unsigned decimal integers.
 */


static ngx_http_func_function_t  ngx_http_func_functions[] = {

    { ngx_string("random"),
      ngx_http_func_random_handler,
      0,
      NGX_HTTP_FUNC_OPT_NUMBER,
      0 },

    { ngx_string("random_string"),
      ngx_http_func_random_string_handler,
      0,
      NGX_HTTP_FUNC_NUMBER,
      0 },

    { ngx_string("escape_uri"),
      ngx_http_func_escape_uri_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_ESCAPE_URI },

    { ngx_string("escape_uri_args"),
      ngx_http_func_escape_uri_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_ESCAPE_ARGS },

    { ngx_string("escape_uri_component"),
      ngx_http_func_escape_uri_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_ESCAPE_URI_COMPONENT },

    { ngx_string("escape_uri_html"),
      ngx_http_func_escape_uri_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_ESCAPE_HTML },

    { ngx_string("unescape"),
      ngx_http_func_unescape_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("unescape_uri"),
      ngx_http_func_unescape_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_UNESCAPE_URI },

    { ngx_string("unescape_redirect"),
      ngx_http_func_unescape_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_UNESCAPE_REDIRECT },

    { ngx_string("escape_html"),
      ngx_http_func_escape_html_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("escape_json"),
      ngx_http_func_escape_json_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("hex"),
      ngx_http_func_hex_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("unhex"),
      ngx_http_func_unhex_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("base64"),
      ngx_http_func_base64_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_BASE64 },

    { ngx_string("base64url"),
      ngx_http_func_base64_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_BASE64URL },

    { ngx_string("unbase64"),
      ngx_http_func_unbase64_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_BASE64 },

    { ngx_string("unbase64url"),
      ngx_http_func_unbase64_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_BASE64URL },

    { ngx_string("tolower"),
      ngx_http_func_tolower_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("toupper"),
      ngx_http_func_toupper_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("length"),
      ngx_http_func_length_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("file"),
      ngx_http_func_file_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("md5"),
      ngx_http_func_md5_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("sha1"),
      ngx_http_func_sha1_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("crc32"),
      ngx_http_func_crc32_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

    { ngx_string("add"),
      ngx_http_func_arith_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_ADD },

    { ngx_string("mod"),
      ngx_http_func_arith_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_MOD },

    { ngx_string("eq"),
      ngx_http_func_compare_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_EQ },

    { ngx_string("lt"),
      ngx_http_func_compare_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_LT },

    { ngx_string("le"),
      ngx_http_func_compare_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_LE },

    { ngx_string("gt"),
      ngx_http_func_compare_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_GT },

    { ngx_string("ge"),
      ngx_http_func_compare_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_GE },

    { ngx_string("str_eq"),
      ngx_http_func_str_eq_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

#if (NGX_OPENSSL)

    { ngx_string("sha256"),
      ngx_http_func_digest_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_SHA256 },

    { ngx_string("sha512"),
      ngx_http_func_digest_handler,
      1,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_SHA512 },

    { ngx_string("hmac_sha256"),
      ngx_http_func_hmac_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_SHA256 },

    { ngx_string("hmac_sha1"),
      ngx_http_func_hmac_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_SHA1 },

    { ngx_string("hmac_sha512"),
      ngx_http_func_hmac_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_SHA512 },

    { ngx_string("hmac_md5"),
      ngx_http_func_hmac_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      NGX_HTTP_FUNC_MD5 },

    { ngx_string("secure_eq"),
      ngx_http_func_secure_eq_handler,
      2,
      NGX_HTTP_FUNC_NO_NUMBER,
      0 },

#endif

    { ngx_null_string, NULL, 0, 0, 0 }
};


static ngx_http_module_t  ngx_http_func_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_func_module = {
    NGX_MODULE_V1,
    &ngx_http_func_module_ctx,             /* module context */
    ngx_http_func_commands,                /* module directives */
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


static char *
ngx_http_func(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                 *value, name;
    ngx_http_variable_t       *var;
    ngx_http_func_ctx_t       *ctx;
    ngx_http_func_function_t  *ff;

    value = cf->args->elts;

    name = value[1];

    for (ff = ngx_http_func_functions; ff->name.len; ff++) {
        if (ff->name.len == name.len
            && ngx_strncasecmp(ff->name.data, name.data, name.len) == 0)
        {
            goto found;
        }
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid function name \"%V\"", &name);
    return NGX_CONF_ERROR;

found:

    ctx = ngx_http_func_parser(cf, ff);
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    name = value[2];

    if (name.len == 0 || name.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid variable name \"%V\"", &name);
        return NGX_CONF_ERROR;
    }

    name.len--;
    name.data++;

    var = ngx_http_add_variable(cf, &name, NGX_HTTP_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_CONF_ERROR;
    }

    var->get_handler = ff->handler;
    var->data = (uintptr_t) ctx;

    return NGX_CONF_OK;
}


static ngx_http_func_ctx_t *
ngx_http_func_parser(ngx_conf_t *cf, ngx_http_func_function_t *ff)
{
    ngx_str_t            *value;
    ngx_int_t             n;
    ngx_uint_t            i, nargs, min, max;
    ngx_http_func_ctx_t  *ctx;

    value = cf->args->elts;
    nargs = cf->args->nelts - 3;

    min = ff->nargs + (ff->number == NGX_HTTP_FUNC_NUMBER ? 1 : 0);
    max = ff->nargs + (ff->number == NGX_HTTP_FUNC_NO_NUMBER ? 0 : 1);

    if (nargs < min || nargs > max) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid number of \"%V\" arguments", &ff->name);
        return NULL;
    }

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_func_ctx_t));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->type = ff->type;

    for (i = 0; i < ff->nargs; i++) {
        ctx->args[i] = ngx_http_func_complex_value(cf, &value[3 + i]);
        if (ctx->args[i] == NULL) {
            return NULL;
        }
    }

    if (nargs > ff->nargs) {
        n = ngx_atoi(value[3 + i].data, value[3 + i].len);

        if (n == NGX_ERROR || n == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid \"%V\" argument \"%V\"",
                               &ff->name, &value[3 + i]);
            return NULL;
        }

        ctx->number = n;
    }

    return ctx;
}


static ngx_http_complex_value_t *
ngx_http_func_complex_value(ngx_conf_t *cf, ngx_str_t *s)
{
    ngx_http_complex_value_t          *cv;
    ngx_http_compile_complex_value_t   ccv;

    cv = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (cv == NULL) {
        return NULL;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    ccv.cf = cf;
    ccv.value = s;
    ccv.complex_value = cv;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NULL;
    }

    return cv;
}


static void
ngx_http_func_value(ngx_http_variable_value_t *v, u_char *data, size_t len)
{
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = len;
    v->data = data;
}


static ngx_int_t
ngx_http_func_random_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char      *p;
    ngx_uint_t   n;

    n = (ngx_uint_t) ngx_random();

    if (ctx->number) {
        /* modulo bias is not significant for the intended usage */
        n %= ctx->number;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_http_func_value(v, p, ngx_sprintf(p, "%ui", n) - p);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func random: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_random_string_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char  *p;
#if !(NGX_OPENSSL)
    size_t   i;
#endif

    p = ngx_pnalloc(r->pool, ctx->number);
    if (p == NULL) {
        return NGX_ERROR;
    }

#if (NGX_OPENSSL)

    if (RAND_bytes(p, ctx->number) != 1) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "RAND_bytes() failed");
        return NGX_ERROR;
    }

#else

    for (i = 0; i < ctx->number; i++) {
        p[i] = (u_char) ngx_random();
    }

#endif

    ngx_http_func_value(v, p, ctx->number);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func random_string: \"%xv\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_escape_uri_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    size_t      len;
    uintptr_t   escape;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    escape = ngx_escape_uri(NULL, val.data, val.len, ctx->type);

    len = val.len + 2 * escape;

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_escape_uri(p, val.data, val.len, ctx->type);

    ngx_http_func_value(v, p, len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func escape_uri: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_unescape_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p, *dst, *src;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, val.len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    dst = p;
    src = val.data;

    ngx_unescape_uri(&dst, &src, val.len, ctx->type);

    ngx_http_func_value(v, p, dst - p);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func unescape: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_escape_html_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    size_t      len;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    len = val.len + ngx_escape_html(NULL, val.data, val.len);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_escape_html(p, val.data, val.len);

    ngx_http_func_value(v, p, len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func escape_html: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_escape_json_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    size_t      len;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    len = val.len + ngx_escape_json(NULL, val.data, val.len);

    p = ngx_pnalloc(r->pool, len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_escape_json(p, val.data, val.len);

    ngx_http_func_value(v, p, len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func escape_json: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_hex_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, val.len * 2);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(p, val.data, val.len);

    ngx_http_func_value(v, p, val.len * 2);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func hex: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_unhex_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p, *s, c;
    size_t      i;
    ngx_int_t   n, hi;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (val.len % 2) {
        goto invalid;
    }

    p = ngx_pnalloc(r->pool, val.len / 2);
    if (p == NULL) {
        return NGX_ERROR;
    }

    s = p;
    hi = -1;

    for (i = 0; i < val.len; i++) {
        c = val.data[i];

        if (c >= '0' && c <= '9') {
            n = c - '0';

        } else if (c >= 'a' && c <= 'f') {
            n = c - 'a' + 10;

        } else if (c >= 'A' && c <= 'F') {
            n = c - 'A' + 10;

        } else {
            goto invalid;
        }

        if (hi < 0) {
            hi = n;
            continue;
        }

        *s++ = (u_char) ((hi << 4) + n);
        hi = -1;
    }

    ngx_http_func_value(v, p, s - p);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func unhex: \"%xv\"", v);

    return NGX_OK;

invalid:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func unhex: invalid input");

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_base64_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    ngx_str_t  val, dst;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    dst.data = ngx_pnalloc(r->pool, ngx_base64_encoded_length(val.len));
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    if (ctx->type == NGX_HTTP_FUNC_BASE64URL) {
        ngx_encode_base64url(&dst, &val);

    } else {
        ngx_encode_base64(&dst, &val);
    }

    ngx_http_func_value(v, dst.data, dst.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func base64: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_unbase64_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    ngx_int_t  rc;
    ngx_str_t  val, dst;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    dst.data = ngx_pnalloc(r->pool, ngx_base64_decoded_length(val.len));
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    if (ctx->type == NGX_HTTP_FUNC_BASE64URL) {
        rc = ngx_decode_base64url(&dst, &val);

    } else {
        rc = ngx_decode_base64(&dst, &val);
    }

    if (rc != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http func unbase64: invalid input");

        v->not_found = 1;

        return NGX_OK;
    }

    ngx_http_func_value(v, dst.data, dst.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func unbase64: \"%xv\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_tolower_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, val.len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(p, val.data, val.len);

    ngx_http_func_value(v, p, val.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func tolower: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_toupper_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    size_t      i;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, val.len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    for (i = 0; i < val.len; i++) {
        p[i] = ngx_toupper(val.data[i]);
    }

    ngx_http_func_value(v, p, val.len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func toupper: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_length_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, NGX_SIZE_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_http_func_value(v, p, ngx_sprintf(p, "%uz", val.len) - p);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func length: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_file_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    size_t                     size;
    ssize_t                    n;
    u_char                    *p;
    ngx_str_t                  val, path;
    ngx_file_t                 file;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    path.len = val.len;

    path.data = ngx_pnalloc(r->pool, path.len + 1);
    if (path.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(path.data, val.data, val.len);
    path.data[path.len] = '\0';

    if (ngx_get_full_name(r->pool, (ngx_str_t *) &ngx_cycle->prefix, &path)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, of.err,
                       "http func file open \"%s\" failed: %d",
                       path.data, of.err);
        v->not_found = 1;
        return NGX_OK;
    }

    if (of.is_dir) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http func file \"%s\" is a directory", path.data);
        v->not_found = 1;
        return NGX_OK;
    }

    size = ngx_min(of.size, NGX_HTTP_FUNC_FILE_MAX);

    p = ngx_pnalloc(r->pool, size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));

    file.fd = of.fd;
    file.name = path;
    file.log = r->connection->log;

    n = ngx_read_file(&file, p, size, 0);

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    ngx_http_func_value(v, p, n);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func file: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_operands(ngx_http_request_t *r, ngx_http_func_ctx_t *ctx,
    ngx_int_t *a, ngx_int_t *b)
{
    ngx_str_t  val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    *a = ngx_atoi(val.data, val.len);

    if (*a == NGX_ERROR) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, ctx->args[1], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    *b = ngx_atoi(val.data, val.len);

    if (*b == NGX_ERROR) {
        return NGX_DECLINED;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_arith_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    ngx_int_t   a, b, rc, n;

    rc = ngx_http_func_operands(r, ctx, &a, &b);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        goto invalid;
    }

    if (ctx->type == NGX_HTTP_FUNC_MOD) {

        if (b == 0) {
            goto invalid;
        }

        n = a % b;

    } else {
        if (a > NGX_MAX_INT_T_VALUE - b) {
            goto invalid;
        }

        n = a + b;
    }

    p = ngx_pnalloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_http_func_value(v, p, ngx_sprintf(p, "%i", n) - p);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func arith: \"%v\"", v);

    return NGX_OK;

invalid:

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func arith: invalid operands");

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_compare_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    ngx_int_t   a, b, rc;
    ngx_uint_t  yes;

    rc = ngx_http_func_operands(r, ctx, &a, &b);

    if (rc == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (rc == NGX_DECLINED) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http func compare: invalid operands");

        v->not_found = 1;

        return NGX_OK;
    }

    switch (ctx->type) {

    case NGX_HTTP_FUNC_EQ:
        yes = (a == b);
        break;

    case NGX_HTTP_FUNC_LT:
        yes = (a < b);
        break;

    case NGX_HTTP_FUNC_LE:
        yes = (a <= b);
        break;

    case NGX_HTTP_FUNC_GT:
        yes = (a > b);
        break;

    default: /* NGX_HTTP_FUNC_GE */
        yes = (a >= b);
        break;
    }

    ngx_http_func_value(v, yes ? (u_char *) "1" : (u_char *) "0", 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func compare: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_str_eq_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    ngx_str_t   a, b;
    ngx_uint_t  yes;

    if (ngx_http_complex_value(r, ctx->args[0], &a) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, ctx->args[1], &b) != NGX_OK) {
        return NGX_ERROR;
    }

    yes = (a.len == b.len && ngx_memcmp(a.data, b.data, a.len) == 0);

    ngx_http_func_value(v, yes ? (u_char *) "1" : (u_char *) "0", 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func str_eq: \"%v\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_md5_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    ngx_str_t   val;
    ngx_md5_t   md5;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, 16);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_md5_init(&md5);
    ngx_md5_update(&md5, val.data, val.len);
    ngx_md5_final(p, &md5);

    ngx_http_func_value(v, p, 16);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func md5: \"%xv\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_sha1_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char      *p;
    ngx_str_t    val;
    ngx_sha1_t   sha1;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, 20);
    if (p == NULL) {
        return NGX_ERROR;
    }

    ngx_sha1_init(&sha1);
    ngx_sha1_update(&sha1, val.data, val.len);
    ngx_sha1_final(p, &sha1);

    ngx_http_func_value(v, p, 20);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func sha1: \"%xv\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_crc32_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char     *p;
    uint32_t    crc;
    ngx_str_t   val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    crc = ngx_crc32_long(val.data, val.len);

    p = ngx_pnalloc(r->pool, 4);
    if (p == NULL) {
        return NGX_ERROR;
    }

    p[0] = (u_char) (crc >> 24);
    p[1] = (u_char) (crc >> 16);
    p[2] = (u_char) (crc >> 8);
    p[3] = (u_char) crc;

    ngx_http_func_value(v, p, 4);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func crc32: \"%xv\"", v);

    return NGX_OK;
}


#if (NGX_OPENSSL)

static const EVP_MD *
ngx_http_func_evp_md(ngx_uint_t type)
{
    switch (type) {

    case NGX_HTTP_FUNC_MD5:
        return EVP_md5();

    case NGX_HTTP_FUNC_SHA1:
        return EVP_sha1();

    case NGX_HTTP_FUNC_SHA512:
        return EVP_sha512();

    default: /* NGX_HTTP_FUNC_SHA256 */
        return EVP_sha256();
    }
}


static ngx_int_t
ngx_http_func_digest_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char        *p;
    unsigned int   len;
    ngx_str_t      val;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    p = ngx_pnalloc(r->pool, EVP_MAX_MD_SIZE);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (EVP_Digest(val.data, val.len, p, &len,
                   ngx_http_func_evp_md(ctx->type), NULL)
        == 0)
    {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "EVP_Digest() failed");
        return NGX_ERROR;
    }

    ngx_http_func_value(v, p, len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func digest: \"%xv\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_hmac_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    u_char        *p;
    unsigned int   len;
    ngx_str_t      val, key;
    const EVP_MD  *md;

    if (ngx_http_complex_value(r, ctx->args[0], &val) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, ctx->args[1], &key) != NGX_OK) {
        return NGX_ERROR;
    }

    md = ngx_http_func_evp_md(ctx->type);

    p = ngx_pnalloc(r->pool, EVP_MAX_MD_SIZE);
    if (p == NULL) {
        return NGX_ERROR;
    }

    if (HMAC(md, key.data, (int) key.len, val.data, val.len, p, &len) == NULL) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "HMAC() failed");
        return NGX_ERROR;
    }

    ngx_http_func_value(v, p, len);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func hmac: \"%xv\"", v);

    return NGX_OK;
}


static ngx_int_t
ngx_http_func_secure_eq_handler(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_func_ctx_t  *ctx = (ngx_http_func_ctx_t *) data;

    ngx_str_t   a, b;
    ngx_uint_t  yes;

    if (ngx_http_complex_value(r, ctx->args[0], &a) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_http_complex_value(r, ctx->args[1], &b) != NGX_OK) {
        return NGX_ERROR;
    }

    /*
     * the comparison time does not depend on the position of the first
     * differing byte; the lengths are not secret and are compared first
     */

    yes = (a.len == b.len && CRYPTO_memcmp(a.data, b.data, a.len) == 0);

    ngx_http_func_value(v, yes ? (u_char *) "1" : (u_char *) "0", 1);

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http func secure_eq: \"%v\"", v);

    return NGX_OK;
}

#endif
