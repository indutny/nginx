
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef ngx_int_t (*ngx_ssl_variable_handler_pt)(ngx_connection_t *c,
    ngx_pool_t *pool, ngx_str_t *s);


#define NGX_DEFAULT_CIPHERS     "HIGH:!aNULL:!MD5"
#define NGX_DEFAULT_ECDH_CURVE  "prime256v1"


#ifdef TLSEXT_TYPE_next_proto_neg
static int ngx_http_ssl_npn_advertised(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned int *outlen, void *arg);
#endif

#ifdef SSL_MODE_ASYNC_KEY_EX
static char *
ngx_http_ssl_key_ex_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_ssl_key_ex(ngx_ssl_conn_t *ssl_conn);

/* Upstream bindings */
static ngx_int_t ngx_http_ssl_ke_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_ssl_ke_process_status_line(ngx_http_request_t *r);
static ngx_int_t ngx_http_ssl_ke_process_header(ngx_http_request_t *r);
static ngx_int_t ngx_http_ssl_ke_reinit_request(ngx_http_request_t *r);
static void ngx_http_ssl_ke_abort_request(ngx_http_request_t *r);
static void ngx_http_ssl_ke_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static ngx_int_t ngx_http_ssl_ke_input_filter_init(void *data);
static ngx_int_t ngx_http_ssl_ke_input_filter(void *data, ssize_t bytes);
#endif

static ngx_int_t ngx_http_ssl_static_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ssl_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_ssl_add_variables(ngx_conf_t *cf);
static void *ngx_http_ssl_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

static ngx_int_t ngx_http_ssl_init(ngx_conf_t *cf);


typedef struct {
  SSL* ssl;
  ngx_http_chunked_t chunked;
  struct {
    ssize_t len;
    ngx_chain_t* start;
    ngx_chain_t* end;
  } body;
} ngx_http_ssl_ke_ctx_t;


static ngx_conf_bitmask_t  ngx_http_ssl_protocols[] = {
    { ngx_string("SSLv2"), NGX_SSL_SSLv2 },
    { ngx_string("SSLv3"), NGX_SSL_SSLv3 },
    { ngx_string("TLSv1"), NGX_SSL_TLSv1 },
    { ngx_string("TLSv1.1"), NGX_SSL_TLSv1_1 },
    { ngx_string("TLSv1.2"), NGX_SSL_TLSv1_2 },
    { ngx_null_string, 0 }
};


static ngx_conf_enum_t  ngx_http_ssl_verify[] = {
    { ngx_string("off"), 0 },
    { ngx_string("on"), 1 },
    { ngx_string("optional"), 2 },
    { ngx_string("optional_no_ca"), 3 },
    { ngx_null_string, 0 }
};


static ngx_command_t  ngx_http_ssl_commands[] = {

    { ngx_string("ssl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_http_ssl_enable,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, enable),
      NULL },

    { ngx_string("ssl_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate),
      NULL },

    { ngx_string("ssl_certificate_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, certificate_key),
      NULL },

    { ngx_string("ssl_dhparam"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, dhparam),
      NULL },

    { ngx_string("ssl_ecdh_curve"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ecdh_curve),
      NULL },

    { ngx_string("ssl_protocols"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, protocols),
      &ngx_http_ssl_protocols },

    { ngx_string("ssl_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, ciphers),
      NULL },

    { ngx_string("ssl_verify_client"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, verify),
      &ngx_http_ssl_verify },

    { ngx_string("ssl_verify_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, verify_depth),
      NULL },

    { ngx_string("ssl_client_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, client_certificate),
      NULL },

    { ngx_string("ssl_trusted_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, trusted_certificate),
      NULL },

    { ngx_string("ssl_prefer_server_ciphers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, prefer_server_ciphers),
      NULL },

    { ngx_string("ssl_session_cache"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_ssl_session_cache,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("ssl_session_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, session_timeout),
      NULL },

    { ngx_string("ssl_crl"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, crl),
      NULL },

    { ngx_string("ssl_stapling"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling),
      NULL },

    { ngx_string("ssl_stapling_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling_file),
      NULL },

    { ngx_string("ssl_stapling_responder"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling_responder),
      NULL },

    { ngx_string("ssl_stapling_verify"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_ssl_srv_conf_t, stapling_verify),
      NULL },

#ifdef SSL_MODE_ASYNC_KEY_EX
    { ngx_string("ssl_key_ex_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_ssl_key_ex_upstream,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },
#endif

      ngx_null_command
};


static ngx_http_module_t  ngx_http_ssl_module_ctx = {
    ngx_http_ssl_add_variables,            /* preconfiguration */
    ngx_http_ssl_init,                     /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_http_ssl_create_srv_conf,          /* create server configuration */
    ngx_http_ssl_merge_srv_conf,           /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_ssl_module = {
    NGX_MODULE_V1,
    &ngx_http_ssl_module_ctx,              /* module context */
    ngx_http_ssl_commands,                 /* module directives */
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


static ngx_http_variable_t  ngx_http_ssl_vars[] = {

    { ngx_string("ssl_protocol"), NULL, ngx_http_ssl_static_variable,
      (uintptr_t) ngx_ssl_get_protocol, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_cipher"), NULL, ngx_http_ssl_static_variable,
      (uintptr_t) ngx_ssl_get_cipher_name, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_session_id"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_session_id, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_cert"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_certificate, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_raw_cert"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_raw_certificate,
      NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_s_dn"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_subject_dn, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_i_dn"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_issuer_dn, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_serial"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_serial_number, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_string("ssl_client_verify"), NULL, ngx_http_ssl_variable,
      (uintptr_t) ngx_ssl_get_client_verify, NGX_HTTP_VAR_CHANGEABLE, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};


static ngx_str_t ngx_http_ssl_sess_id_ctx = ngx_string("HTTP");


#ifdef TLSEXT_TYPE_next_proto_neg

#define NGX_HTTP_NPN_ADVERTISE  "\x08http/1.1"

static int
ngx_http_ssl_npn_advertised(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned int *outlen, void *arg)
{
#if (NGX_HTTP_SPDY || NGX_DEBUG)
    ngx_connection_t  *c;

    c = ngx_ssl_get_connection(ssl_conn);
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0, "SSL NPN advertised");
#endif

#if (NGX_HTTP_SPDY)
    {
    ngx_http_connection_t  *hc;

    hc = c->data;

    if (hc->addr_conf->spdy) {
        *out = (unsigned char *) NGX_SPDY_NPN_ADVERTISE NGX_HTTP_NPN_ADVERTISE;
        *outlen = sizeof(NGX_SPDY_NPN_ADVERTISE NGX_HTTP_NPN_ADVERTISE) - 1;

        return SSL_TLSEXT_ERR_OK;
    }
    }
#endif

    *out = (unsigned char *) NGX_HTTP_NPN_ADVERTISE;
    *outlen = sizeof(NGX_HTTP_NPN_ADVERTISE) - 1;

    return SSL_TLSEXT_ERR_OK;
}

#endif


static ngx_int_t
ngx_http_ssl_static_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;

    size_t     len;
    ngx_str_t  s;

    if (r->connection->ssl) {

        (void) handler(r->connection, NULL, &s);

        v->data = s.data;

        for (len = 0; v->data[len]; len++) { /* void */ }

        v->len = len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;

        return NGX_OK;
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v,
    uintptr_t data)
{
    ngx_ssl_variable_handler_pt  handler = (ngx_ssl_variable_handler_pt) data;

    ngx_str_t  s;

    if (r->connection->ssl) {

        if (handler(r->connection, r->pool, &s) != NGX_OK) {
            return NGX_ERROR;
        }

        v->len = s.len;
        v->data = s.data;

        if (v->len) {
            v->valid = 1;
            v->no_cacheable = 0;
            v->not_found = 0;

            return NGX_OK;
        }
    }

    v->not_found = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ssl_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ssl_vars; v->name.len; v++) {
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
ngx_http_ssl_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_ssl_srv_conf_t  *sscf;

    sscf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ssl_srv_conf_t));
    if (sscf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     sscf->protocols = 0;
     *     sscf->certificate = { 0, NULL };
     *     sscf->certificate_key = { 0, NULL };
     *     sscf->dhparam = { 0, NULL };
     *     sscf->ecdh_curve = { 0, NULL };
     *     sscf->client_certificate = { 0, NULL };
     *     sscf->trusted_certificate = { 0, NULL };
     *     sscf->crl = { 0, NULL };
     *     sscf->ciphers = { 0, NULL };
     *     sscf->shm_zone = NULL;
     *     sscf->stapling_file = { 0, NULL };
     *     sscf->stapling_responder = { 0, NULL };
     */

    sscf->enable = NGX_CONF_UNSET;
    sscf->prefer_server_ciphers = NGX_CONF_UNSET;
    sscf->verify = NGX_CONF_UNSET_UINT;
    sscf->verify_depth = NGX_CONF_UNSET_UINT;
    sscf->builtin_session_cache = NGX_CONF_UNSET;
    sscf->session_timeout = NGX_CONF_UNSET;
    sscf->stapling = NGX_CONF_UNSET;
    sscf->stapling_verify = NGX_CONF_UNSET;

    return sscf;
}


static char *
ngx_http_ssl_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ssl_srv_conf_t *prev = parent;
    ngx_http_ssl_srv_conf_t *conf = child;

    ngx_pool_cleanup_t  *cln;

    if (conf->enable == NGX_CONF_UNSET) {
        if (prev->enable == NGX_CONF_UNSET) {
            conf->enable = 0;

        } else {
            conf->enable = prev->enable;
            conf->file = prev->file;
            conf->line = prev->line;
        }
    }

    ngx_conf_merge_value(conf->session_timeout,
                         prev->session_timeout, 300);

    ngx_conf_merge_value(conf->prefer_server_ciphers,
                         prev->prefer_server_ciphers, 0);

    ngx_conf_merge_bitmask_value(conf->protocols, prev->protocols,
                         (NGX_CONF_BITMASK_SET|NGX_SSL_SSLv3|NGX_SSL_TLSv1
                          |NGX_SSL_TLSv1_1|NGX_SSL_TLSv1_2));

    ngx_conf_merge_uint_value(conf->verify, prev->verify, 0);
    ngx_conf_merge_uint_value(conf->verify_depth, prev->verify_depth, 1);

    ngx_conf_merge_str_value(conf->certificate, prev->certificate, "");
    ngx_conf_merge_str_value(conf->certificate_key, prev->certificate_key, "");

    ngx_conf_merge_str_value(conf->dhparam, prev->dhparam, "");

    ngx_conf_merge_str_value(conf->client_certificate, prev->client_certificate,
                         "");
    ngx_conf_merge_str_value(conf->trusted_certificate,
                         prev->trusted_certificate, "");
    ngx_conf_merge_str_value(conf->crl, prev->crl, "");

    ngx_conf_merge_str_value(conf->ecdh_curve, prev->ecdh_curve,
                         NGX_DEFAULT_ECDH_CURVE);

    ngx_conf_merge_str_value(conf->ciphers, prev->ciphers, NGX_DEFAULT_CIPHERS);

    ngx_conf_merge_value(conf->stapling, prev->stapling, 0);
    ngx_conf_merge_value(conf->stapling_verify, prev->stapling_verify, 0);
    ngx_conf_merge_str_value(conf->stapling_file, prev->stapling_file, "");
    ngx_conf_merge_str_value(conf->stapling_responder,
                         prev->stapling_responder, "");

    conf->ssl.log = cf->log;

    if (conf->enable) {

        if (conf->certificate.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

        if (conf->certificate_key.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined for "
                          "the \"ssl\" directive in %s:%ui",
                          conf->file, conf->line);
            return NGX_CONF_ERROR;
        }

    } else {

        if (conf->certificate.len == 0) {
            return NGX_CONF_OK;
        }

        if (conf->certificate_key.len == 0) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no \"ssl_certificate_key\" is defined "
                          "for certificate \"%V\"", &conf->certificate);
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_create(&conf->ssl, conf->protocols, conf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME

    if (SSL_CTX_set_tlsext_servername_callback(conf->ssl.ctx,
                                               ngx_http_ssl_servername)
        == 0)
    {
        ngx_log_error(NGX_LOG_WARN, cf->log, 0,
            "nginx was built with SNI support, however, now it is linked "
            "dynamically to an OpenSSL library which has no tlsext support, "
            "therefore SNI is not available");
    }

#endif

#ifdef TLSEXT_TYPE_next_proto_neg
    SSL_CTX_set_next_protos_advertised_cb(conf->ssl.ctx,
                                          ngx_http_ssl_npn_advertised, NULL);
#endif

#ifdef SSL_MODE_ASYNC_KEY_EX
    if (conf->key_ex.upstream.upstream != NULL) {
      SSL_CTX_set_mode(conf->ssl.ctx, SSL_MODE_ASYNC_KEY_EX);
      ngx_ssl_set_key_ex_cb(conf->ssl.ctx, ngx_http_ssl_key_ex);
    }
#endif

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NGX_CONF_ERROR;
    }

    cln->handler = ngx_ssl_cleanup_ctx;
    cln->data = &conf->ssl;

    if (ngx_ssl_certificate(cf, &conf->ssl, &conf->certificate,
                            &conf->certificate_key)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (SSL_CTX_set_cipher_list(conf->ssl.ctx,
                                (const char *) conf->ciphers.data)
        == 0)
    {
        ngx_ssl_error(NGX_LOG_EMERG, cf->log, 0,
                      "SSL_CTX_set_cipher_list(\"%V\") failed",
                      &conf->ciphers);
    }

    if (conf->verify) {

        if (conf->client_certificate.len == 0 && conf->verify != 3) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "no ssl_client_certificate for ssl_client_verify");
            return NGX_CONF_ERROR;
        }

        if (ngx_ssl_client_certificate(cf, &conf->ssl,
                                       &conf->client_certificate,
                                       conf->verify_depth)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_ssl_trusted_certificate(cf, &conf->ssl,
                                    &conf->trusted_certificate,
                                    conf->verify_depth)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_crl(cf, &conf->ssl, &conf->crl) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (conf->prefer_server_ciphers) {
        SSL_CTX_set_options(conf->ssl.ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    /* a temporary 512-bit RSA key is required for export versions of MSIE */
    SSL_CTX_set_tmp_rsa_callback(conf->ssl.ctx, ngx_ssl_rsa512_key_callback);

    if (ngx_ssl_dhparam(cf, &conf->ssl, &conf->dhparam) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    if (ngx_ssl_ecdh_curve(cf, &conf->ssl, &conf->ecdh_curve) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_value(conf->builtin_session_cache,
                         prev->builtin_session_cache, NGX_SSL_NONE_SCACHE);

    if (conf->shm_zone == NULL) {
        conf->shm_zone = prev->shm_zone;
    }

    if (ngx_ssl_session_cache(&conf->ssl, &ngx_http_ssl_sess_id_ctx,
                              conf->builtin_session_cache,
                              conf->shm_zone, conf->session_timeout)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    if (conf->stapling) {

        if (ngx_ssl_stapling(cf, &conf->ssl, &conf->stapling_file,
                             &conf->stapling_responder, conf->stapling_verify)
            != NGX_OK)
        {
            return NGX_CONF_ERROR;
        }

    }

    return NGX_CONF_OK;
}


static char *
ngx_http_ssl_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    char  *rv;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    sscf->file = cf->conf_file->file.name.data;
    sscf->line = cf->conf_file->line;

    return NGX_CONF_OK;
}


static char *
ngx_http_ssl_session_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_ssl_srv_conf_t *sscf = conf;

    size_t       len;
    ngx_str_t   *value, name, size;
    ngx_int_t    n;
    ngx_uint_t   i, j;

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {

        if (ngx_strcmp(value[i].data, "off") == 0) {
            sscf->builtin_session_cache = NGX_SSL_NO_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "none") == 0) {
            sscf->builtin_session_cache = NGX_SSL_NONE_SCACHE;
            continue;
        }

        if (ngx_strcmp(value[i].data, "builtin") == 0) {
            sscf->builtin_session_cache = NGX_SSL_DFLT_BUILTIN_SCACHE;
            continue;
        }

        if (value[i].len > sizeof("builtin:") - 1
            && ngx_strncmp(value[i].data, "builtin:", sizeof("builtin:") - 1)
               == 0)
        {
            n = ngx_atoi(value[i].data + sizeof("builtin:") - 1,
                         value[i].len - (sizeof("builtin:") - 1));

            if (n == NGX_ERROR) {
                goto invalid;
            }

            sscf->builtin_session_cache = n;

            continue;
        }

        if (value[i].len > sizeof("shared:") - 1
            && ngx_strncmp(value[i].data, "shared:", sizeof("shared:") - 1)
               == 0)
        {
            len = 0;

            for (j = sizeof("shared:") - 1; j < value[i].len; j++) {
                if (value[i].data[j] == ':') {
                    break;
                }

                len++;
            }

            if (len == 0) {
                goto invalid;
            }

            name.len = len;
            name.data = value[i].data + sizeof("shared:") - 1;

            size.len = value[i].len - j - 1;
            size.data = name.data + len + 1;

            n = ngx_parse_size(&size);

            if (n == NGX_ERROR) {
                goto invalid;
            }

            if (n < (ngx_int_t) (8 * ngx_pagesize)) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "session cache \"%V\" is too small",
                                   &value[i]);

                return NGX_CONF_ERROR;
            }

            sscf->shm_zone = ngx_shared_memory_add(cf, &name, n,
                                                   &ngx_http_ssl_module);
            if (sscf->shm_zone == NULL) {
                return NGX_CONF_ERROR;
            }

            sscf->shm_zone->init = ngx_ssl_session_cache_init;

            continue;
        }

        goto invalid;
    }

    if (sscf->shm_zone && sscf->builtin_session_cache == NGX_CONF_UNSET) {
        sscf->builtin_session_cache = NGX_SSL_NO_BUILTIN_SCACHE;
    }

    return NGX_CONF_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid session cache \"%V\"", &value[i]);

    return NGX_CONF_ERROR;
}


#ifdef SSL_MODE_ASYNC_KEY_EX
static char *
ngx_http_ssl_key_ex_upstream(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_ssl_srv_conf_t *sscf = conf;
    ngx_str_t *values;
    ngx_str_t upstream;
    ngx_int_t    rc, n;
    ngx_uint_t   i, j;
    ngx_http_upstream_main_conf_t  *umcf;
    ngx_http_upstream_srv_conf_t **uscfp;
    ngx_http_upstream_srv_conf_t *u;
    ngx_http_upstream_conf_t* uc;
    ngx_hash_init_t hash;
    ngx_url_t* url;

    static ngx_str_t  empty_headers[] = {
      ngx_null_string
    };

    if (cf->args->nelts != 2) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ssl_key_ex_upstream expects one argument");

        return NGX_CONF_ERROR;
    }

    values = cf->args->elts;
    upstream = values[1];

    /* Parse upstream string into schema://upstream/path */
    url = &sscf->key_ex.url;
    if (upstream.len >= 7 &&
        ngx_strncasecmp(upstream.data, (u_char*) "http://", 7) == 0) {
        sscf->key_ex.schema.data = (u_char*) "http://";
        sscf->key_ex.schema.len = 7;
        sscf->key_ex.ssl = 0;
        url->default_port = 80;
    } else if (upstream.len >= 8 &&
               ngx_strncasecmp(upstream.data, (u_char*) "https://", 8) == 0) {
        sscf->key_ex.schema.data = (u_char*) "https://";
        sscf->key_ex.schema.len = 8;
        sscf->key_ex.ssl = 1;
        url->default_port = 443;
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ssl_key_ex_upstream expects valid uri");

        return NGX_CONF_ERROR;
    }

    /* Slice off the rest of the path */
    url->url.len = upstream.len - sscf->key_ex.schema.len;
    url->url.data = upstream.data + sscf->key_ex.schema.len;
    url->uri_part = 1;
    url->no_resolve = 1;

    rc = ngx_parse_url(cf->pool, url);
    if (rc != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ssl_key_ex_upstream expects valid uri");
        return NGX_CONF_ERROR;
    }
    umcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_upstream_module);

    u = NULL;
    uscfp = umcf->upstreams.elts;
    for (i = 0; i < umcf->upstreams.nelts; i++) {
        if (uscfp[i]->host.len != url->host.len
            || ngx_strncasecmp(uscfp[i]->host.data,
                               url->host.data,
                               url->host.len) != 0) {
            continue;
        }

        u = uscfp[i];
        break;
    }

    if (u == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "ssl_key_ex_upstream: unknown upstream");
        return NGX_CONF_ERROR;
    }

    uc = &sscf->key_ex.upstream;
    uc->upstream = u;
    uc->store = 0;
    uc->store_access = 0600;
    uc->buffering = 1;
    uc->ignore_client_abort = 0;

    uc->local = NULL;

    uc->connect_timeout = 60000;
    uc->send_timeout = 60000;
    uc->read_timeout = 60000;

    uc->send_lowat = 0;
    uc->buffer_size = 1024;

    uc->busy_buffers_size_conf = NGX_CONF_UNSET_SIZE;
    uc->max_temp_file_size_conf = NGX_CONF_UNSET_SIZE;
    uc->temp_file_write_size_conf = NGX_CONF_UNSET_SIZE;

    uc->pass_request_headers = 0;
    uc->pass_request_body = 0;

#if (NGX_HTTP_CACHE)
    uc->cache = NGX_CONF_UNSET_PTR;
    uc->cache_min_uses = NGX_CONF_UNSET_UINT;
    uc->cache_bypass = NULL;
    uc->no_cache = NULL;
    uc->cache_valid = NULL;
    uc->cache_lock = NGX_CONF_UNSET;
    uc->cache_lock_timeout = NGX_CONF_UNSET_MSEC;
#endif

    uc->hide_headers = NGX_CONF_UNSET_PTR;
    uc->pass_headers = NGX_CONF_UNSET_PTR;

    hash.max_size = 512;
    hash.bucket_size = 1;
    hash.name = "ssl_headers_hash";

    if (ngx_http_upstream_hide_headers_hash(cf, uc, uc, empty_headers, &hash)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    uc->intercept_errors = 0;
#if (NGX_HTTP_SSL)
    uc->ssl_session_reuse = 1;
#endif

    /* "proxy_cyclic_temp_file" is disabled */
    uc->cyclic_temp_file = 0;

    ngx_str_set(&uc->module, "ssl");

    return NGX_OK;
}


ngx_int_t ngx_http_ssl_key_ex(ngx_ssl_conn_t *ssl_conn) {
    ngx_connection_t          *c;
    ngx_http_core_srv_conf_t  *cscf;
    ngx_http_ssl_srv_conf_t   *sscf;
    ngx_http_request_t        *r;
    ngx_http_upstream_t       *u;
    ngx_http_ssl_ke_ctx_t     *ctx;
    ngx_int_t                 err;

    c = ngx_ssl_get_connection(ssl_conn);

    /* Simulate a request, and pipe it to upstream */
    r = ngx_http_create_request(c);
    if (r == NULL) {
        return NGX_ERROR;
    }

    ngx_str_set(&r->uri, "<<ssl-key-ex>>");
    r->valid_location = 1;

    /* Do not proxy response to the connection */
    r->subrequest_in_memory = 1;
    r->simulated = 1;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);

    r->header_in = ngx_create_temp_buf(r->pool,
                                       cscf->client_header_buffer_size);
    if (r->header_in == NULL) {
        goto fatal;
    }

    err = ngx_http_upstream_create(r);
    if (err != NGX_OK) {
        goto fatal;
    }

    u = r->upstream;
    u->conf = &sscf->key_ex.upstream;

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if (ctx == NULL) {
        goto fatal;
    }

    ctx->ssl = ssl_conn;
    ngx_http_set_ctx(r, ctx, ngx_http_ssl_module);

    u->create_request = ngx_http_ssl_ke_create_request;
    u->reinit_request = ngx_http_ssl_ke_reinit_request;
    u->process_header = ngx_http_ssl_ke_process_status_line;
    u->abort_request = ngx_http_ssl_ke_abort_request;
    u->finalize_request = ngx_http_ssl_ke_finalize_request;

    /* Parse body */
    u->input_filter_init = ngx_http_ssl_ke_input_filter_init;
    u->input_filter = ngx_http_ssl_ke_input_filter;
    u->input_filter_ctx = r;

    c->data = r;

    c->sent = 0;
    c->destroyed = 0;

    ngx_http_upstream_init(r);

    return NGX_OK;

fatal:
    ngx_http_free_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
    return NGX_ERROR;
}


#define NGX_CSTR_BUF(b, str)                                                  \
    (b)->start = (u_char*) (str);                                             \
    (b)->pos = (b)->start;                                                    \
    (b)->end = (b)->start + sizeof((str)) - 1;                                \


#define NGX_STR_BUF(b, str)                                                   \
    (b)->start = (str)->data;                                                 \
    (b)->pos = (b)->start;                                                    \
    (b)->end = (b)->start + (str)->len;                                       \


ngx_int_t ngx_http_ssl_ke_create_request(ngx_http_request_t *r) {
    ngx_http_ssl_srv_conf_t* sscf;
    ngx_chain_t                  *cl;
    u_char *p;
    ngx_buf_t b[13];
    ngx_buf_t *buf;
    ngx_str_t base64, binary, sni, escaped_sni;
    ngx_http_ssl_ke_ctx_t *ctx;
    u_char body_len[32];
    ngx_int_t i, sz;

    sscf = ngx_http_get_module_srv_conf(r, ngx_http_ssl_module);
    ctx = ngx_http_get_module_ctx(r, ngx_http_ssl_module);

    sni.data = (u_char*) SSL_get_servername(ctx->ssl,
                                            TLSEXT_NAMETYPE_host_name);
    if (sni.data == NULL) {
        sni.len = 0;
        escaped_sni.len = 0;
        escaped_sni.data = NULL;
    } else {
        sni.len = ngx_strlen(sni.data);
        escaped_sni.len = sni.len + 2 * ngx_escape_uri(NULL,
                                                       sni.data,
                                                       sni.len,
                                                       NGX_ESCAPE_URI_COMPONENT);
        escaped_sni.data = ngx_palloc(r->pool, escaped_sni.len);
        if (escaped_sni.data == NULL) {
            return NGX_ERROR;
        }

        ngx_escape_uri(escaped_sni.data,
                       sni.data,
                       sni.len,
                       NGX_ESCAPE_URI_COMPONENT);
    }

    ngx_memset(b, 0, sizeof(b));
    NGX_CSTR_BUF(&b[0], "POST ");
    NGX_STR_BUF(&b[1], &sscf->key_ex.url.uri);
    NGX_CSTR_BUF(&b[2], "/");
    NGX_STR_BUF(&b[3], &escaped_sni);
    NGX_CSTR_BUF(&b[4], " HTTP/1.1\r\nHost: ");
    NGX_STR_BUF(&b[5], &sscf->key_ex.url.host);

    if (SSL_want_rsa_decrypt(ctx->ssl)) {
        NGX_CSTR_BUF(&b[6], "");
    } else if (SSL_get_key_ex_type(ctx->ssl) == EVP_PKEY_RSA) {
        NGX_CSTR_BUF(&b[6], "\r\nX-Key: rsa");
    } else {
        NGX_CSTR_BUF(&b[6], "\r\nX-Key: ecdsa");
    }

    if (SSL_want_sign(ctx->ssl)) {
        ngx_str_t md;

        NGX_CSTR_BUF(&b[7], "\r\nX-Type: sign\r\nX-MD: ");
        md.data = (u_char*) OBJ_nid2sn(SSL_get_key_ex_md(ctx->ssl));
        md.len = ngx_strlen(md.data);
        NGX_STR_BUF(&b[8], &md);
    } else {
        NGX_CSTR_BUF(&b[7], "\r\nX-Type: decrypt");
        NGX_CSTR_BUF(&b[8], "");
    }

    NGX_CSTR_BUF(&b[9], "\r\nContent-Length: ");


    binary.data = (u_char*) SSL_get_key_ex_data(ctx->ssl);
    binary.len = SSL_get_key_ex_len(ctx->ssl);

    base64.len = ngx_base64_encoded_length(binary.len);
    base64.data = ngx_palloc(r->pool, base64.len);
    if (base64.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64(&base64, &binary);

    NGX_STR_BUF(&b[11], &base64);

    b[10].start = body_len;
    b[10].pos = b[10].start;
    b[10].end = ngx_snprintf(body_len,
                             sizeof(body_len),
                             "%d\r\n\r\n",
                             base64.len);

    /* Get total size of all buffers */
    sz = 0;
    for (i = 0; i < 13; i++) {
        sz += b[i].end - b[i].start;
    }

    buf = ngx_create_temp_buf(r->pool, sz);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    /* Copy all data into one buffer */
    for (p = buf->start, i = 0; i < 13; i++) {
        ngx_memcpy(p, b[i].start, b[i].end - b[i].start);
        p += b[i].end - b[i].start;
    }
    buf->last = p;

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = buf;
    cl->next = NULL;
    r->upstream->request_bufs = cl;

    return NGX_OK;
}


#undef NGX_CSTR_BUF
#undef NGX_STR_BUF


ngx_int_t ngx_http_ssl_ke_process_status_line(ngx_http_request_t *r) {
    ngx_int_t rc;
    ngx_http_status_t st;
    ngx_http_upstream_t* u;

    u = r->upstream;
    memset(&st, 0, sizeof(st));

    rc = ngx_http_parse_status_line(r, &u->buffer, &st);
    if (rc != NGX_OK) {
        return rc;
    }

    /* Request failed, or has no body */
    if (st.code < 200 || st.code >= 300) {
        return NGX_ERROR;
    }

    u->headers_in.status_n = st.code;
    u->process_header = ngx_http_ssl_ke_process_header;

    return u->process_header(r);
}


ngx_int_t ngx_http_ssl_ke_process_header(ngx_http_request_t *r) {
    int rc;
    ngx_http_upstream_t* u;
    ngx_http_upstream_main_conf_t  *umcf;
    ngx_table_elt_t* h;
    ngx_http_upstream_header_t     *hh;

    u = r->upstream;
    umcf = ngx_http_get_module_main_conf(r, ngx_http_upstream_module);

    for (;;) {
        rc = ngx_http_parse_header_line(r, &u->buffer, 1);
        if (rc == NGX_AGAIN) {
            break;
        }

        if (rc == NGX_HTTP_PARSE_HEADER_DONE) {
            if (u->headers_in.chunked) {
                u->headers_in.content_length_n = -1;
            }

            return NGX_OK;
        }

        if (rc != NGX_OK) {
            break;
        }

        h = ngx_list_push(&u->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }

        /* Store known headers on-request */
        h->hash = r->header_hash;

        h->key.len = r->header_name_end - r->header_name_start;
        h->value.len = r->header_end - r->header_start;

        h->key.data = ngx_pnalloc(r->pool, h->key.len + 1 +
                                           h->value.len + 1);
        ngx_memcpy(h->key.data, r->lowcase_header, h->key.len);
        h->key.data[h->key.len] = 0;

        h->value.data = h->key.data + h->key.len + 1;
        ngx_memcpy(h->value.data, r->header_start, h->value.len);
        h->value.data[h->value.len] = 0;

        h->lowcase_key = h->key.data;

        hh = ngx_hash_find(&umcf->headers_in_hash,
                           h->hash,
                           h->key.data,
                           h->key.len);

        if (hh && hh->handler(r, h, hh->offset) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    return rc;
}


ngx_int_t ngx_http_ssl_ke_reinit_request(ngx_http_request_t *r) {
    return NGX_ERROR;
}


void ngx_http_ssl_ke_abort_request(ngx_http_request_t *r) {
}


void ngx_http_ssl_ke_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_http_upstream_t* u;
    ngx_http_ssl_ke_ctx_t* ctx;
    ngx_connection_t* c;
    ngx_buf_t* buf;
    ngx_str_t data, src;
    ngx_chain_t* cl;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssl_module);

    /* Error */
    if (rc != NGX_OK) {
        goto fatal;
    }

    u = r->upstream;

    /* No body */
    if (ctx->body.start == NULL) {
        goto fatal;
    }

    /* Concat all body chunks into one buffer */
    buf = ngx_create_temp_buf(r->pool, ctx->body.len);
    if (buf == NULL) {
        goto fatal;
    }

    buf->pos = buf->start;
    buf->last = buf->start;
    for (cl = ctx->body.start; cl != NULL; cl = cl->next) {
        ngx_memcpy(buf->last, cl->buf->pos, cl->buf->last - cl->buf->pos);
        buf->last += cl->buf->last - cl->buf->pos;
    }

    /* Decode base64 */
    src.data = buf->pos;
    src.len = buf->last - buf->pos;
    data.len = ngx_base64_decoded_length(src.len);
    data.data = ngx_palloc(r->pool, data.len);

    if (data.data == NULL) {
        goto fatal;
    }

    rc = ngx_decode_base64(&data, &src);
    if (rc != NGX_OK) {
        goto fatal;
    }

    rc = ngx_ssl_supply_key_ex(ngx_ssl_get_connection(ctx->ssl),
                               data.data,
                               data.len);
    if (rc != NGX_OK && rc != NGX_AGAIN) {
        goto fatal;
    }

    return;

fatal:
    ngx_http_close_connection(ngx_ssl_get_connection(ctx->ssl));
    /* Kill parent connection */
    return;
}


ngx_int_t ngx_http_ssl_ke_input_filter_init(void *data) {
    return NGX_OK;
}


static ngx_int_t ngx_http_ssl_ke_push_chunk(ngx_http_request_t* r,
                                            ngx_buf_t* buf,
                                            ssize_t bytes) {
    ngx_chain_t* cl;
    ngx_buf_t* b;
    ngx_http_upstream_t* u;
    ngx_http_ssl_ke_ctx_t* ctx;

    u = r->upstream;
    ctx = ngx_http_get_module_ctx(r, ngx_http_ssl_module);

    cl = ngx_chain_get_free_buf(r->pool, &u->free_bufs);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    /* Append chunk */
    if (ctx->body.end != NULL) {
        ctx->body.end->next = cl;
    } else {
        ctx->body.start = cl;
    }
    ctx->body.end = cl;

    b = cl->buf;

    b->flush = 1;
    b->memory = 1;

    b->pos = buf->pos;
    b->tag = u->output.tag;

    if (buf->pos + bytes <= buf->end) {
        ctx->chunked.size = 0;
        buf->pos += bytes;
        b->last = buf->pos;
        ctx->body.len += bytes;
    } else {
        ctx->chunked.size -= buf->end - buf->pos;
        ctx->body.len += buf->end - buf->pos;
        buf->pos = buf->end;
        b->last = buf->last;
    }

    return NGX_OK;
}


ngx_int_t ngx_http_ssl_ke_input_filter(void *data, ssize_t bytes) {
    ngx_int_t rc;
    ngx_http_request_t        *r;
    ngx_http_upstream_t       *u;
    ngx_http_ssl_ke_ctx_t     *ctx;
    ngx_buf_t* buf;

    r = data;
    u = r->upstream;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ssl_module);

    /* Move forward */
    buf = &u->buffer;
    buf->pos = buf->last;
    buf->last += bytes;

    /* Content-Length */
    if (u->headers_in.content_length_n != -1) {
        rc = ngx_http_ssl_ke_push_chunk(r, buf, bytes);
        if (rc != NGX_OK) {
          return rc;
        }

        u->length -= bytes;
        if (u->length == 0) {
            u->keepalive = !u->headers_in.connection_close;
        }
        return NGX_OK;
    }

    /* Chunked */
    for (;;) {
        rc = ngx_http_parse_chunked(r, buf, &ctx->chunked);
        if (rc == NGX_OK) {
            rc = ngx_http_ssl_ke_push_chunk(r, buf, ctx->chunked.size);
            if (rc != NGX_OK) {
                return rc;
            }
        } else if (rc == NGX_DONE) {
            /* Just to make finalize happen */
            u->length = 0;
            u->keepalive = !u->headers_in.connection_close;
            break;
        } else if (rc == NGX_AGAIN) {
            break;
        } else {
            return rc;
        }
    }

    return NGX_OK;
}
#endif


static ngx_int_t
ngx_http_ssl_init(ngx_conf_t *cf)
{
    ngx_uint_t                   s;
    ngx_http_ssl_srv_conf_t     *sscf;
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_core_srv_conf_t   **cscfp;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {

        sscf = cscfp[s]->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (sscf->ssl.ctx == NULL || !sscf->stapling) {
            continue;
        }

        clcf = cscfp[s]->ctx->loc_conf[ngx_http_core_module.ctx_index];

        if (ngx_ssl_stapling_resolver(cf, &sscf->ssl, clcf->resolver,
                                      clcf->resolver_timeout)
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
