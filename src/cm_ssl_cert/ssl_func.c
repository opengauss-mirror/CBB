/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * CBB is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * ssl_func.c
 *
 *
 * IDENTIFICATION
 *    src/cm_certification/ssl_func.c
 *
 * -------------------------------------------------------------------------
 */
#include <float.h>
#include <math.h>
#include <unistd.h>
#include "cm_ip.h"
#include "cm_memory.h"
#include "cm_spinlock.h"
#include "cs_tcp.h"
#include "cm_date_to_text.h"
#include "cm_defs.h"
#include "cm_system.h"
#include "cs_ssl.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "ssl_metadata.h"
#include "ssl_func.h"

ssl_instance_t g_ser_ssl = {0};

int chk_ssl_cert_expire(ssl_instance_t *ssl_inst, cert_param_t ca_type)
{
    cert_param_value_t cert_notify;
    CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_CLI_SSL_CERT_NOTIFY_TIME, &cert_notify));
    int32 cert_notify_time = (ca_type == CERT_PARAM_SER_SSL_CA) ? (int32)cert_notify.ser_ssl_cert_notify_time : \
        (int32)cert_notify.cli_ssl_cert_notify_time;
    ssl_ca_cert_expire(ssl_inst->ssl_fd, cert_notify_time);
    return CM_SUCCESS;
}

int chk_ssl_crl_expire(ssl_instance_t *ssl_inst, cert_param_t ca_type)
{
    cert_param_value_t crl_notify;
    CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_CLI_SSL_CERT_NOTIFY_TIME, &crl_notify));
    int32 crl_notify_time = (ca_type == CERT_PARAM_SER_SSL_CA) ? (int32)crl_notify.ser_ssl_cert_notify_time : \
        (int32)crl_notify.cli_ssl_cert_notify_time;
    (void)ssl_crl_expire(ssl_inst->ssl_fd, (int32)crl_notify_time);
    return CM_SUCCESS;
}

int chk_ssl_cert_revoke(ssl_instance_t *ssl_inst, const char *cert_file, const char *ca_file, const char *crl_file)
{
    if (access(crl_file, F_OK) == -1) {
        return CM_SUCCESS;
    }

    FILE *cert_fd = fopen(cert_file, "r");
    X509 *cert = PEM_read_X509(cert_fd, NULL, NULL, NULL);
    fclose(cert_fd);

    FILE *ca_fd = fopen(ca_file, "r");
    X509 *ca = PEM_read_X509(ca_fd, NULL, NULL, NULL);
    fclose(ca_fd);

    FILE *crl_fd = fopen(crl_file, "rb");
    X509_CRL *crl = PEM_read_X509_CRL(crl_fd, NULL, NULL, NULL);
    fclose(crl_fd);

    X509_STORE *store = X509_STORE_new();
    X509_STORE_add_cert(store, cert);
    X509_STORE_add_cert(store, ca);
    X509_STORE_add_crl(store, crl);
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    X509_STORE_CTX_set_flags(ctx, X509_V_FLAG_CRL_CHECK);

    int ret = X509_verify_cert(ctx);
    if (ret <= 0) {
        int err = X509_STORE_CTX_get_error(ctx);
        if (err == X509_V_ERR_CERT_REVOKED) {
            LOG_RUN_ERR("Cert has been revoked.");
        } else {
            LOG_RUN_ERR("Failed to verify certs, errcode: %d (%s)\n", err, X509_verify_cert_error_string(err));
        }
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(cert);
        X509_free(ca);
        X509_CRL_free(crl);
        return CM_ERROR;
    } else {
        LOG_RUN_INF("Certs are valied");
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    X509_free(ca);
    X509_CRL_free(crl);

    return CM_SUCCESS;
}

static status_t ser_create_ssl_fd(ssl_config_t *ssl_cfg, ssl_instance_t *ssl_inst)
{
    char plain[CM_PASSWD_MAX_LEN + 1] = {0};

    // create acceptor fd
    ssl_inst->ssl_fd = cs_ssl_create_acceptor_fd(ssl_cfg);
    if (ssl_inst->ssl_fd == NULL) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("create server ssl acceptor context failed");
        return CM_ERROR;
    }

    // check cert expire
    if (chk_ssl_cert_expire(ssl_inst, CERT_PARAM_SER_SSL_CA) != CM_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("check server ssl cert failed");
        return CM_ERROR;
    }

    if (chk_ssl_crl_expire(ssl_inst, CERT_PARAM_SER_SSL_CA) != CM_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("check server ssl cert failed");
        return CM_ERROR;
    }

    if (chk_ssl_cert_revoke(ssl_inst, ssl_cfg->cert_file, ssl_cfg->ca_file, ssl_cfg->crl_file) != CM_SUCCESS) {
        LOG_RUN_ERR("check server ssl crl failed");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static status_t cli_create_ssl_fd(ssl_config_t *ssl_cfg, ssl_instance_t *ssl_inst)
{
    char plain[CM_PASSWD_MAX_LEN + 1] = {0};

    // create connector fd
    ssl_inst->ssl_fd = cs_ssl_create_connector_fd(ssl_cfg);
    MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
    if (ssl_inst->ssl_fd == NULL) {
        LOG_RUN_ERR("[mes] create ssl connector context failed");
        return CM_ERROR;
    }

    // check cert expire
    if (chk_ssl_cert_expire(ssl_inst, CERT_PARAM_CLI_SSL_CA) != CM_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("[mes] check ssl cert failed");
        return CM_ERROR;
    }

    if (chk_ssl_crl_expire(ssl_inst, CERT_PARAM_CLI_SSL_CA) != CM_SUCCESS) {
        MEMS_RETURN_IFERR(memset_s(plain, sizeof(plain), 0, sizeof(plain)));
        LOG_RUN_ERR("[mes] check ssl cert failed");
        return CM_ERROR;
    }

    if (chk_ssl_cert_revoke(ssl_inst, ssl_cfg->cert_file, ssl_cfg->ca_file, ssl_cfg->crl_file) != CM_SUCCESS) {
        LOG_RUN_ERR("check server ssl crl failed");
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

status_t cert_init_ssl(ssl_instance_t *ssl_inst, cert_param_t ca_type)
{
    ssl_config_t ssl_cfg = {0};
    cert_param_value_t ca;
    cert_param_value_t key;
    cert_param_value_t cert;
    cert_param_value_t crl;

    // Required parameters
    if (ca_type == CERT_PARAM_SER_SSL_CA) {
        CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_SER_SSL_CA, &ca));
        ssl_cfg.ca_file = ca.ser_ssl_ca;
        CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_SER_SSL_KEY, &key));
        ssl_cfg.key_file = key.ser_ssl_key;
        CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_SER_SSL_CERT, &cert));
        ssl_cfg.cert_file = cert.ser_ssl_cert;
        CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_SER_SSL_CRL, &crl));
        ssl_cfg.crl_file = crl.ser_ssl_crl;
    } else {
        CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_CLI_SSL_CA, &ca));
        ssl_cfg.ca_file = ca.cli_ssl_ca;
        CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_CLI_SSL_KEY, &key));
        ssl_cfg.key_file = key.cli_ssl_key;
        CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_CLI_SSL_CERT, &cert));
        ssl_cfg.cert_file = cert.cli_ssl_cert;
        CM_RETURN_IFERR(ssl_md_get_param(CERT_PARAM_CLI_SSL_CRL, &crl));
        ssl_cfg.crl_file = crl.cli_ssl_crl;
    }

    ssl_cfg.verify_peer = CM_TRUE;

    if (CM_IS_EMPTY_STR(ssl_cfg.cert_file) || CM_IS_EMPTY_STR(ssl_cfg.key_file) || CM_IS_EMPTY_STR(ssl_cfg.ca_file)) {
        LOG_RUN_WAR("[ssl] SSL disabled: certificate file or private key file or CA certificate is not available.");
        LOG_ALARM(WARN_SSL_DIASBLED, "}");
        return CM_SUCCESS;
    }

    /* Require no public access to key file */
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.ca_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.key_file));
    CM_RETURN_IFERR(cs_ssl_verify_file_stat(ssl_cfg.cert_file));
    // create fd
    status_t status;
    if (ca_type == CERT_PARAM_SER_SSL_CA) {
        status = ser_create_ssl_fd(&ssl_cfg, ssl_inst);
    } else {
        status = cli_create_ssl_fd(&ssl_cfg, ssl_inst);
    }
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

static void cert_deinit_ssl(ssl_instance_t *ssl_inst)
{
    if (ssl_inst->ssl_fd != NULL) {
        cs_ssl_free_context(ssl_inst->ssl_fd);
        ssl_inst->ssl_fd = NULL;
    }
}

status_t cli_init_ssl(ssl_instance_t *ssl_inst)
{
    int ret;
    ret = cert_init_ssl(ssl_inst, CERT_PARAM_CLI_SSL_CA);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("Failed to init client ssl.");
        cert_deinit_ssl(ssl_inst);
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

status_t cli_ssl_connect(ssl_instance_t *ssl_inst, cs_pipe_t *pipe)
{
    if (cs_ssl_connect(ssl_inst->ssl_fd, pipe) != CM_SUCCESS) {
        cs_disconnect(pipe);
        LOG_RUN_ERR("client ssl certification connect failed");
        return CM_ERROR;
    }
    return CM_SUCCESS;
}

void cli_ssl_uninit(ssl_instance_t *ssl_inst)
{
    LOG_RUN_INF("[ssl] ssl_uninit start");
    cert_deinit_ssl(ssl_inst);

    LOG_RUN_INF("[ssl] ser_ssl_uninit success");
    return;
}

status_t ser_cert_accept(cs_pipe_t *pipe)
{
    LOG_RUN_INF_INHIBIT(LOG_INHIBIT_LEVEL4, "[ssl] server ssl accept: start server_ssl_accept...");
    if (cs_ssl_accept(g_ser_ssl.ssl_fd, pipe) != CM_SUCCESS) {
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

void ser_ssl_uninit(void)
{
    LOG_RUN_INF("[ssl] ssl_uninit start");
    cert_deinit_ssl(&g_ser_ssl);

    LOG_RUN_INF("[ssl] ser_ssl_uninit success");
    return;
}

status_t ser_init_ssl(socket_t sock)
{
    int ret;

    do {
        ret = (int)cert_init_ssl(&g_ser_ssl, CERT_PARAM_SER_SSL_CA);
        if (ret != CM_SUCCESS) {
            break;
        }
    } while (0);

    if (ret != CM_SUCCESS) {
        ser_ssl_uninit();
        return ret;
    }

    LOG_RUN_INF("[mes] mes_init success.");
    return ret;
}