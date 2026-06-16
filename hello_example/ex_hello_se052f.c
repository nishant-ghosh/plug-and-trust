/*
 *
 * Copyright 2026
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_types.h>
#include <nxLog.h>
#include <nxLog_App.h>
#include <se05x_APDU_apis.h>
#include <sm_types.h>
#include <stdio.h>
#include <string.h>

static void print_hex(const char *label, const uint8_t *data, size_t data_len)
{
    size_t i = 0;

    printf("%s", label);
    for (i = 0; i < data_len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) < data_len) {
            printf(" ");
        }
    }
    printf("\n");
}

static void print_auth_mode(void)
{
#if SSS_HAVE_SE05X_AUTH_PLATFSCP03
    printf("SE05x auth mode:      PlatformSCP03 with compiled-in default key set\n");
#elif SSS_HAVE_SE05X_AUTH_NONE
    printf("SE05x auth mode:      Plain\n");
#else
    printf("SE05x auth mode:      Other configured authentication mode\n");
#endif
}

int main(int argc, const char *argv[])
{
    ex_sss_boot_ctx_t boot_ctx;
    char *port_name          = NULL;
    int ret                  = 1;
    sss_status_t sss_status  = kStatus_SSS_Fail;
    smStatus_t sm_status     = SM_NOT_OK;
    uint8_t version[32]      = {0};
    size_t version_len       = sizeof(version);
    uint8_t state[64]        = {0};
    size_t state_len         = sizeof(state);
    uint8_t random_data[16]  = {0};
    size_t random_data_len   = sizeof(random_data);
    sss_se05x_session_t *se05x_session = NULL;
    int apdu_probe_ok        = 0;

    memset(&boot_ctx, 0, sizeof(boot_ctx));

    if (nLog_Init() != 0) {
        LOG_E("Log initialization failed");
    }

    sss_status = ex_sss_boot_connectstring(argc, argv, &port_name);
    if (sss_status != kStatus_SSS_Success) {
        LOG_E("ex_sss_boot_connectstring failed");
        goto cleanup;
    }

    sss_status = ex_sss_boot_open(&boot_ctx, port_name);
    if (sss_status != kStatus_SSS_Success) {
        LOG_E("ex_sss_boot_open failed");
        goto cleanup;
    }
    print_auth_mode();

    se05x_session = (sss_se05x_session_t *)&boot_ctx.session;

    sm_status = Se05x_API_GetVersion(&se05x_session->s_ctx, version, &version_len);
    if (sm_status == SM_OK) {
        print_hex("SE05x applet version: ", version, version_len);
        apdu_probe_ok = 1;
    }
    else {
        LOG_W("Se05x_API_GetVersion failed: 0x%04X", sm_status);
    }

    sm_status = Se05x_API_ReadState(&se05x_session->s_ctx, state, &state_len);
    if (sm_status == SM_OK) {
        print_hex("SE05x state:          ", state, state_len);
        apdu_probe_ok = 1;
    }
    else {
        LOG_W("Se05x_API_ReadState failed: 0x%04X", sm_status);
    }

    sm_status = Se05x_API_GetRandom(&se05x_session->s_ctx, sizeof(random_data), random_data, &random_data_len);
    if (sm_status == SM_OK) {
        print_hex("SE05x random bytes:   ", random_data, random_data_len);
        apdu_probe_ok = 1;
    }
    else {
        LOG_W("Se05x_API_GetRandom failed: 0x%04X", sm_status);
    }

    if (apdu_probe_ok) {
        printf("SE052F hello test passed; at least one non-destructive APDU succeeded\n");
    }
    else {
        printf("SE052F session-open hello test passed; non-destructive APDU probes were rejected\n");
    }
    ret = 0;

cleanup:
    ex_sss_session_close(&boot_ctx);
    nLog_DeInit();
    return ret;
}
