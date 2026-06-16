/*
 *
 * Copyright 2026
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <ex_sss_boot.h>
#include <fsl_sss_se05x_policy.h>
#include <fsl_sss_se05x_types.h>
#include <nxLog.h>
#include <nxLog_App.h>
#include <se05x_APDU_apis.h>
#include <sm_types.h>
#include <stdio.h>
#include <string.h>

#define SE052F_RUNTIME_AUTH_OBJ_ID 0x60000000u

/* Public half of EX_SSS_AUTH_SE05X_KEY_HOST_ECDSA_KEY, used until the real
 * TA/HWKM-derived host authentication public key is supplied. */
static const uint8_t kSe052fDemoHostEcdsaPublicKey[] = {
    0x04, 0x3C, 0x9E, 0x47, 0xED, 0xF0, 0x51, 0xA3, 0x58, 0x9F, 0x67, 0x30, 0x2D, 0x22, 0x56, 0x7C,
    0x2E, 0x17, 0x22, 0x9E, 0x88, 0x83, 0x33, 0x8E, 0xC3, 0xB7, 0xD5, 0x27, 0xF9, 0xEE, 0x71, 0xD0,
    0xA8, 0x1A, 0xAE, 0x7F, 0xE2, 0x1C, 0xAA, 0x66, 0x77, 0x78, 0x3A, 0xA8, 0x8D, 0xA6, 0xD6, 0xA8,
    0xAD, 0x5E, 0xC5, 0x3B, 0x10, 0xBC, 0x0B, 0x11, 0x09, 0x44, 0x82, 0xF0, 0x4D, 0x24, 0xB5, 0xBE,
    0xC4,
};

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

static smStatus_t create_runtime_ec_auth_object_if_needed(sss_se05x_session_t *se05x_session)
{
    sss_policy_u read_policy;
    sss_policy_t policy_set;
    uint8_t policy_buffer[MAX_POLICY_BUFFER_SIZE] = {0};
    size_t policy_buffer_len                      = 0;
    Se05xPolicy_t se05x_policy;
    SE05x_Result_t exists = kSE05x_Result_NA;
    sss_status_t sss_status;
    smStatus_t sm_status;

    sm_status = Se05x_API_CheckObjectExists(&se05x_session->s_ctx, SE052F_RUNTIME_AUTH_OBJ_ID, &exists);
    if (sm_status != SM_OK) {
        LOG_W("Se05x_API_CheckObjectExists(0x%08X) failed: 0x%04X", SE052F_RUNTIME_AUTH_OBJ_ID, sm_status);
        return sm_status;
    }

    if (exists == kSE05x_Result_SUCCESS) {
        printf("SE052F runtime EC auth object 0x%08X already exists\n", SE052F_RUNTIME_AUTH_OBJ_ID);
        return SM_OK;
    }

    memset(&read_policy, 0, sizeof(read_policy));
    memset(&policy_set, 0, sizeof(policy_set));

    read_policy.type                   = KPolicy_Common;
    read_policy.auth_obj_id            = 0;
    read_policy.policy.common.can_Read = 1;

    policy_set.policies[0] = &read_policy;
    policy_set.nPolicies   = 1;

    sss_status = sss_se05x_create_object_policy_buffer(&policy_set, policy_buffer, &policy_buffer_len);
    if (sss_status != kStatus_SSS_Success) {
        LOG_W("sss_se05x_create_object_policy_buffer failed: 0x%04X", sss_status);
        return SM_NOT_OK;
    }

    se05x_policy.value     = policy_buffer;
    se05x_policy.value_len = policy_buffer_len;

    sm_status = Se05x_API_WriteECKey(&se05x_session->s_ctx,
        &se05x_policy,
        SE05x_MaxAttemps_UNLIMITED,
        SE052F_RUNTIME_AUTH_OBJ_ID,
        kSE05x_ECCurve_NIST_P256,
        NULL,
        0,
        kSe052fDemoHostEcdsaPublicKey,
        sizeof(kSe052fDemoHostEcdsaPublicKey),
        kSE05x_INS_AUTH_OBJECT,
        kSE05x_KeyPart_Public);
    if (sm_status != SM_OK) {
        LOG_W("Se05x_API_WriteECKey auth object 0x%08X failed: 0x%04X", SE052F_RUNTIME_AUTH_OBJ_ID, sm_status);
        return sm_status;
    }

    printf("Created SE052F runtime EC auth object 0x%08X\n", SE052F_RUNTIME_AUTH_OBJ_ID);
    return SM_OK;
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
    int runtime_auth_object_ok = 0;

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

    sm_status = create_runtime_ec_auth_object_if_needed(se05x_session);
    if (sm_status == SM_OK) {
        runtime_auth_object_ok = 1;
    }
    else {
        LOG_W("Runtime EC auth object provisioning failed: 0x%04X", sm_status);
    }

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
    ret = runtime_auth_object_ok ? 0 : 1;

cleanup:
    ex_sss_session_close(&boot_ctx);
    nLog_DeInit();
    return ret;
}
