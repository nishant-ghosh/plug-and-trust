/*
 *
 * Copyright 2026
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <ex_sss_boot.h>
#include <ex_sss_auth.h>
#include <fsl_sss_se05x_policy.h>
#include <fsl_sss_se05x_types.h>
#include <nxLog.h>
#include <nxLog_App.h>
#include <se05x_APDU_apis.h>
#include <sm_types.h>
#include <stdio.h>
#include <string.h>

#define SE052F_RUNTIME_AUTH_OBJ_ID 0x60000000u
#define SE052F_ATTESTATION_KEY_ID 0x60000001u
#define SE052F_SIGNING_KEY_ID 0x60000002u
#define SE052F_APPLET_SCP_AUTH_OBJ_ID SE052F_RUNTIME_AUTH_OBJ_ID

/* Demo Plug & Trust host EC key pair. Replace this with the TA/HWKM-derived
 * host key before using ECKey applet-SCP outside bring-up. */
static uint8_t kSe052fDemoHostEcdsaKeyPair[] = EX_SSS_AUTH_SE05X_KEY_HOST_ECDSA_KEY;

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

static smStatus_t create_bound_ec_key_if_needed(
    sss_se05x_session_t *se05x_session, uint32_t object_id, const char *label, int allow_attest, int allow_sign)
{
    sss_policy_u asym_policy;
    sss_policy_u common_policy;
    sss_policy_t policy_set;
    uint8_t policy_buffer[MAX_POLICY_BUFFER_SIZE] = {0};
    size_t policy_buffer_len                      = 0;
    Se05xPolicy_t se05x_policy;
    SE05x_Result_t exists = kSE05x_Result_NA;
    sss_status_t sss_status;
    smStatus_t sm_status;

    sm_status = Se05x_API_CheckObjectExists(&se05x_session->s_ctx, object_id, &exists);
    if (sm_status != SM_OK) {
        LOG_W("Se05x_API_CheckObjectExists(%s 0x%08X) failed: 0x%04X", label, object_id, sm_status);
        return sm_status;
    }

    if (exists == kSE05x_Result_SUCCESS) {
        printf("SE052F %s key 0x%08X already exists\n", label, object_id);
        return SM_OK;
    }

    memset(&asym_policy, 0, sizeof(asym_policy));
    memset(&common_policy, 0, sizeof(common_policy));
    memset(&policy_set, 0, sizeof(policy_set));

    asym_policy.type                      = KPolicy_Asym_Key;
    asym_policy.auth_obj_id               = SE052F_RUNTIME_AUTH_OBJ_ID;
    asym_policy.policy.asymmkey.can_Attest = allow_attest ? 1 : 0;
    asym_policy.policy.asymmkey.can_Sign   = allow_sign ? 1 : 0;

    common_policy.type                     = KPolicy_Common;
    common_policy.auth_obj_id              = SE052F_RUNTIME_AUTH_OBJ_ID;
    common_policy.policy.common.can_Read   = 1;
    common_policy.policy.common.can_Delete = 1;
    common_policy.policy.common.req_Sm     = 1;

    policy_set.policies[0] = &asym_policy;
    policy_set.policies[1] = &common_policy;
    policy_set.nPolicies   = 2;

    sss_status = sss_se05x_create_object_policy_buffer(&policy_set, policy_buffer, &policy_buffer_len);
    if (sss_status != kStatus_SSS_Success) {
        LOG_W("sss_se05x_create_object_policy_buffer(%s) failed: 0x%04X", label, sss_status);
        return SM_NOT_OK;
    }

    se05x_policy.value     = policy_buffer;
    se05x_policy.value_len = policy_buffer_len;

    sm_status = Se05x_API_WriteECKey(&se05x_session->s_ctx,
        &se05x_policy,
        SE05x_MaxAttemps_NA,
        object_id,
        kSE05x_ECCurve_NIST_P256,
        NULL,
        0,
        NULL,
        0,
        kSE05x_INS_NA,
        kSE05x_KeyPart_Pair);
    if (sm_status != SM_OK) {
        LOG_W("Se05x_API_WriteECKey %s key 0x%08X failed: 0x%04X", label, object_id, sm_status);
        return sm_status;
    }

    printf("Created SE052F %s key 0x%08X bound to auth object 0x%08X\n", label, object_id, SE052F_RUNTIME_AUTH_OBJ_ID);
    return SM_OK;
}

static smStatus_t create_bound_secure_key_objects_if_needed(sss_se05x_session_t *se05x_session)
{
    smStatus_t sm_status = SM_NOT_OK;

    sm_status = create_bound_ec_key_if_needed(se05x_session, SE052F_ATTESTATION_KEY_ID, "attestation", 1, 0);
    if (sm_status != SM_OK) {
        return sm_status;
    }

    return create_bound_ec_key_if_needed(se05x_session, SE052F_SIGNING_KEY_ID, "signing", 0, 1);
}

static void free_applet_scp_auth_context(ex_SE05x_authCtx_t *applet_auth_ctx)
{
#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_key_object_free(&applet_auth_ctx->eckey.ex_static.HostEcdsaObj);
    sss_key_object_free(&applet_auth_ctx->eckey.ex_static.HostEcKeypair);
    sss_key_object_free(&applet_auth_ctx->eckey.ex_static.SeEcPubKey);
    sss_key_object_free(&applet_auth_ctx->eckey.ex_static.masterSec);
    sss_key_object_free(&applet_auth_ctx->eckey.ex_dyn.Enc);
    sss_key_object_free(&applet_auth_ctx->eckey.ex_dyn.Mac);
    sss_key_object_free(&applet_auth_ctx->eckey.ex_dyn.Rmac);
#else
    AX_UNUSED_ARG(applet_auth_ctx);
#endif
}

static sss_status_t open_applet_scp_session(ex_sss_boot_ctx_t *boot_ctx,
    sss_session_t *applet_session,
    sss_tunnel_t *tunnel_ctx,
    SE_Connect_Ctx_t *applet_open_ctx,
    ex_SE05x_authCtx_t *applet_auth_ctx)
{
#if SSS_HAVE_HOSTCRYPTO_ANY
    sss_status_t status = kStatus_SSS_Fail;
    int tunnel_ctx_initialized = 0;

    memset(applet_open_ctx, 0, sizeof(*applet_open_ctx));
    memset(applet_auth_ctx, 0, sizeof(*applet_auth_ctx));
    memset(applet_session, 0, sizeof(*applet_session));
    memset(tunnel_ctx, 0, sizeof(*tunnel_ctx));

    applet_open_ctx->auth.authType = kSSS_AuthType_ECKey;
    status = ex_sss_se05x_prepare_host_with_key(&boot_ctx->host_session,
        &boot_ctx->host_ks,
        applet_open_ctx,
        applet_auth_ctx,
        kSSS_AuthType_ECKey,
        kSe052fDemoHostEcdsaKeyPair,
        sizeof(kSe052fDemoHostEcdsaKeyPair));
    if (status != kStatus_SSS_Success) {
        LOG_W("ex_sss_se05x_prepare_host_with_key(ECKey applet SCP) failed: 0x%04X", status);
        goto cleanup;
    }

    status = sss_tunnel_context_init(tunnel_ctx, &boot_ctx->session);
    if (status != kStatus_SSS_Success) {
        LOG_W("sss_tunnel_context_init(ECKey applet SCP) failed: 0x%04X", status);
        goto cleanup;
    }
    tunnel_ctx_initialized = 1;

    applet_open_ctx->connType  = kType_SE_Conn_Type_Channel;
    applet_open_ctx->tunnelCtx = tunnel_ctx;

    status = sss_session_open(applet_session,
        kType_SSS_SE_SE05x,
        SE052F_APPLET_SCP_AUTH_OBJ_ID,
        kSSS_ConnectionType_Encrypted,
        applet_open_ctx);
    if (status != kStatus_SSS_Success) {
        LOG_W("sss_session_open(ECKey applet SCP) failed: 0x%04X", status);
        goto cleanup;
    }

    printf("Opened applet SCP ECKey session 0x%08X over PlatformSCP\n", SE052F_APPLET_SCP_AUTH_OBJ_ID);

cleanup:
    if (status != kStatus_SSS_Success) {
        if (tunnel_ctx_initialized) {
            sss_tunnel_context_free(tunnel_ctx);
        }
        free_applet_scp_auth_context(applet_auth_ctx);
    }
    return status;
#else
    AX_UNUSED_ARG(boot_ctx);
    AX_UNUSED_ARG(applet_session);
    AX_UNUSED_ARG(tunnel_ctx);
    AX_UNUSED_ARG(applet_open_ctx);
    AX_UNUSED_ARG(applet_auth_ctx);
    LOG_W("Applet SCP requires host crypto support");
    return kStatus_SSS_Fail;
#endif
}

static int probe_applet_scp_session(sss_session_t *applet_session)
{
    sss_se05x_session_t *applet_se05x_session = (sss_se05x_session_t *)applet_session;
    uint8_t version[32]                       = {0};
    size_t version_len                        = sizeof(version);
    smStatus_t sm_status;

    sm_status = Se05x_API_GetVersion(&applet_se05x_session->s_ctx, version, &version_len);
    if (sm_status != SM_OK) {
        LOG_W("Se05x_API_GetVersion over applet SCP failed: 0x%04X", sm_status);
        return 0;
    }

    print_hex("SE05x applet SCP version: ", version, version_len);
    return 1;
}

static sss_status_t sign_random_digest_with_existing_key(
    sss_session_t *session, const char *session_label, uint8_t *digest, size_t digest_len)
{
    sss_status_t status          = kStatus_SSS_Fail;
    sss_key_store_t key_store    = {0};
    sss_object_t signing_key     = {0};
    sss_asymmetric_t asymm_ctx   = {0};
    uint8_t signature[128]       = {0};
    size_t signature_len         = sizeof(signature);
    int key_store_initialized    = 0;
    int signing_key_initialized  = 0;
    int asymm_ctx_initialized    = 0;

    status = sss_key_store_context_init(&key_store, session);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: sss_key_store_context_init failed: 0x%04X", session_label, status);
        goto cleanup;
    }
    key_store_initialized = 1;

    status = sss_key_store_allocate(&key_store, __LINE__);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: sss_key_store_allocate failed: 0x%04X", session_label, status);
        goto cleanup;
    }

    status = sss_key_object_init(&signing_key, &key_store);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: sss_key_object_init failed: 0x%04X", session_label, status);
        goto cleanup;
    }
    signing_key_initialized = 1;

    status = sss_key_object_get_handle(&signing_key, SE052F_SIGNING_KEY_ID);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: signing key 0x%08X handle lookup failed: 0x%04X", session_label, SE052F_SIGNING_KEY_ID, status);
        goto cleanup;
    }

    status = sss_asymmetric_context_init(&asymm_ctx, session, &signing_key, kAlgorithm_SSS_SHA256, kMode_SSS_Sign);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: sss_asymmetric_context_init failed: 0x%04X", session_label, status);
        goto cleanup;
    }
    asymm_ctx_initialized = 1;

    status = sss_asymmetric_sign_digest(&asymm_ctx, digest, digest_len, signature, &signature_len);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: signing with key 0x%08X failed: 0x%04X", session_label, SE052F_SIGNING_KEY_ID, status);
        goto cleanup;
    }

    printf("%s signing digest:   ", session_label);
    print_hex("", digest, digest_len);
    printf("%s signature:        ", session_label);
    print_hex("", signature, signature_len);

cleanup:
    if (asymm_ctx_initialized) {
        sss_asymmetric_context_free(&asymm_ctx);
    }
    if (signing_key_initialized) {
        sss_key_object_free(&signing_key);
    }
    if (key_store_initialized) {
        sss_key_store_context_free(&key_store);
    }
    return status;
}

static void init_attestation_data_lengths(sss_se05x_attst_data_t *attst_data)
{
    size_t i = 0;

    for (i = 0; i < SE05X_MAX_ATTST_DATA; i++) {
        attst_data->data[i].timeStampLen = sizeof(attst_data->data[i].timeStamp);
        attst_data->data[i].chipIdLen    = sizeof(attst_data->data[i].chipId);
        attst_data->data[i].attributeLen = sizeof(attst_data->data[i].attribute);
        attst_data->data[i].signatureLen = sizeof(attst_data->data[i].signature);
#if SSS_HAVE_SE05X_VER_GTE_07_02
        attst_data->data[i].cmdLen     = sizeof(attst_data->data[i].cmd);
        attst_data->data[i].objSizeLen = sizeof(attst_data->data[i].objSize);
#else
        attst_data->data[i].outrandomLen = sizeof(attst_data->data[i].outrandom);
#endif
    }
}

static sss_status_t read_key_object_with_attestation(
    sss_session_t *session, uint32_t object_id, const char *label, uint8_t *freshness, size_t freshness_len)
{
    sss_status_t status              = kStatus_SSS_Fail;
    sss_key_store_t key_store        = {0};
    sss_object_t target_key          = {0};
    sss_object_t attestation_key     = {0};
    sss_se05x_attst_data_t attst_data = {0};
    uint8_t object_data[256]         = {0};
    size_t object_data_len           = sizeof(object_data);
    size_t object_bit_len            = 0;
    int key_store_initialized        = 0;
    int target_key_initialized       = 0;
    int attestation_key_initialized  = 0;

    status = sss_key_store_context_init(&key_store, session);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: sss_key_store_context_init failed: 0x%04X", label, status);
        goto cleanup;
    }
    key_store_initialized = 1;

    status = sss_key_store_allocate(&key_store, __LINE__);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: sss_key_store_allocate failed: 0x%04X", label, status);
        goto cleanup;
    }

    status = sss_key_object_init(&target_key, &key_store);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: target key object init failed: 0x%04X", label, status);
        goto cleanup;
    }
    target_key_initialized = 1;

    status = sss_key_object_get_handle(&target_key, object_id);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: target key 0x%08X handle lookup failed: 0x%04X", label, object_id, status);
        goto cleanup;
    }

    status = sss_key_object_init(&attestation_key, &key_store);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: attestation key object init failed: 0x%04X", label, status);
        goto cleanup;
    }
    attestation_key_initialized = 1;

    status = sss_key_object_get_handle(&attestation_key, SE052F_ATTESTATION_KEY_ID);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: attestation key 0x%08X handle lookup failed: 0x%04X", label, SE052F_ATTESTATION_KEY_ID, status);
        goto cleanup;
    }

    init_attestation_data_lengths(&attst_data);
    status = sss_se05x_key_store_get_key_attst((sss_se05x_key_store_t *)&key_store,
        (sss_se05x_object_t *)&target_key,
        object_data,
        &object_data_len,
        &object_bit_len,
        (sss_se05x_object_t *)&attestation_key,
        kAlgorithm_SSS_SHA256,
        freshness,
        freshness_len,
        &attst_data);
    if (status != kStatus_SSS_Success) {
        LOG_W("%s: read-with-attestation failed for object 0x%08X: 0x%04X", label, object_id, status);
        goto cleanup;
    }

    printf("%s attested read object: 0x%08X\n", label, object_id);
    printf("%s public object data:   ", label);
    print_hex("", object_data, object_data_len);
    if (attst_data.valid_number > 0) {
        printf("%s attestation attr:   ", label);
        print_hex("", attst_data.data[0].attribute, attst_data.data[0].attributeLen);
        printf("%s attestation chip:   ", label);
        print_hex("", attst_data.data[0].chipId, attst_data.data[0].chipIdLen);
        printf("%s attestation sig:    ", label);
        print_hex("", attst_data.data[0].signature, attst_data.data[0].signatureLen);
    }

cleanup:
    if (attestation_key_initialized) {
        sss_key_object_free(&attestation_key);
    }
    if (target_key_initialized) {
        sss_key_object_free(&target_key);
    }
    if (key_store_initialized) {
        sss_key_store_context_free(&key_store);
    }
    return status;
}

static sss_status_t read_secure_key_objects_with_attestation(sss_session_t *session)
{
    sss_status_t status      = kStatus_SSS_Fail;
    smStatus_t sm_status     = SM_NOT_OK;
    uint8_t freshness[16]    = {0};
    size_t freshness_len     = sizeof(freshness);

    sm_status = Se05x_API_GetRandom(&((sss_se05x_session_t *)session)->s_ctx, sizeof(freshness), freshness, &freshness_len);
    if ((sm_status != SM_OK) || (freshness_len != sizeof(freshness))) {
        LOG_W("Unable to generate attestation freshness: 0x%04X", sm_status);
        return kStatus_SSS_Fail;
    }

    status = read_key_object_with_attestation(
        session, SE052F_ATTESTATION_KEY_ID, "PlatformSCP+AppletSCP(ECKey) attestation key", freshness, freshness_len);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    status = read_key_object_with_attestation(
        session, SE052F_SIGNING_KEY_ID, "PlatformSCP+AppletSCP(ECKey) signing key", freshness, freshness_len);
    if (status == kStatus_SSS_Success) {
        printf("Expected result: read-with-attestation succeeded for all secure key objects\n");
    }

    return status;
}

int main(int argc, const char *argv[])
{
    ex_sss_boot_ctx_t boot_ctx;
    sss_session_t applet_scp_session;
    sss_tunnel_t applet_scp_tunnel_ctx;
    SE_Connect_Ctx_t applet_scp_open_ctx;
    ex_SE05x_authCtx_t applet_scp_auth_ctx;
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
    uint8_t signing_digest[32] = {0};
    size_t signing_digest_len  = sizeof(signing_digest);
    sss_se05x_session_t *se05x_session = NULL;
    int runtime_auth_object_ok = 0;
    int secure_key_objects_ok = 0;
    int applet_scp_session_ok = 0;
    int applet_scp_probe_ok = 0;
    int applet_scp_sign_ok = 0;
    int applet_scp_attested_read_ok = 0;

    memset(&boot_ctx, 0, sizeof(boot_ctx));
    memset(&applet_scp_session, 0, sizeof(applet_scp_session));
    memset(&applet_scp_tunnel_ctx, 0, sizeof(applet_scp_tunnel_ctx));
    memset(&applet_scp_open_ctx, 0, sizeof(applet_scp_open_ctx));
    memset(&applet_scp_auth_ctx, 0, sizeof(applet_scp_auth_ctx));

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

    if (runtime_auth_object_ok) {
        sm_status = create_bound_secure_key_objects_if_needed(se05x_session);
        if (sm_status == SM_OK) {
            secure_key_objects_ok = 1;
        }
        else {
            LOG_W("Bound secure key object provisioning failed: 0x%04X", sm_status);
        }
    }

    if (runtime_auth_object_ok) {
        sss_status = open_applet_scp_session(
            &boot_ctx, &applet_scp_session, &applet_scp_tunnel_ctx, &applet_scp_open_ctx, &applet_scp_auth_ctx);
        if (sss_status == kStatus_SSS_Success) {
            applet_scp_session_ok = 1;
            applet_scp_probe_ok   = probe_applet_scp_session(&applet_scp_session);
        }
        else {
            LOG_W("Applet SCP session open failed: 0x%04X", sss_status);
        }
    }

    sm_status = Se05x_API_GetVersion(&se05x_session->s_ctx, version, &version_len);
    if (sm_status == SM_OK) {
        print_hex("SE05x applet version: ", version, version_len);
    }
    else {
        LOG_W("Se05x_API_GetVersion failed: 0x%04X", sm_status);
    }

    sm_status = Se05x_API_ReadState(&se05x_session->s_ctx, state, &state_len);
    if (sm_status == SM_OK) {
        print_hex("SE05x state:          ", state, state_len);
    }
    else {
        LOG_W("Se05x_API_ReadState failed: 0x%04X", sm_status);
    }

    sm_status = Se05x_API_GetRandom(&se05x_session->s_ctx, sizeof(random_data), random_data, &random_data_len);
    if (sm_status == SM_OK) {
        print_hex("SE05x random bytes:   ", random_data, random_data_len);
    }
    else {
        LOG_W("Se05x_API_GetRandom failed: 0x%04X", sm_status);
    }

    if (secure_key_objects_ok && applet_scp_session_ok) {
        signing_digest_len = sizeof(signing_digest);
        sm_status = Se05x_API_GetRandom(&se05x_session->s_ctx, sizeof(signing_digest), signing_digest, &signing_digest_len);
        if ((sm_status == SM_OK) && (signing_digest_len == sizeof(signing_digest))) {
            printf("Expected: PlatformSCP-only signing should fail because key 0x%08X requires auth object 0x%08X\n",
                SE052F_SIGNING_KEY_ID,
                SE052F_RUNTIME_AUTH_OBJ_ID);
            sss_status = sign_random_digest_with_existing_key(&boot_ctx.session, "PlatformSCP", signing_digest, signing_digest_len);
            if (sss_status != kStatus_SSS_Success) {
                printf("Expected result: PlatformSCP-only signing was denied by object policy\n");
            }
            else {
                LOG_W("Unexpected result: PlatformSCP-only signing succeeded");
            }

            printf("Expected: PlatformSCP+AppletSCP(ECKey) signing should succeed using auth object 0x%08X\n",
                SE052F_RUNTIME_AUTH_OBJ_ID);
            sss_status = sign_random_digest_with_existing_key(
                &applet_scp_session, "PlatformSCP+AppletSCP(ECKey)", signing_digest, signing_digest_len);
            if (sss_status == kStatus_SSS_Success) {
                applet_scp_sign_ok = 1;
                printf("Expected result: PlatformSCP+AppletSCP(ECKey) signing succeeded\n");
            }

            sss_status = read_secure_key_objects_with_attestation(&applet_scp_session);
            if (sss_status == kStatus_SSS_Success) {
                applet_scp_attested_read_ok = 1;
            }
        }
        else {
            LOG_W("Unable to generate signing digest: 0x%04X", sm_status);
        }
    }

    ret = (runtime_auth_object_ok && secure_key_objects_ok && applet_scp_session_ok && applet_scp_probe_ok &&
              applet_scp_sign_ok && applet_scp_attested_read_ok) ?
              0 :
              1;

cleanup:
    if (applet_scp_session.subsystem != kType_SSS_SubSystem_NONE) {
        sss_session_close(&applet_scp_session);
        sss_session_delete(&applet_scp_session);
        sss_tunnel_context_free(&applet_scp_tunnel_ctx);
        free_applet_scp_auth_context(&applet_scp_auth_ctx);
    }
    ex_sss_session_close(&boot_ctx);
    nLog_DeInit();
    return ret;
}
