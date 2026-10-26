/* SPDX-License-Identifier: BSD-2-Clause */

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#include "test.h"
#include "tpm2-pkcs11/pkcs11-tpm2.h"

/*
 * Tests of the vendor mechanism CKM_TPM2_CERTIFY: a signing key which is not a
 * token object, created here through ESAPI as an attestation key would be,
 * certifies keys of the token.
 */

/* an unused persistent handle for the CKF_TPM2_SIGNER_ESYS_TR tests */
#define AK_PERSISTENT_HANDLE 0x81000AC0

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;

    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys;
    ESYS_TR ak;
    TPM2B_PUBLIC *ak_public;
    /* marshalled TPMS_CONTEXT of the AK */
    CK_BYTE ak_context[sizeof(TPMS_CONTEXT)];
    CK_ULONG ak_context_len;
};

static void create_ak(test_info *ti) {

    const char *tcti = getenv("TPM2_PKCS11_TCTI");
    TSS2_RC rc = Tss2_TctiLdr_Initialize(tcti, &ti->tcti);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    rc = Esys_Initialize(&ti->esys, ti->tcti, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    /* a restricted ECDSA P-256 signing key, as an attestation key */
    TPM2B_PUBLIC in_public = {
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT
                | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT
                | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH,
            .parameters.eccDetail = {
                .symmetric.algorithm = TPM2_ALG_NULL,
                .scheme = {
                    .scheme = TPM2_ALG_ECDSA,
                    .details.ecdsa.hashAlg = TPM2_ALG_SHA256
                },
                .curveID = TPM2_ECC_NIST_P256,
                .kdf.scheme = TPM2_ALG_NULL
            },
        },
    };
    TPM2B_SENSITIVE_CREATE in_sensitive = { 0 };
    TPM2B_DATA outside_info = { 0 };
    TPML_PCR_SELECTION pcrs = { 0 };

    rc = Esys_CreatePrimary(ti->esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
            ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive, &in_public,
            &outside_info, &pcrs, &ti->ak, &ti->ak_public, NULL, NULL, NULL);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    /* the module loads it in an ESAPI context of its own */
    TPMS_CONTEXT *context = NULL;
    rc = Esys_ContextSave(ti->esys, ti->ak, &context);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    size_t offset = 0;
    rc = Tss2_MU_TPMS_CONTEXT_Marshal(context, ti->ak_context,
            sizeof(ti->ak_context), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    ti->ak_context_len = offset;
    Esys_Free(context);
}

static int test_setup(void **state) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, TOKEN_COUNT);

    ti->slot_id = slots[0];

    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL,
            NULL, &ti->handle);
    assert_int_equal(rv, CKR_OK);

    create_ak(ti);

    *state = ti;

    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_CloseAllSessions(ti->slot_id);
    assert_int_equal(rv, CKR_OK);

    Esys_FlushContext(ti->esys, ti->ak);
    Esys_Free(ti->ak_public);
    Esys_Finalize(&ti->esys);
    Tss2_TctiLdr_Finalize(&ti->tcti);

    free(ti);

    return 0;
}

static void get_private_key(CK_SESSION_HANDLE session, CK_KEY_TYPE key_type,
        CK_OBJECT_HANDLE_PTR priv) {

    CK_OBJECT_HANDLE pub;
    get_keypair(session, key_type, &pub, priv);
}

/* The TPM name of a key of the token: nameAlg || H(TPMT_PUBLIC). */
static void key_name(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, TPM2B_NAME *name) {

    CK_BYTE blob[sizeof(TPM2B_PUBLIC)];
    CK_ATTRIBUTE attr = { CKA_TPM2_PUB_BLOB, blob, sizeof(blob) };
    CK_RV rv = C_GetAttributeValue(session, key, &attr, 1);
    assert_int_equal(rv, CKR_OK);

    TPM2B_PUBLIC pub = { 0 };
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob, attr.ulValueLen, &offset, &pub);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(pub.publicArea.nameAlg, TPM2_ALG_SHA256);

    CK_BYTE area[sizeof(TPMT_PUBLIC)];
    offset = 0;
    rc = Tss2_MU_TPMT_PUBLIC_Marshal(&pub.publicArea, area, sizeof(area), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    name->size = 2 + SHA256_DIGEST_LENGTH;
    name->name[0] = TPM2_ALG_SHA256 >> 8;
    name->name[1] = TPM2_ALG_SHA256 & 0xff;
    SHA256(area, offset, &name->name[2]);
}

/* The AK's public key, through a DER SubjectPublicKeyInfo. */
static EVP_PKEY *ak_pkey(test_info *ti) {

    static const CK_BYTE p256_spki_prefix[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
        0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04
    };

    TPMS_ECC_POINT *point = &ti->ak_public->publicArea.unique.ecc;
    assert_int_equal(point->x.size, 32);
    assert_int_equal(point->y.size, 32);

    CK_BYTE der[sizeof(p256_spki_prefix) + 64];
    memcpy(der, p256_spki_prefix, sizeof(p256_spki_prefix));
    memcpy(&der[sizeof(p256_spki_prefix)], point->x.buffer, 32);
    memcpy(&der[sizeof(p256_spki_prefix) + 32], point->y.buffer, 32);

    const unsigned char *p = der;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, sizeof(der));
    assert_non_null(pkey);
    return pkey;
}

/* Checks the output of the mechanism: TPM2B_ATTEST || TPMT_SIGNATURE. */
static void check_attestation(test_info *ti, CK_OBJECT_HANDLE key,
        CK_BYTE_PTR qualifying, CK_ULONG qualifying_len,
        CK_BYTE_PTR out, CK_ULONG out_len) {

    TPM2B_ATTEST attest = { 0 };
    TPMT_SIGNATURE signature = { 0 };
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_ATTEST_Unmarshal(out, out_len, &offset, &attest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(out, out_len, &offset, &signature);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(offset, out_len);

    TPMS_ATTEST info = { 0 };
    offset = 0;
    rc = Tss2_MU_TPMS_ATTEST_Unmarshal(attest.attestationData, attest.size,
            &offset, &info);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(info.magic, TPM2_GENERATED_VALUE);
    assert_int_equal(info.type, TPM2_ST_ATTEST_CERTIFY);
    assert_int_equal(info.extraData.size, qualifying_len);
    assert_memory_equal(info.extraData.buffer, qualifying, qualifying_len);

    TPM2B_NAME name = { 0 };
    key_name(ti->handle, key, &name);
    assert_int_equal(info.attested.certify.name.size, name.size);
    assert_memory_equal(info.attested.certify.name.name, name.name, name.size);

    /* the AK signed it */
    assert_int_equal(signature.sigAlg, TPM2_ALG_ECDSA);
    assert_int_equal(signature.signature.ecdsa.hash, TPM2_ALG_SHA256);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    assert_non_null(sig);
    BIGNUM *r = BN_bin2bn(signature.signature.ecdsa.signatureR.buffer,
            signature.signature.ecdsa.signatureR.size, NULL);
    BIGNUM *s = BN_bin2bn(signature.signature.ecdsa.signatureS.buffer,
            signature.signature.ecdsa.signatureS.size, NULL);
    assert_non_null(r);
    assert_non_null(s);
    assert_int_equal(ECDSA_SIG_set0(sig, r, s), 1);
    unsigned char *der = NULL;
    int der_len = i2d_ECDSA_SIG(sig, &der);
    assert_true(der_len > 0);
    ECDSA_SIG_free(sig);

    EVP_PKEY *pkey = ak_pkey(ti);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    assert_non_null(mdctx);
    int ok = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
    assert_int_equal(ok, 1);
    ok = EVP_DigestVerify(mdctx, der, der_len, attest.attestationData, attest.size);
    assert_int_equal(ok, 1);

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(der);
}

static void certify_params_context(test_info *ti, CK_TPM2_CERTIFY_PARAMS *params) {

    memset(params, 0, sizeof(*params));
    params->flags = CKF_TPM2_SIGNER_CONTEXT;
    params->pSigner = ti->ak_context;
    params->ulSignerLen = ti->ak_context_len;
}

static void certify_and_check(test_info *ti, CK_KEY_TYPE key_type,
        CK_TPM2_CERTIFY_PARAMS *params) {

    CK_SESSION_HANDLE session = ti->handle;
    CK_OBJECT_HANDLE key;
    get_private_key(session, key_type, &key);

    CK_MECHANISM mech = { CKM_TPM2_CERTIFY, params, sizeof(*params) };
    CK_RV rv = C_SignInit(session, &mech, key);
    assert_int_equal(rv, CKR_OK);

    /* the digest of what an attestation is about, here a challenge */
    CK_BYTE qualifying[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)"challenge", 9, qualifying);

    /* call for size, the operation stays active */
    CK_ULONG out_len = 0;
    rv = C_Sign(session, qualifying, sizeof(qualifying), NULL, &out_len);
    assert_int_equal(rv, CKR_OK);
    assert_true(out_len >= sizeof(TPM2B_ATTEST));

    /* too small, the operation stays active */
    CK_BYTE out[sizeof(TPM2B_ATTEST) + sizeof(TPMT_SIGNATURE)];
    CK_ULONG small_len = 16;
    rv = C_Sign(session, qualifying, sizeof(qualifying), out, &small_len);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(small_len, out_len);

    assert_true(out_len <= sizeof(out));
    rv = C_Sign(session, qualifying, sizeof(qualifying), out, &out_len);
    assert_int_equal(rv, CKR_OK);

    check_attestation(ti, key, qualifying, sizeof(qualifying), out, out_len);

    /* the operation is over */
    rv = C_Sign(session, qualifying, sizeof(qualifying), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);
}

static void test_certify_mechanism_advertised(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_MECHANISM_TYPE mechs[128];
    CK_ULONG count = ARRAY_LEN(mechs);
    CK_RV rv = C_GetMechanismList(ti->slot_id, mechs, &count);
    assert_int_equal(rv, CKR_OK);

    bool found = false;
    CK_ULONG i;
    for (i = 0; i < count; i++) {
        if (mechs[i] == CKM_TPM2_CERTIFY) {
            found = true;
        }
    }
    assert_true(found);

    CK_MECHANISM_INFO info = { 0 };
    rv = C_GetMechanismInfo(ti->slot_id, CKM_TPM2_CERTIFY, &info);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(info.flags, CKF_SIGN | CKF_HW);
}

static void test_certify_ec_key(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_TPM2_CERTIFY_PARAMS params;
    certify_params_context(ti, &params);
    certify_and_check(ti, CKK_EC, &params);
}

static void test_certify_rsa_key(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_TPM2_CERTIFY_PARAMS params;
    certify_params_context(ti, &params);
    certify_and_check(ti, CKK_RSA, &params);
}

static void test_certify_context_reused(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    /* the module flushes what it loaded, the context can be loaded again */
    CK_TPM2_CERTIFY_PARAMS params;
    certify_params_context(ti, &params);
    certify_and_check(ti, CKK_EC, &params);
    certify_and_check(ti, CKK_EC, &params);
}

static void test_certify_explicit_scheme(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    TPMT_SIG_SCHEME scheme = {
        .scheme = TPM2_ALG_ECDSA,
        .details.ecdsa.hashAlg = TPM2_ALG_SHA256
    };
    CK_BYTE scheme_buf[sizeof(scheme)];
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPMT_SIG_SCHEME_Marshal(&scheme, scheme_buf,
            sizeof(scheme_buf), &offset);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    CK_TPM2_CERTIFY_PARAMS params;
    certify_params_context(ti, &params);
    params.pInScheme = scheme_buf;
    params.ulInSchemeLen = offset;
    certify_and_check(ti, CKK_EC, &params);
}

static void test_certify_persistent_signer(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    ESYS_TR persistent = ESYS_TR_NONE;
    TSS2_RC rc = Esys_EvictControl(ti->esys, ESYS_TR_RH_OWNER, ti->ak,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            AK_PERSISTENT_HANDLE, &persistent);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    uint8_t *tr = NULL;
    size_t tr_len = 0;
    rc = Esys_TR_Serialize(ti->esys, persistent, &tr, &tr_len);
    assert_int_equal(rc, TSS2_RC_SUCCESS);

    CK_TPM2_CERTIFY_PARAMS params = {
        .flags = CKF_TPM2_SIGNER_ESYS_TR,
        .pSigner = tr,
        .ulSignerLen = tr_len,
    };
    certify_and_check(ti, CKK_EC, &params);

    /* a persistent object stays */
    certify_and_check(ti, CKK_RSA, &params);

    /* a transient object's context is not an ESYS_TR of a persistent object */
    CK_OBJECT_HANDLE key;
    get_private_key(ti->handle, CKK_EC, &key);
    params.pSigner = ti->ak_context;
    params.ulSignerLen = ti->ak_context_len;
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY, &params, sizeof(params) };
    CK_RV rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    Esys_Free(tr);
    rc = Esys_EvictControl(ti->esys, ESYS_TR_RH_OWNER, persistent,
            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
            AK_PERSISTENT_HANDLE, &persistent);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
}

static void test_certify_not_logged_in(void **state) {

    test_info *ti = test_info_from_state(state);

    /* private keys can be found once logged in */
    user_login(ti->handle);
    CK_OBJECT_HANDLE key;
    get_private_key(ti->handle, CKK_EC, &key);
    logout(ti->handle);

    CK_TPM2_CERTIFY_PARAMS params;
    certify_params_context(ti, &params);
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY, &params, sizeof(params) };
    CK_RV rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);
}

static void test_certify_data_len_range(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE key;
    get_private_key(ti->handle, CKK_EC, &key);

    CK_TPM2_CERTIFY_PARAMS params;
    certify_params_context(ti, &params);
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY, &params, sizeof(params) };
    CK_RV rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_OK);

    /* qualifyingData is a TPM2B_DATA, which the TSS sizes for the largest digest */
    CK_BYTE qualifying[sizeof(TPMU_HA) + 1] = { 0 };
    CK_BYTE out[sizeof(TPM2B_ATTEST) + sizeof(TPMT_SIGNATURE)];
    CK_ULONG out_len = sizeof(out);
    rv = C_Sign(ti->handle, qualifying, sizeof(qualifying), out, &out_len);
    assert_int_equal(rv, CKR_DATA_LEN_RANGE);

    /* the error terminated the operation */
    rv = C_Sign(ti->handle, qualifying, 32, out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* the largest qualifyingData works, as does none */
    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_OK);
    out_len = sizeof(out);
    rv = C_Sign(ti->handle, qualifying, sizeof(TPMU_HA), out, &out_len);
    assert_int_equal(rv, CKR_OK);
    check_attestation(ti, key, qualifying, sizeof(TPMU_HA), out, out_len);

    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_OK);
    out_len = sizeof(out);
    rv = C_Sign(ti->handle, NULL, 0, out, &out_len);
    assert_int_equal(rv, CKR_OK);
    check_attestation(ti, key, NULL, 0, out, out_len);
}

static void test_certify_bad_params(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE key;
    get_private_key(ti->handle, CKK_EC, &key);

    CK_TPM2_CERTIFY_PARAMS params;
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY, &params, sizeof(params) };

    /* no parameter, or of the wrong size */
    CK_MECHANISM nomech = { CKM_TPM2_CERTIFY, NULL, 0 };
    CK_RV rv = C_SignInit(ti->handle, &nomech, key);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    certify_params_context(ti, &params);
    mech.ulParameterLen = sizeof(params) - 1;
    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    mech.ulParameterLen = sizeof(params);

    /* no or both signer flags */
    params.flags = 0;
    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    params.flags = CKF_TPM2_SIGNER_CONTEXT | CKF_TPM2_SIGNER_ESYS_TR;
    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    /* a truncated context */
    certify_params_context(ti, &params);
    params.ulSignerLen -= 1;
    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    /*
     * A context which the TPM refuses: alter the start of the TPM's blob,
     * which follows sequence, savedHandle, hierarchy and the sizes (the end
     * of contextBlob is metadata which ESAPI appends, which the TPM does not
     * protect).
     */
    CK_BYTE bad[sizeof(ti->ak_context)];
    memcpy(bad, ti->ak_context, ti->ak_context_len);
    bad[8 + 4 + 4 + 2 + 2 + 4] ^= 0xff;
    certify_params_context(ti, &params);
    params.pSigner = bad;
    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    /* a scheme which isn't a TPMT_SIG_SCHEME */
    CK_BYTE scheme[] = { 0x00, 0x18, 0x00 };
    certify_params_context(ti, &params);
    params.pInScheme = scheme;
    params.ulInSchemeLen = sizeof(scheme);
    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    /* no operation is left active */
    certify_params_context(ti, &params);
    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_OK);
    CK_ULONG out_len = 0;
    rv = C_Sign(ti->handle, NULL, 0, NULL, &out_len);
    assert_int_equal(rv, CKR_OK);
}

static void test_certify_not_a_private_key(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE pub, priv;
    get_keypair(ti->handle, CKK_EC, &pub, &priv);

    CK_TPM2_CERTIFY_PARAMS params;
    certify_params_context(ti, &params);
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY, &params, sizeof(params) };
    CK_RV rv = C_SignInit(ti->handle, &mech, pub);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);

    /* nor a verification mechanism */
    rv = C_VerifyInit(ti->handle, &mech, priv);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);
}

static void test_certify_multipart_refused(void **state) {

    test_info *ti = test_info_from_state(state);
    user_login(ti->handle);

    CK_OBJECT_HANDLE key;
    get_private_key(ti->handle, CKK_EC, &key);

    CK_TPM2_CERTIFY_PARAMS params;
    certify_params_context(ti, &params);
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY, &params, sizeof(params) };

    CK_BYTE qualifying[32] = { 0 };
    CK_BYTE out[sizeof(TPM2B_ATTEST) + sizeof(TPMT_SIGNATURE)];
    CK_ULONG out_len = sizeof(out);

    CK_RV rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_OK);
    rv = C_SignUpdate(ti->handle, qualifying, sizeof(qualifying));
    assert_int_equal(rv, CKR_FUNCTION_FAILED);
    rv = C_Sign(ti->handle, qualifying, sizeof(qualifying), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_OK);
    rv = C_SignFinal(ti->handle, out, &out_len);
    assert_int_equal(rv, CKR_FUNCTION_FAILED);
    rv = C_Sign(ti->handle, qualifying, sizeof(qualifying), out, &out_len);
    assert_int_equal(rv, CKR_OPERATION_NOT_INITIALIZED);

    /* an operation abandoned with the session releases the signing key */
    rv = C_SignInit(ti->handle, &mech, key);
    assert_int_equal(rv, CKR_OK);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_certify_mechanism_advertised,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_ec_key,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_rsa_key,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_context_reused,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_explicit_scheme,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_persistent_signer,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_not_logged_in,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_data_len_range,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_bad_params,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_not_a_private_key,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_multipart_refused,
            test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
