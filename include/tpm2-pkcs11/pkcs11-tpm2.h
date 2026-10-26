/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Vendor defined attributes and mechanisms of the tpm2-pkcs11 module.
 *
 * Include this header after a PKCS#11 header which defines the CK_* base
 * types, CKA_VENDOR_DEFINED and CKM_VENDOR_DEFINED, such as the one of
 * p11-kit or NSS.
 */
#ifndef TPM2_PKCS11_PKCS11_TPM2_H_
#define TPM2_PKCS11_PKCS11_TPM2_H_

/*
 * Vendor attributes.
 *
 * We will allow these to be accessed, but the values are not stable.
 */
#define CKA_VENDOR_TPM2_DEFINED  0x0F000000UL
#define CKA_TPM2_OBJAUTH_ENC     (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x1UL)
#define CKA_TPM2_PUB_BLOB        (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x2UL)
#define CKA_TPM2_PRIV_BLOB       (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x3UL)
#define CKA_TPM2_ENC_BLOB        (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x4UL)
#define CKA_TPM2_SERIALIZED_TR   (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x5UL)

/*
 * Vendor mechanisms.
 */
#define CKM_VENDOR_TPM2_DEFINED  0x0F000000UL

/*
 * CKM_TPM2_CERTIFY: TPM2_Certify of a private key object of the token by a
 * TPM signing key which is not a token object, such as an attestation key
 * created under an endorsement key.
 *
 *   C_SignInit(hSession, &mechanism, hKey)
 *     mechanism.pParameter is a CK_TPM2_CERTIFY_PARAMS which names the
 *     signing key, hKey is the private key object to certify (the
 *     objectHandle of TPM2_Certify).
 *   C_Sign(hSession, pData, ulDataLen, pSignature, pulSignatureLen)
 *     pData is the qualifyingData of TPM2_Certify, at most the size of
 *     the buffer of a TPM2B_DATA (64 bytes, the size of the largest digest,
 *     with the TSS). pSignature receives the marshalled TPM2B_ATTEST (certifyInfo)
 *     followed by the marshalled TPMT_SIGNATURE (signature).
 *
 * Single-part only: C_SignUpdate and C_SignFinal fail with
 * CKR_FUNCTION_FAILED and terminate the operation. The user must be logged
 * in. The module advertises the mechanism when the TPM implements
 * TPM2_Certify.
 */
#define CKM_TPM2_CERTIFY         (CKM_VENDOR_DEFINED|CKM_VENDOR_TPM2_DEFINED|0x1UL)

/* pSigner is a marshalled TPMS_CONTEXT, as returned by TPM2_ContextSave of
 * a transient object. The module loads it for the operation and flushes it
 * afterwards. */
#define CKF_TPM2_SIGNER_CONTEXT  0x1UL
/* pSigner is the serialized ESYS_TR (Esys_TR_Serialize) of a persistent
 * object. */
#define CKF_TPM2_SIGNER_ESYS_TR  0x2UL

typedef struct CK_TPM2_CERTIFY_PARAMS {
    CK_FLAGS flags;            /* exactly one of CKF_TPM2_SIGNER_* */
    CK_BYTE_PTR pSigner;       /* the signing key, as flags says */
    CK_ULONG ulSignerLen;
    CK_BYTE_PTR pSignerAuth;   /* authorization value of the signing key, may be empty */
    CK_ULONG ulSignerAuthLen;
    CK_BYTE_PTR pInScheme;     /* marshalled TPMT_SIG_SCHEME, empty for TPM2_ALG_NULL */
    CK_ULONG ulInSchemeLen;
} CK_TPM2_CERTIFY_PARAMS;

typedef CK_TPM2_CERTIFY_PARAMS *CK_TPM2_CERTIFY_PARAMS_PTR;

#endif /* TPM2_PKCS11_PKCS11_TPM2_H_ */
