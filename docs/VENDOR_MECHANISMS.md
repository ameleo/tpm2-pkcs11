# Vendor Mechanisms

The library defines vendor mechanisms for TPM operations which PKCS#11 has no
standard mechanism for. Their constants and parameter structures are in the
installed header `tpm2-pkcs11/pkcs11-tpm2.h`, along with the vendor attributes
`CKA_TPM2_*`. Include it after a PKCS#11 header, such as the one of p11-kit or
NSS.

Like the vendor attributes, the values are not stable yet.

## CKM_TPM2_CERTIFY

`CKM_TPM2_CERTIFY` performs a
[TPM2_Certify](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
of a private key of the token, with a TPM signing key which is not an object of
the token, such as an attestation key (AK) created under the endorsement key.
The result proves that the private key resides in the same TPM as the signing
key, which is what device attestation needs, for example ACME
`device-attest-01` with the WebAuthn `tpm` attestation statement format.

TPM2_Certify needs the authorization value of the object which is certified.
The library keeps the authorization values of the keys of a token, and does not
reveal them, so an application can only certify a key of the token through the
library.

### Usage

```c
CK_TPM2_CERTIFY_PARAMS params = {
    .flags = CKF_TPM2_SIGNER_CONTEXT,
    .pSigner = ak_context,          /* marshalled TPMS_CONTEXT */
    .ulSignerLen = ak_context_len,
    .pSignerAuth = NULL,            /* the AK's authorization value, if any */
    .ulSignerAuthLen = 0,
    .pInScheme = NULL,              /* marshalled TPMT_SIG_SCHEME, empty for TPM2_ALG_NULL */
    .ulInSchemeLen = 0,
};
CK_MECHANISM mechanism = { CKM_TPM2_CERTIFY, &params, sizeof(params) };

rv = C_SignInit(session, &mechanism, private_key);
rv = C_Sign(session, qualifying_data, qualifying_data_len, out, &out_len);
/* out: marshalled TPM2B_ATTEST (certifyInfo) || marshalled TPMT_SIGNATURE */
```

* `hKey` of `C_SignInit` is the private key object of the token which is
  certified, the `objectHandle` of TPM2_Certify. The signing key, the
  `signHandle`, is named by the mechanism parameter, since it is not an object
  of the token: an AK must be created under the endorsement hierarchy, and it
  belongs to the attestation protocol of the application rather than to the
  token. As with the other signature mechanisms, `hKey` is the key which the
  token uses for the operation, and the one whose `CKA_ALLOWED_MECHANISMS`
  must contain `CKM_TPM2_CERTIFY`. The library adds it to the allowed
  mechanisms of the RSA and EC private keys which it, or `tpm2_ptool`,
  creates.
* The signing key is either:
  * `CKF_TPM2_SIGNER_CONTEXT`: the marshalled `TPMS_CONTEXT` of a transient
    object, as `Esys_ContextSave` and `Tss2_MU_TPMS_CONTEXT_Marshal` produce
    it. Contexts of objects can be loaded through any connection to the TPM,
    through a resource manager or not. The library loads it in `C_SignInit` and
    flushes it when the operation ends, so the application keeps its own copy
    of the object.
  * `CKF_TPM2_SIGNER_ESYS_TR`: the `Esys_TR_Serialize` of a persistent object.
* The authorization value of the key which is certified goes through the
  salted HMAC session of the token, the one of the signing key through a
  password session.
* `pData` of `C_Sign` is the `qualifyingData` of TPM2_Certify: the TPM copies
  it into the `extraData` of the attestation. It is at most the size of the
  buffer of a `TPM2B_DATA`, 64 bytes with the TSS, else `C_Sign` returns
  `CKR_DATA_LEN_RANGE`.
* The mechanism is single-part: `C_SignUpdate` and `C_SignFinal` return
  `CKR_FUNCTION_FAILED`, which terminates the operation. `C_Sign` with a
  `NULL` output returns an upper bound of the output length, as it does for the
  other mechanisms, and keeps the operation active, as does
  `CKR_BUFFER_TOO_SMALL`.
* The user must be logged in.
* `C_GetMechanismList` lists the mechanism when the TPM implements
  TPM2_Certify. `C_GetMechanismInfo` reports `CKF_SIGN | CKF_HW`, with no key
  sizes.

### Errors

| Function      | Return value                  | Reason |
|---------------|-------------------------------|--------|
| `C_SignInit`  | `CKR_USER_NOT_LOGGED_IN`      | The user is not logged in. |
| `C_SignInit`  | `CKR_MECHANISM_INVALID`       | `CKM_TPM2_CERTIFY` is not in the `CKA_ALLOWED_MECHANISMS` of `hKey`, as for keys created by earlier versions. |
| `C_SignInit`  | `CKR_KEY_TYPE_INCONSISTENT`   | `hKey` is not a private key. |
| `C_SignInit`  | `CKR_MECHANISM_PARAM_INVALID` | The parameter is malformed, or the TPM refuses to load the signing key. |
| `C_Sign`      | `CKR_DATA_LEN_RANGE`          | `qualifyingData` is too long. |
| `C_Sign`      | `CKR_FUNCTION_FAILED`         | The TPM refused TPM2_Certify, for example because the signing key is not a signing key, or the scheme does not match it. |
| `C_SignUpdate`, `C_SignFinal` | `CKR_FUNCTION_FAILED` | Single-part mechanism. |
| `C_VerifyInit` | `CKR_MECHANISM_INVALID`      | The mechanism has no verification. |
