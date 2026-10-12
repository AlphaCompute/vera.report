/* Validate the complete KMS CMS envelope before Rust decrypts it. This does
 * not authenticate its sender; the caller must already have verified AWS TLS. */
#include <stddef.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

static int sha256_algorithm(const X509_ALGOR *algorithm) {
    const ASN1_OBJECT *oid = NULL;
    int type = 0;
    if (!algorithm) return 0;
    X509_ALGOR_get0(&oid, &type, NULL, algorithm);
    return OBJ_obj2nid(oid) == NID_sha256 && (type == V_ASN1_NULL || type == V_ASN1_UNDEF);
}

static int recipient_algorithm(CMS_ContentInfo *cms) {
    STACK_OF(CMS_RecipientInfo) *recipients = CMS_get0_RecipientInfos(cms);
    if (!recipients || sk_CMS_RecipientInfo_num(recipients) != 1) return 0;
    CMS_RecipientInfo *recipient = sk_CMS_RecipientInfo_value(recipients, 0);
    X509_ALGOR *algorithm = NULL;
    if (CMS_RecipientInfo_type(recipient) != CMS_RECIPINFO_TRANS ||
        !CMS_RecipientInfo_ktri_get0_algs(recipient, NULL, NULL, &algorithm)) return 0;
    const ASN1_OBJECT *oid = NULL;
    const void *parameters = NULL;
    int type = 0, valid = 0;
    X509_ALGOR_get0(&oid, &type, &parameters, algorithm);
    if (OBJ_obj2nid(oid) != NID_rsaesOaep || type != V_ASN1_SEQUENCE) return 0;
    const ASN1_STRING *encoded = parameters;
    const unsigned char *start = ASN1_STRING_get0_data(encoded), *cursor = start;
    long size = ASN1_STRING_length(encoded);
    RSA_OAEP_PARAMS *oaep = d2i_RSA_OAEP_PARAMS(NULL, &cursor, size);
    X509_ALGOR *mask_hash = NULL;
    if (!oaep || cursor != start + size || !sha256_algorithm(oaep->hashFunc) || !oaep->maskGenFunc) goto done;
    X509_ALGOR_get0(&oid, &type, &parameters, oaep->maskGenFunc);
    if (OBJ_obj2nid(oid) != NID_mgf1 || type != V_ASN1_SEQUENCE) goto done;
    encoded = parameters; start = ASN1_STRING_get0_data(encoded); cursor = start;
    size = ASN1_STRING_length(encoded);
    mask_hash = d2i_X509_ALGOR(NULL, &cursor, size);
    if (!mask_hash || cursor != start + size || !sha256_algorithm(mask_hash)) goto done;
    if (oaep->pSourceFunc) {
        X509_ALGOR_get0(&oid, &type, &parameters, oaep->pSourceFunc);
        if (OBJ_obj2nid(oid) != NID_pSpecified || type != V_ASN1_OCTET_STRING ||
            ASN1_STRING_length(parameters) != 0) goto done;
    }
    valid = 1;
 done:
    X509_ALGOR_free(mask_hash); RSA_OAEP_PARAMS_free(oaep);
    return valid;
}

int vera_recipient_envelope_valid(const unsigned char *data, size_t length) {
    if (!data || !length || length > 16384) return 0;
    const unsigned char *cursor = data;
    CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, &cursor, (long)length);
    int valid = cms && cursor == data + length &&
        OBJ_obj2nid(CMS_get0_type(cms)) == NID_pkcs7_enveloped && recipient_algorithm(cms);
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return valid;
}
