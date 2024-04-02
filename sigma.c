#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cmac.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cbor.h>

unsigned char S3K_Info[] = /* "Sigma3" */
{0x53, 0x69, 0x67, 0x6d, 0x61, 0x33};

unsigned char S2K_Info[] = /* "Sigma2" */
{0x53, 0x69, 0x67, 0x6d, 0x61, 0x32};

unsigned char IPK[] = 
{ 0x05, 0xbb, 0xba, 0xa1, 0xe9, 0xf5, 0xe9, 0x3e, 0x0b, 0x4b, 0xdd, 0x7f, 0x34, 0x57, 0x33, 0xf0, 0x0a, 0x05, 0x9a, 0x90, 0x79, 0x44, 0x48, 0x93, 0x97, 0xb2, 0x01, 0x56, 0x07, 0xd8, 0x64, 0x52}; 

unsigned char TBEData2_Nonce[13] = /* "NCASE_Sigma2N" */
{0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69,
0x67, 0x6d, 0x61, 0x32, 0x4e};

unsigned char TBEData3_Nonce[13] = /* "NCASE_Sigma3N" */
{0x4e, 0x43, 0x41, 0x53, 0x45, 0x5f, 0x53, 0x69,
0x67, 0x6d, 0x61, 0x33, 0x4e};

unsigned char SEKeys_Info[] = /* "SessionKeys" */
{0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b,
0x65, 0x79, 0x73};

typedef struct session_key_t {
    unsigned char *i2r_key;
    unsigned char *r2i_key;
    unsigned char *att_challenge;
    size_t len;
} session_key_t;

typedef struct sigma1_t {
    unsigned char *i_random;
    unsigned char *dst_id;

    EVP_PKEY *ie_pub;
    unsigned char *ie_pub_bin;
    size_t ie_pub_bin_len;

    unsigned char *msg_bin;
    size_t msg_bin_len;
} sigma1_t;




/*typedef struct sigma2_tbs_t {*/
    /*unsigned char *r_cert;*/

    /*EVP_PKEY *re_pub;*/
    /*unsigned char *re_pub_bin;*/
    /*size_t re_pub_bin_len;*/

    /*EVP_PKEY *ie_pub;*/
    /*unsigned char *ie_pub_bin;*/
    /*size_t ie_pub_bin_len;*/
/*} sigma2_tbs_t ;*/

typedef struct sigma_tbe_t {
    unsigned char *cert_der;
    size_t cert_der_len;

    unsigned char *sig;
    size_t sig_len;

    unsigned char *tbe_bin;
    size_t tbe_bin_len;
} sigma_tbe_t ;

typedef struct sigma2_t {
    unsigned char *r_random;
    EVP_PKEY *re_pub;
    unsigned char *re_pub_bin;
    size_t re_pub_bin_len;
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *tag;
    size_t tag_len;
    unsigned char *msg_bin;
    size_t msg_bin_len;
} sigma2_t ;

typedef struct sigma3_tbs_t {
    unsigned char *i_cert;


    EVP_PKEY *ie_pub;
    unsigned char *ie_pub_bin;
    size_t ie_pub_bin_len;

    EVP_PKEY *re_pub;
    unsigned char *re_pub_bin;
    size_t re_pub_bin_len;
} sigma3_tbs_t ;

typedef struct sigma3_tbe_t {
    unsigned char *i_cert;

    unsigned char *i_sig;
    size_t i_sig_len;
} sigma3_tbe_t ;

typedef struct sigma3_t {
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *tag;
    size_t tag_len;
    unsigned char *msg_bin;
    size_t msg_bin_len;
} sigma3_t ;


typedef struct ec_keypair_t {
    EVP_PKEY *priv;
    EVP_PKEY *pub;
    unsigned char *pub_hex;
    unsigned char *pub_bin;
    size_t pub_bin_len;
} ec_keypair_t;

typedef struct cert_keypair_t {
    X509 *cert;
    unsigned char* cert_der;
    size_t cert_der_len;
    EVP_PKEY *priv;
    EVP_PKEY *pub;
    unsigned char *pub_hex;
    unsigned char *pub_bin;
    size_t pub_bin_len;
} cert_keypair_t;


typedef struct hybrid_signcryption_t{
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *tag;
    size_t tag_len;
    unsigned char *s;
    size_t s_len;
} hybrid_signcryption_t;

typedef struct ecies_encrypt_t{
    unsigned char *ye;
    size_t ye_len;
    unsigned char *iv;
    size_t iv_len;
    unsigned char *ciphertext;
    size_t ciphertext_len;
} ecies_encrypt_t;

typedef struct ecies_signature_t {
    ecies_encrypt_t *c;
    unsigned char *sig;
    size_t sig_len;
} ecies_signature_t;

EVP_PKEY* evp_pkey_from_point_hex(EC_GROUP* group, char* point_hex, BN_CTX* ctx)  
{
    EC_KEY* ec_key = EC_KEY_new();
    EC_KEY_set_group(ec_key, group);

    EC_POINT* ec_pub_point = EC_POINT_new(group);
    ec_pub_point = EC_POINT_hex2point(group, point_hex, ec_pub_point, ctx);
    EC_KEY_set_public_key(ec_key, ec_pub_point);

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey, ec_key);

    return pkey;
}

int aes_ctr_raw(unsigned char *cipher_name, unsigned char *in, int in_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char **out, int is_encrypt )
{
    EVP_CIPHER_CTX *ctx;

    int out_len;
    int len;


    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);

    if(!EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, is_encrypt))
        return -1;

    if(!EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, is_encrypt))
        return -1;

    *out = OPENSSL_malloc(in_len);

    if(!EVP_CipherUpdate(ctx, *out, &out_len, in, in_len))
        return -1;

    if(!EVP_CipherFinal_ex(ctx, *out, &len))
        return -1;
    out_len += len;


    EVP_CIPHER_CTX_cleanup(ctx);
    /*EVP_CIPHER_free(cipher);*/

    return out_len;
}

int aead_encrypt_raw(unsigned char *cipher_name, unsigned char *plaintext, int plaintext_len, unsigned char *aad, int aad_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char **ciphertext, unsigned char **tag, int tag_len)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;


    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if(1 != EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        return -1;

    if(OPENSSL_strcasecmp(cipher_name, "gcm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
            return -1;
    }else if(OPENSSL_strcasecmp(cipher_name, "ccm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL))
            return -1;
    }

    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        return -1;

    *ciphertext = OPENSSL_malloc(plaintext_len);

    if(1 != EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    *tag = OPENSSL_malloc(tag_len);

    if(OPENSSL_strcasecmp(cipher_name, "gcm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, *tag))
            return -1;
    }else if(OPENSSL_strcasecmp(cipher_name, "ccm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, tag_len, *tag))
            return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    /*EVP_CIPHER_free(cipher);*/

    return ciphertext_len;
}

int aead_decrypt_raw( unsigned char *cipher_name, unsigned char *ciphertext, int ciphertext_len, unsigned char *aad, int aad_len, unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv, int iv_len, unsigned char **plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;


    if(!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if(!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        return -1;

    if(OPENSSL_strcasecmp(cipher_name, "gcm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
            return -1;
    }else if(OPENSSL_strcasecmp(cipher_name, "ccm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, iv_len, NULL))
            return -1;
    }

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        return -1;

    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        return -1;

    *plaintext = OPENSSL_malloc(ciphertext_len);

    if(!EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    if(OPENSSL_strcasecmp(cipher_name, "gcm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
            return -1;
    }else if(OPENSSL_strcasecmp(cipher_name, "ccm")){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, tag_len, tag))
            return -1;
    }

    ret = EVP_DecryptFinal_ex(ctx, *plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    /*EVP_CIPHER_free(cipher);*/

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
}

int hmac_raw3(char *digest_name, unsigned char* key, size_t key_len, unsigned char *data, size_t data_len, unsigned char *data2, size_t data2_len, unsigned char *data3, size_t data3_len, unsigned char **out)
{
    char *propq = NULL;
    OSSL_LIB_CTX *library_context = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    EVP_MD_CTX *digest_context = NULL;
    size_t out_len = 0;
    OSSL_PARAM params[4], *p = params;

    library_context = OSSL_LIB_CTX_new();

    mac = EVP_MAC_fetch(library_context, "HMAC", propq);
    mctx = EVP_MAC_CTX_new(mac);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, sizeof(digest_name));
    *p = OSSL_PARAM_construct_end();

    EVP_MAC_init(mctx, key, key_len, params);

    EVP_MAC_update(mctx, data, data_len);
    EVP_MAC_update(mctx, data2, data2_len);
    EVP_MAC_update(mctx, data3, data3_len);

    EVP_MAC_final(mctx, NULL, &out_len, 0);

    *out = OPENSSL_malloc(out_len);

    EVP_MAC_final(mctx, *out, &out_len, out_len);

    EVP_MD_CTX_free(digest_context);
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    OSSL_LIB_CTX_free(library_context);

    return out_len;
}

int hmac_raw(char *digest_name, unsigned char* key, size_t key_len, unsigned char *data, size_t data_len, unsigned char **out)
{
    char *propq = NULL;
    OSSL_LIB_CTX *library_context = NULL;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    EVP_MD_CTX *digest_context = NULL;
    size_t out_len = 0;
    OSSL_PARAM params[4], *p = params;

    library_context = OSSL_LIB_CTX_new();

    mac = EVP_MAC_fetch(library_context, "HMAC", propq);
    mctx = EVP_MAC_CTX_new(mac);

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, sizeof(digest_name));
    *p = OSSL_PARAM_construct_end();

    EVP_MAC_init(mctx, key, key_len, params);

    EVP_MAC_update(mctx, data, data_len);

    EVP_MAC_final(mctx, NULL, &out_len, 0);

    *out = OPENSSL_malloc(out_len);

    EVP_MAC_final(mctx, *out, &out_len, out_len);

    EVP_MD_CTX_free(digest_context);
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    OSSL_LIB_CTX_free(library_context);

    return out_len;
}

unsigned char* digest_raw(unsigned char* digest_name, unsigned char* msg, size_t msg_len, size_t *out_len_ptr)
{
    unsigned char *out = NULL;
    const EVP_MD *digest;

    digest = EVP_get_digestbyname(digest_name);
    *out_len_ptr = EVP_MD_get_size(digest);

    out = OPENSSL_malloc(*out_len_ptr); 
    EVP_Digest(msg, msg_len, out, (unsigned int *) out_len_ptr, digest, NULL);

    return out;
}



unsigned char * bin2hex(const unsigned char * bin, size_t bin_len)
{

    unsigned char   *out = NULL;
    size_t  out_len;
    size_t n = bin_len*2 + 1;

    out = OPENSSL_malloc(n);
    OPENSSL_buf2hexstr_ex(out, n, &out_len, bin, bin_len, '\0');

    return out;

}

unsigned char* export_pubkey(EVP_PKEY *priv_pkey)
{
    unsigned char *pubkey = NULL;
    size_t pubkey_len;
    unsigned char *pub_hex = NULL;

    pubkey_len = EVP_PKEY_get1_encoded_public_key(priv_pkey, &pubkey);
    pub_hex = bin2hex(pubkey, pubkey_len);

    if(pubkey) OPENSSL_free(pubkey);

    return pub_hex;
}

X509* read_cert(unsigned char *fname){
    BIO *in = BIO_new_file(fname, "r");
    X509 *certificate = PEM_read_bio_X509(in, NULL, NULL, NULL);
    return certificate;
}

X509* read_cert_der(unsigned char *der, size_t der_len){
    BIO *bio;
    X509 *certificate;

    bio = BIO_new(BIO_s_mem());            
    BIO_write(bio, der, der_len ); 
    certificate = d2i_X509_bio(bio, NULL);
    return certificate;
}

cert_keypair_t *read_cert_keypair(unsigned char* privf, unsigned char* certf){
    X509* cert = read_cert(certf);
    //EVP_PKEY * pk = PEM_read_bio_PUBKEY(bioin, NULL, NULL, NULL);
    EVP_PKEY *pub = X509_get_pubkey(cert);

    int der_len;
    unsigned char *der =NULL;
    der_len = i2d_X509(cert, &der);

    /*BIO *der_w = BIO_new_file("/tmp/a.der", "w");*/
    /*i2d_X509_bio(der_w, cert);*/

    unsigned char *pub_bin = NULL;
    size_t pub_bin_len;
    unsigned char *pub_hex = NULL;
    pub_bin_len = EVP_PKEY_get1_encoded_public_key(pub, &pub_bin);
    pub_hex = bin2hex(pub_bin, pub_bin_len);

    BIO *in = BIO_new_file(privf, "r");
    EVP_PKEY *priv = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
    
    cert_keypair_t *out = (cert_keypair_t *)malloc(sizeof(cert_keypair_t));

    out->priv = priv;

    out->cert=cert;
    out->cert_der = der;
    out->cert_der_len = der_len;

    out->pub = pub;
    out->pub_hex = pub_hex;
    out->pub_bin = pub_bin;
    out->pub_bin_len = pub_bin_len;

    return out;
}

ec_keypair_t * gen_ec_keypair(unsigned char* group_name){
    ec_keypair_t *out = (ec_keypair_t *)malloc(sizeof(ec_keypair_t));

    BN_CTX * bnctx= BN_CTX_new();
    int nid = OBJ_sn2nid(group_name);
    EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);

    EVP_PKEY  *xa_pkey = EVP_PKEY_new();
    EVP_PKEY_keygen(ctx, &xa_pkey);
    //    PEM_write_PrivateKey(stdout,  xa_pkey, NULL, NULL, 0, NULL, NULL);

    unsigned char *ya_hex = export_pubkey(xa_pkey);
    //printf("pub_hex: %s\n", ya_hex);

    EVP_PKEY *ya_pkey=evp_pkey_from_point_hex(group, ya_hex, bnctx);
    //    PEM_write_PUBKEY(stdout,  ya_pkey);

    size_t ya_len;
    unsigned char* ya = OPENSSL_hexstr2buf(ya_hex, &ya_len);

    out->priv = xa_pkey;
    out->pub = ya_pkey;
    out->pub_hex = ya_hex;
    out->pub_bin = ya;
    out->pub_bin_len = ya_len;

    EC_GROUP_free(group);
    EVP_PKEY_CTX_free(ctx);
    BN_CTX_free(bnctx);

    return out;
}

int hkdf_raw(int mode, unsigned char *digest_name, unsigned char *ikm, size_t ikm_len, unsigned char *salt, size_t salt_len, unsigned char *info, size_t info_len, unsigned char **okm, size_t okm_len )
{
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[6], *p = params;
    OSSL_LIB_CTX *library_context = NULL;

    library_context = OSSL_LIB_CTX_new();

    kdf = EVP_KDF_fetch(library_context, "HKDF", NULL);

    kctx = EVP_KDF_CTX_new(kdf);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest_name, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm, ikm_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, info, info_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, salt, salt_len);
    *p = OSSL_PARAM_construct_end();

    *okm = OPENSSL_malloc(okm_len);
    if (EVP_KDF_derive(kctx, *okm, okm_len, params) != 1) {
        OPENSSL_free(*okm);
        okm_len = -1;
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OSSL_LIB_CTX_free(library_context);

    return okm_len;
}

EVP_PKEY* pubhex2pkey(unsigned char* group_name, unsigned char* yb_hex){

    BN_CTX *bnctx = BN_CTX_new();
    int nid = OBJ_sn2nid(group_name);
    EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);

    EVP_PKEY *yb_pkey=evp_pkey_from_point_hex(group, yb_hex, bnctx);
    BN_CTX_free(bnctx);
    EC_GROUP_free(group);

    return yb_pkey;
}

unsigned char* ecdh_raw(EVP_PKEY *priv, EVP_PKEY *peer_pub, size_t *z_len_ptr)
{
    unsigned char* z=NULL;
    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new(priv, NULL);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_pub);

    EVP_PKEY_derive(ctx, NULL, z_len_ptr);
    z = OPENSSL_malloc(*z_len_ptr);
    EVP_PKEY_derive(ctx, z, z_len_ptr);

    EVP_PKEY_CTX_free(ctx);

    return z;
}

int LabeledExpand(unsigned char *suite_id, size_t suite_id_len, unsigned char* prk, size_t prk_len, unsigned char* label, size_t label_len, unsigned char* info, size_t info_len, size_t okm_len, unsigned char** okm){
    unsigned char pre[] = { okm_len >> 8, okm_len & 0xff, 'H', 'P', 'K', 'E', '-', 'v', '1' };
    size_t pre_len = strlen(pre);

    unsigned char *labeled_info;
    size_t labeled_info_len = pre_len + suite_id_len + label_len + info_len;
    labeled_info = OPENSSL_malloc(labeled_info_len);
    memcpy(labeled_info, pre, pre_len);
    memcpy(labeled_info+pre_len, suite_id, suite_id_len);
    memcpy(labeled_info+pre_len+suite_id_len, label, label_len);
    memcpy(labeled_info+pre_len+suite_id_len+label_len, info, info_len);

    unsigned char salt[] = "";
    int out_len = hkdf_raw(2, "SHA256", prk, prk_len, salt, strlen(salt), labeled_info, labeled_info_len, okm, okm_len);

    //BIO_dump_indent_fp(stdout, *okm, out_len, 2);
    OPENSSL_free(labeled_info);

    return out_len;
}

int LabeledExtract(unsigned char *suite_id, size_t suite_id_len, unsigned char* salt, size_t salt_len, unsigned char *label, size_t label_len, unsigned char* ikm, size_t ikm_len, size_t out_len, unsigned char **out)
{

    unsigned char pre[] = "HPKE-v1";
    size_t  pre_len = strlen(pre);
    unsigned char info[] = "";

    unsigned char *labeled_ikm;
    size_t labeled_ikm_len = pre_len + suite_id_len + label_len + ikm_len;
    labeled_ikm = OPENSSL_malloc(labeled_ikm_len);
    memcpy(labeled_ikm, pre, pre_len);
    memcpy(labeled_ikm+pre_len, suite_id, suite_id_len);
    memcpy(labeled_ikm+pre_len+suite_id_len, label, label_len);
    memcpy(labeled_ikm+pre_len+suite_id_len+label_len, ikm, ikm_len);

    out_len = hkdf_raw(1, "SHA256", labeled_ikm, labeled_ikm_len, salt, salt_len, info, strlen(info), out, out_len);

    //BIO_dump_indent_fp(stdout, *out, out_len, 2);
    OPENSSL_free(labeled_ikm);

    return out_len;
}

int ExtractAndExpand(unsigned char *suite_id, size_t suite_id_len, unsigned char* dh, size_t dh_len, unsigned char *kem_context, size_t kem_context_len, unsigned char **out)
{
    //printf("prk:\n");
    unsigned char *eae_prk;
    size_t eae_prk_len;
    unsigned char salt[] ="";
    unsigned char label_prk[] = "eae_prk";
    eae_prk_len = LabeledExtract(suite_id, suite_id_len, salt, strlen(salt), label_prk, strlen(label_prk), dh, dh_len, 32, &eae_prk);

    //printf("ss:\n");
    unsigned char label_ss[] = "shared_secret";
    size_t ss_len = LabeledExpand(suite_id, suite_id_len, eae_prk, eae_prk_len, label_ss, strlen(label_ss), kem_context, kem_context_len, 32, out);

    OPENSSL_free(eae_prk);

    return ss_len;
}


int hpke_nonce_xor(size_t nonce_len, uint64_t seq, uint8_t*  base_nonce, uint8_t **out_nonce_ptr) 
{
    *out_nonce_ptr = OPENSSL_malloc(nonce_len);
    uint8_t *out_nonce = *out_nonce_ptr;
    memset(out_nonce, 0, nonce_len);
    uint64_t seq_copy = seq;
    for (size_t i = 0; i < 8; i++) {
        out_nonce[nonce_len - i - 1] = seq_copy & 0xff;
        seq_copy >>= 8;
    }
    for (size_t i = 0; i < nonce_len; i++) {
        out_nonce[i] ^= base_nonce[i];
    }

    return nonce_len;
}

ecies_encrypt_t * ecies_encrpyt_raw(unsigned char* group_name, unsigned char* digest_name, EVP_PKEY *yb_pkey, unsigned char* msg, size_t msg_len)
{

    unsigned char salt[] = "";
    unsigned char info[] = "";
    unsigned int  okm_len = 16;

    //printf("xe:\n");
    ec_keypair_t *ec_e = gen_ec_keypair(group_name);

    /*//printf("yb:%s\n", yb_hex);*/
    /*EVP_PKEY *yb_pkey=pubhex2pkey(group_name, yb_hex);*/

    //printf("z:\n");
    unsigned char *z;
    size_t zlen;
    z = ecdh_raw(ec_e->priv, yb_pkey, &zlen);
    //BIO_dump_indent_fp(stdout, z, zlen, 2);

    //printf("okm:\n");
    unsigned char *okm= NULL;
    hkdf_raw(0, digest_name, z, zlen, salt, strlen(salt), info, strlen(info), &okm, okm_len);
    //BIO_dump_indent_fp(stdout, okm, okm_len, 2);

    //printf("iv:\n");
    BIGNUM *iv_bn=BN_new();
    BN_rand(iv_bn, 128, 0, 0);
    unsigned char *iv = OPENSSL_malloc(128);
    int iv_len = BN_bn2bin(iv_bn, iv);
    //BIO_dump_indent_fp(stdout, iv, iv_len, 2);

    //printf("msg:\n");
    //BIO_dump_indent_fp(stdout, msg, msg_len, 2);

    //printf("ciphertext:\n");
    unsigned char *ciphertext=NULL;    
    int ciphertext_len = aes_ctr_raw("aes-256-ctr", msg, msg_len, okm, iv, iv_len, &ciphertext, 1);
    //BIO_dump_indent_fp(stdout, ciphertext, ciphertext_len, 2);

    ecies_encrypt_t *out = (ecies_encrypt_t *)malloc(sizeof(ecies_encrypt_t));
    out->ye = ec_e->pub_bin;
    out->ye_len = ec_e->pub_bin_len;
    out->iv = iv;
    out->iv_len = iv_len;
    out->ciphertext = ciphertext;
    out->ciphertext_len = ciphertext_len;

    OPENSSL_free(z);
    OPENSSL_free(okm);
    OPENSSL_free(iv_bn);
    OPENSSL_free(ec_e->priv);
    OPENSSL_free(ec_e->pub);
    OPENSSL_free(ec_e->pub_hex);

    return out;
}

size_t ecies_decrypt_raw(unsigned char* group_name, unsigned char* digest_name, EVP_PKEY *xb_pkey, ecies_encrypt_t *c, unsigned char** msg)
{

    EC_KEY *e = NULL;
    EC_POINT *e_pub = NULL;
    unsigned char salt[] = "";
    unsigned char info[] = "";
    unsigned int  okm_len = 16;

    BN_CTX *bnctx = BN_CTX_new();
    int nid = OBJ_sn2nid(group_name);
    EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);

    unsigned char* ye_hex = bin2hex(c->ye, c->ye_len);
    EVP_PKEY *ye_pkey=evp_pkey_from_point_hex(group, ye_hex, bnctx);


    //printf("z:\n");
    unsigned char *z;
    size_t zlen;
    z = ecdh_raw(xb_pkey, ye_pkey, &zlen);
    //BIO_dump_indent_fp(stdout, z, zlen, 2);

    //printf("okm:\n");
    unsigned char *okm= NULL;
    hkdf_raw(0, digest_name, z, zlen, salt, strlen(salt), info, strlen(info), &okm, okm_len);
    //BIO_dump_indent_fp(stdout, okm, okm_len, 2);

    //printf("iv:\n");
    //BIO_dump_indent_fp(stdout, c->iv, c->iv_len, 2);

    //printf("ciphertext:\n");
    //BIO_dump_indent_fp(stdout, c->ciphertext, c->ciphertext_len, 2);

    //printf("msg:\n");
    size_t msg_len;
    msg_len = aes_ctr_raw("aes-256-ctr", c->ciphertext, c->ciphertext_len, okm, c->iv, c->iv_len, msg, 0);
    //BIO_dump_indent_fp(stdout, *msg, msg_len, 2);

    OPENSSL_free(bnctx);
    OPENSSL_free(group);
    OPENSSL_free(ye_hex);
    OPENSSL_free(ye_pkey);
    /*OPENSSL_free(zctx);*/
    OPENSSL_free(z);
    OPENSSL_free(okm);

    return msg_len;
}


int sigma_signature_verify(unsigned char* group_name, unsigned char* sig_name, unsigned char* digest_name, EVP_PKEY *pubkey, 
        unsigned char* sig, size_t sig_len, 
        unsigned char* cert, size_t cert_len, 
        unsigned char* pub1, size_t pub1_len, 
        unsigned char* pub2, size_t pub2_len
        )
{

    const char *propq = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    /*unsigned char *sig_value = NULL;*/
    EVP_MD_CTX *verify_context = NULL;
    int ret = 0;

    libctx = OSSL_LIB_CTX_new();
    verify_context = EVP_MD_CTX_new();

    EVP_DigestVerifyInit_ex(verify_context, NULL, sig_name, libctx, NULL, pubkey, NULL); 

    EVP_DigestVerifyUpdate(verify_context, cert, cert_len); 
    EVP_DigestVerifyUpdate(verify_context, pub1, pub1_len); 
    EVP_DigestVerifyUpdate(verify_context, pub2, pub2_len); 

    if (EVP_DigestVerifyFinal(verify_context, sig, sig_len)) {
        ret = 1;
        //printf("sigma's ecdsa verify: success!\n");
    }

    EVP_MD_CTX_free(verify_context);
    OSSL_LIB_CTX_free(libctx);
    /*OPENSSL_free(bnctx);*/
    /*OPENSSL_free(group);*/
    /*OPENSSL_free(ya_pkey);*/

    return ret;
}

//sigma2_tbe_t * sigma2_signature(unsigned char* group_name, unsigned char* sig_name, unsigned char* digest_name, cert_keypair_t *r, ec_keypair_t *re, EVP_PKEY *ie_pkey)
sigma_tbe_t * sigma_signature(unsigned char* group_name, unsigned char* sig_name, unsigned char* digest_name, 
        EVP_PKEY *privkey, 
        unsigned char* cert, size_t cert_len, 
        unsigned char* pub1, size_t pub1_len, 
        unsigned char* pub2, size_t pub2_len
        )
{

    sigma_tbe_t *out = (sigma_tbe_t *)malloc(sizeof(sigma_tbe_t));

    unsigned char *sig;

    const char *propq = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    size_t sig_len = 0;
    /*unsigned char *sig_value = NULL;*/
    EVP_MD_CTX *sign_context = NULL;

    libctx = OSSL_LIB_CTX_new();
    sign_context = EVP_MD_CTX_new();

    EVP_DigestSignInit_ex(sign_context, NULL, sig_name, libctx, NULL, privkey, NULL); 

    EVP_DigestSignUpdate(sign_context, cert, cert_len); 
    EVP_DigestSignUpdate(sign_context, pub1, pub1_len); 
    EVP_DigestSignUpdate(sign_context, pub2, pub2_len); 

    /*unsigned char* ie_pub_bin;*/
    /*size_t ie_pub_bin_len;*/
    /*ie_pub_bin_len = EVP_PKEY_get1_encoded_public_key(ie_pkey, &ie_pub_bin);*/
    /*EVP_DigestSignUpdate(sign_context, ie_pub_bin, ie_pub_bin_len); */

    EVP_DigestSignFinal(sign_context, NULL, &sig_len); 

    sig = OPENSSL_malloc(sig_len);

    if (!EVP_DigestSignFinal(sign_context, sig, &sig_len)){ 
        OPENSSL_free(sig);
        sig_len = -1;
    }

    EVP_MD_CTX_free(sign_context);
    OSSL_LIB_CTX_free(libctx);

    out->sig = sig;
    out->sig_len = sig_len;

    //printf("sig:\n");
    //BIO_dump_indent_fp(stdout, sig, sig_len, 2);

    out->cert_der = cert;
    out->cert_der_len = cert_len;

    unsigned char* buffer;
    size_t buffer_size;
    cbor_item_t *item = cbor_new_indefinite_array();
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(out->cert_der, out->cert_der_len)));
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(out->sig, out->sig_len)));
    cbor_serialize_alloc(item, &buffer, &buffer_size);
    cbor_decref(&item);

    out->tbe_bin = buffer;
    out->tbe_bin_len = buffer_size;

    return out;
}

unsigned char* read_ec_pubkey(EVP_PKEY *pkey)
{

    unsigned char* pub=NULL;
    size_t pub_len;
    char* pub_hex = NULL;

    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL,  0, &pub_len);
    pub = OPENSSL_malloc(pub_len);
    EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, pub_len, NULL);

    /*EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len);*/

    pub_hex = bin2hex(pub, pub_len);

    OPENSSL_free(pub);

    return pub_hex;
}

BIGNUM* get_pkey_bn_param(EVP_PKEY *pkey, unsigned char *param_name)
{
    BIGNUM *x_bn = NULL;

    x_bn = BN_new();
    EVP_PKEY_get_bn_param(pkey, param_name, &x_bn);

    return x_bn;
}


int read_file(char *fname, unsigned char **buf) {

    FILE *fd = fopen(fname, "rb");

    fseek(fd, 0, SEEK_END);
    size_t flen = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    *buf = (unsigned char*)malloc(flen);

    size_t read_len = fread(*buf, 1, flen, fd);

    fclose(fd);

    return flen;
}


//int verify_cert(unsigned char* eef, unsigned char* rootf){
    /*X509* ee = read_cert(eef);*/
    /*X509* root = read_cert(rootf);*/
int verify_cert(X509* ee, X509* root){

    X509_STORE_CTX *ctx= X509_STORE_CTX_new();

    X509_STORE *s = X509_STORE_new();
    X509_STORE_add_cert(s, root);

    X509_STORE_CTX_init(ctx, s, ee, NULL);

    int status = X509_verify_cert(ctx);
    if(status == 1)
    {
        //printf("Certificate verified ok\n");
    }else
    {
        int n = X509_STORE_CTX_get_error(ctx);
        fprintf(stderr, "%s\n", X509_verify_cert_error_string(n));
    }

    return status;
}


sigma1_t* send_sigma1(
        unsigned char *r_id, EVP_PKEY *ie_pub, 
        unsigned char *ie_pub_bin,
        size_t ie_pub_bin_len
        )
{
    //printf("irand:\n");
    BIGNUM *irand_bn=BN_new();
    BN_rand(irand_bn, 256, 0, 0);
    unsigned char *irand = OPENSSL_malloc(256);
    int irand_len = BN_bn2bin(irand_bn, irand);
    //BIO_dump_indent_fp(stdout, irand, irand_len, 2);

    sigma1_t* m1 = OPENSSL_malloc(sizeof(sigma1_t));
    m1->i_random = irand;
    m1->dst_id = r_id;
    m1->ie_pub = ie_pub;
    m1->ie_pub_bin = ie_pub_bin; 
    m1->ie_pub_bin_len = ie_pub_bin_len;

    unsigned char* buffer;
    size_t buffer_size;
    cbor_item_t *item = cbor_new_indefinite_array();
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(m1->i_random, 256)));
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(m1->dst_id, sizeof(m1->dst_id))));
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(m1->ie_pub_bin, m1->ie_pub_bin_len)));
    cbor_serialize_alloc(item, &buffer, &buffer_size);
    cbor_decref(&item);

    m1->msg_bin = buffer;
    m1->msg_bin_len = buffer_size;

    return m1;
}

sigma2_t* send_sigma2(unsigned char* group_name, unsigned char* sig_name, unsigned char* digest_name,  sigma1_t* m1, cert_keypair_t *r, ec_keypair_t *re )
{

    //printf("rrand:\n");
    BIGNUM *rrand_bn=BN_new();
    BN_rand(rrand_bn, 256, 0, 0);
    unsigned char *rrand = OPENSSL_malloc(256);
    int rrand_len = BN_bn2bin(rrand_bn, rrand);
    //BIO_dump_indent_fp(stdout, rrand, rrand_len, 2);

    unsigned char *m1_hash;
    size_t m1_hash_len;
    m1_hash = digest_raw(digest_name, m1->msg_bin, m1->msg_bin_len, &m1_hash_len);

    size_t ipk_len = sizeof(IPK);
    unsigned char *salt;
    size_t salt_len = ipk_len + rrand_len + re->pub_bin_len + m1_hash_len;
    salt = OPENSSL_malloc(salt_len);
    memcpy(salt, IPK, ipk_len);
    memcpy(salt+ipk_len, rrand, rrand_len);
    memcpy(salt+ipk_len+rrand_len, re->pub_bin, re->pub_bin_len);
    memcpy(salt+ipk_len+rrand_len+re->pub_bin_len, m1_hash, m1_hash_len);
    //printf("sigma2 salt:\n");
    //BIO_dump_indent_fp(stdout, salt, salt_len, 2);

    size_t ss_len; 
    unsigned char* ss;
    ss = ecdh_raw(re->priv, m1->ie_pub, &ss_len);
    //printf("sigma2 ss:\n");
    //BIO_dump_indent_fp(stdout, ss, ss_len, 2);
    
    unsigned char* s2k;
    size_t s2k_len = hkdf_raw(2, digest_name, ss, ss_len, salt, salt_len, S2K_Info, sizeof(S2K_Info), &s2k, 32);
    //printf("sigma2 s2k:\n");
    //BIO_dump_indent_fp(stdout, s2k, s2k_len, 2);

    //sigma2_tbe_t *tbe = sigma2_signature( group_name,  sig_name,  digest_name, r, re, m1->ie_pub);
    sigma_tbe_t *tbe = sigma_signature( group_name,  sig_name,  digest_name, 
            r->priv,
            r->cert_der, r->cert_der_len, 
            re->pub_bin, re->pub_bin_len, 
            m1->ie_pub_bin, m1->ie_pub_bin_len 
            );
    //printf("sigma2 tbe:\n");
    //BIO_dump_indent_fp(stdout, tbe->tbe_bin, tbe->tbe_bin_len, 2);

    //printf("enc ciphertext:\n");
    unsigned char *ciphertext=NULL;    
    unsigned char *tag=NULL;    
    unsigned char aad[] = "";
    size_t tag_len = 16;
    int ciphertext_len = aead_encrypt_raw("aes-256-gcm", tbe->tbe_bin, tbe->tbe_bin_len, NULL, 0, s2k, TBEData2_Nonce, 13, &ciphertext, &tag, tag_len);
    //BIO_dump_indent_fp(stdout, ciphertext, ciphertext_len, 2);


    sigma2_t *out = (sigma2_t *)malloc(sizeof(sigma2_t));
    out->r_random = rrand;
    out->re_pub = re->pub;
    out->re_pub_bin = re->pub_bin;
    out->re_pub_bin_len = re->pub_bin_len;
    out->ciphertext = ciphertext;
    out->ciphertext_len = ciphertext_len;
    out->tag = tag;
    out->tag_len = tag_len;

    unsigned char* buffer;
    size_t buffer_size;
    cbor_item_t *item = cbor_new_indefinite_array();
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(out->r_random, 256)));
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(out->re_pub_bin, out->re_pub_bin_len)));
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(out->ciphertext, out->ciphertext_len)));
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(out->tag, out->tag_len)));
    cbor_serialize_alloc(item, &buffer, &buffer_size);
    cbor_decref(&item);

    out->msg_bin = buffer;
    out->msg_bin_len = buffer_size;

    return out;
}

int validate_sigma2(unsigned char* group_name, unsigned char* sig_name, unsigned char* digest_name,  X509* root_cert, sigma1_t *m1, sigma2_t* m2, cert_keypair_t *i, ec_keypair_t *ie)
{
    unsigned char *m1_hash=NULL;
    size_t m1_hash_len;
    m1_hash = digest_raw(digest_name, m1->msg_bin, m1->msg_bin_len, &m1_hash_len);

    size_t ipk_len = sizeof(IPK);
    size_t rrand_len = 32;
    unsigned char *salt;
    size_t salt_len = ipk_len + rrand_len + m2->re_pub_bin_len + m1_hash_len;
    salt = OPENSSL_malloc(salt_len);
    memcpy(salt, IPK, ipk_len);
    memcpy(salt+ipk_len, m2->r_random, rrand_len);
    memcpy(salt+ipk_len+rrand_len, m2->re_pub_bin, m2->re_pub_bin_len);
    memcpy(salt+ipk_len+rrand_len+m2->re_pub_bin_len, m1_hash, m1_hash_len);
    //printf("sigma2 salt:\n");
    //BIO_dump_indent_fp(stdout, salt, salt_len, 2);


    size_t ss_len; 
    unsigned char* ss;
    ss = ecdh_raw(ie->priv, m2->re_pub, &ss_len);
    //printf("sigma2 ss:\n");
    //BIO_dump_indent_fp(stdout, ss, ss_len, 2);

    unsigned char* s2k;
    size_t s2k_len = hkdf_raw(2, digest_name, ss, ss_len, salt, salt_len, S2K_Info, sizeof(S2K_Info), &s2k, 32);
    //printf("sigma2 s2k:\n");
    //BIO_dump_indent_fp(stdout, s2k, s2k_len, 2);

    //printf("client: decrypt and read m2->tbe\n");
    size_t msg_len;
    unsigned char *msg;
    msg_len = aead_decrypt_raw("aes-256-gcm",m2->ciphertext, m2->ciphertext_len, NULL, 0, m2->tag, m2->tag_len, s2k, TBEData2_Nonce, 13, &msg);
    //BIO_dump_indent_fp(stdout, msg, msg_len, 2);

    struct cbor_load_result result;
    cbor_item_t* item = cbor_load(msg, msg_len, &result);
    /*cbor_describe(item, stdout);*/

    cbor_item_t* item_rcert = cbor_array_get(item, 0);

    size_t item_rcert_len = cbor_bytestring_length(item_rcert);
    unsigned char* item_rcert_bytes = cbor_bytestring_handle(item_rcert);
    X509* rcert =  read_cert_der(item_rcert_bytes, item_rcert_len);
    int status = verify_cert(rcert, root_cert);
    //printf("\nsigma2 rcert verify: %d\n", status);
    EVP_PKEY *rpub = X509_get_pubkey(rcert);

    cbor_item_t* item_rsig = cbor_array_get(item, 1);
    size_t item_rsig_len = cbor_bytestring_length(item_rsig);
    unsigned char* item_rsig_bytes = cbor_bytestring_handle(item_rsig);

    int sigma2_sig_status = sigma_signature_verify(group_name, sig_name, digest_name, rpub, 
            item_rsig_bytes, item_rsig_len, 
            item_rcert_bytes, item_rcert_len,
            m2->re_pub_bin, m2->re_pub_bin_len, 
            m1->ie_pub_bin, m1->ie_pub_bin_len
            ); 

    return sigma2_sig_status;
}


sigma3_t* send_sigma3(unsigned char* group_name, unsigned char* sig_name, unsigned char* digest_name,  sigma1_t* m1, sigma2_t* m2, cert_keypair_t *i, ec_keypair_t *ie )
{

    unsigned char *digest_value = NULL;
    unsigned int digest_len;
    const EVP_MD *digest;

    digest = EVP_get_digestbyname(digest_name);
    digest_len = EVP_MD_get_size(digest);
    digest_value = OPENSSL_malloc(digest_len); 

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, digest, NULL);
    EVP_DigestUpdate(mdctx, m1->msg_bin, m1->msg_bin_len);
    EVP_DigestUpdate(mdctx, m2->msg_bin, m2->msg_bin_len);
    EVP_DigestFinal_ex(mdctx, digest_value, &digest_len);

    /*EVP_Digest(msg, msg_len, out, (unsigned int *) out_len_ptr, digest, NULL);*/

    size_t ipk_len = sizeof(IPK);
    unsigned char *salt;
    size_t salt_len = ipk_len + digest_len;
    salt = OPENSSL_malloc(salt_len);
    memcpy(salt, IPK, ipk_len);
    memcpy(salt+digest_len, digest_value, digest_len);

    size_t ss_len; 
    unsigned char* ss;
    ss = ecdh_raw(ie->priv, m2->re_pub, &ss_len);
    
    unsigned char* s3k;
    size_t s3k_len = hkdf_raw(2, digest_name, ss, ss_len, salt, salt_len, S3K_Info, sizeof(S3K_Info), &s3k, 32);
    //printf("s3k:\n");
    //BIO_dump_indent_fp(stdout, s3k, s3k_len, 2);

    //printf("sigma tbe:\n");
    sigma_tbe_t *tbe = sigma_signature( group_name,  sig_name,  digest_name, 
            i->priv,
            i->cert_der, i->cert_der_len, 
            ie->pub_bin, ie->pub_bin_len, 
            m2->re_pub_bin, m2->re_pub_bin_len 
            );
    //BIO_dump_indent_fp(stdout, tbe->tbe_bin, tbe->tbe_bin_len, 2);

    //printf("enc ciphertext:\n");
    unsigned char *ciphertext=NULL;    
    unsigned char *tag=NULL;    
    unsigned char aad[] = "";
    size_t tag_len = 16;
    int ciphertext_len = aead_encrypt_raw("aes-256-gcm", tbe->tbe_bin, tbe->tbe_bin_len, NULL, 0, s3k, TBEData3_Nonce, 13, &ciphertext, &tag, tag_len);
    //BIO_dump_indent_fp(stdout, ciphertext, ciphertext_len, 2);


    sigma3_t *out = (sigma3_t *)malloc(sizeof(sigma3_t));
    out->ciphertext = ciphertext;
    out->ciphertext_len = ciphertext_len;
    out->tag = tag;
    out->tag_len = tag_len;

    unsigned char* buffer;
    size_t buffer_size;
    cbor_item_t *item = cbor_new_indefinite_array();
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(out->ciphertext, out->ciphertext_len)));
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(out->tag, out->tag_len)));
    cbor_serialize_alloc(item, &buffer, &buffer_size);
    cbor_decref(&item);

    out->msg_bin = buffer;
    out->msg_bin_len = buffer_size;

    return out;
}

int validate_sigma3(unsigned char* group_name, unsigned char* sig_name, unsigned char* digest_name,  X509* root_cert, sigma1_t *m1, sigma2_t* m2, sigma3_t* m3, cert_keypair_t *r, ec_keypair_t *re)
{
    unsigned char *digest_value = NULL;
    unsigned int digest_len;
    const EVP_MD *digest;

    digest = EVP_get_digestbyname(digest_name);
    digest_len = EVP_MD_get_size(digest);
    digest_value = OPENSSL_malloc(digest_len); 

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, digest, NULL);
    EVP_DigestUpdate(mdctx, m1->msg_bin, m1->msg_bin_len);
    EVP_DigestUpdate(mdctx, m2->msg_bin, m2->msg_bin_len);
    EVP_DigestFinal_ex(mdctx, digest_value, &digest_len);

    /*EVP_Digest(msg, msg_len, out, (unsigned int *) out_len_ptr, digest, NULL);*/

    size_t ipk_len = sizeof(IPK);
    unsigned char *salt;
    size_t salt_len = ipk_len + digest_len;
    salt = OPENSSL_malloc(salt_len);
    memcpy(salt, IPK, ipk_len);
    memcpy(salt+digest_len, digest_value, digest_len);

    size_t ss_len; 
    unsigned char* ss = ecdh_raw(re->priv, m1->ie_pub, &ss_len);
    
    unsigned char* s3k;
    size_t s3k_len = hkdf_raw(2, digest_name, ss, ss_len, salt, salt_len, S3K_Info, sizeof(S3K_Info), &s3k, 32);
    
    size_t msg_len;
    unsigned char *msg;
    msg_len = aead_decrypt_raw("aes-256-gcm",m3->ciphertext, m3->ciphertext_len, NULL, 0, m3->tag, m3->tag_len, s3k, TBEData3_Nonce, 13, &msg);

    struct cbor_load_result result;
    cbor_item_t* item = cbor_load(msg, msg_len, &result);

    cbor_item_t* item_icert = cbor_array_get(item, 0);
    size_t item_icert_len = cbor_bytestring_length(item_icert);
    unsigned char* item_icert_bytes = cbor_bytestring_handle(item_icert);
    X509* icert =  read_cert_der(item_icert_bytes, item_icert_len);
    int status = verify_cert(icert, root_cert);
    //printf("\nsigma2 icert verify: %d\n", status);
    EVP_PKEY *ipub = X509_get_pubkey(icert);

    cbor_item_t* item_isig = cbor_array_get(item, 1);
    size_t item_isig_len = cbor_bytestring_length(item_isig);
    unsigned char* item_isig_bytes = cbor_bytestring_handle(item_isig);

    int sigma3_sig_status = sigma_signature_verify(group_name, sig_name, digest_name, ipub, 
            item_isig_bytes, item_isig_len, 
            item_icert_bytes, item_icert_len,
            m1->ie_pub_bin, m1->ie_pub_bin_len, 
            m2->re_pub_bin, m2->re_pub_bin_len
            ); 
    //printf("\nsigma3 sig verify: %d\n", sigma3_sig_status);

    return sigma3_sig_status;
}

session_key_t* derive_session_key(unsigned char* digest_name, EVP_PKEY* priv, EVP_PKEY* peer_pub, sigma1_t* m1, sigma2_t* m2, sigma3_t* m3){
    unsigned char *digest_value = NULL;
    unsigned int digest_len;
    const EVP_MD *digest;

    digest_len = EVP_MD_get_size(digest);
    digest_value = OPENSSL_malloc(digest_len); 

    digest = EVP_get_digestbyname(digest_name);
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex2(mdctx, digest, NULL);
    EVP_DigestUpdate(mdctx, m1->msg_bin, m1->msg_bin_len);
    EVP_DigestUpdate(mdctx, m2->msg_bin, m2->msg_bin_len);
    EVP_DigestUpdate(mdctx, m3->msg_bin, m3->msg_bin_len);
    EVP_DigestFinal_ex(mdctx, digest_value, &digest_len);

    size_t ipk_len = sizeof(IPK);
    unsigned char *salt;
    size_t salt_len = ipk_len + digest_len;
    salt = OPENSSL_malloc(salt_len);
    memcpy(salt, IPK, ipk_len);
    memcpy(salt+digest_len, digest_value, digest_len);

    size_t ss_len; 
    unsigned char* ss = ecdh_raw(priv, peer_pub, &ss_len);

    unsigned char* sk;
    size_t sk_len = hkdf_raw(2, digest_name, ss, ss_len, salt, salt_len, SEKeys_Info, sizeof(SEKeys_Info), &sk, 32*3);

    session_key_t *out = (session_key_t *)malloc(sizeof(session_key_t));
    out->i2r_key = sk;
    out->r2i_key = sk+32;
    out->att_challenge = sk+64;
    out->len = 32;

    return out;
}


/*unsigned char* digest_raw(unsigned char* digest_name, unsigned char* msg, size_t msg_len, size_t *out_len_ptr)*/
/*{*/
    /*unsigned char *out = NULL;*/
    /*const EVP_MD *digest;*/

    /*digest = EVP_get_digestbyname(digest_name);*/
    /**out_len_ptr = EVP_MD_get_size(digest);*/

    /*out = OPENSSL_malloc(*out_len_ptr);*/
    /*EVP_Digest(msg, msg_len, out, (unsigned int *) out_len_ptr, digest, NULL);*/

    /*return out;*/
/*}*/


void main(int argc, char *argv[]){
    double start_time = clock();

    unsigned char *msg;
    size_t msg_len = read_file(argv[1], &msg);

    unsigned char* group_name = "prime256v1";
    unsigned char *digest_name="SHA256";
    unsigned char *sig_name="SHA256";
    unsigned char id_a[]="a";
    unsigned char id_b[]="b";
    double handshake_time;
    double end_time;

    BIO *out_bio;
    out_bio = BIO_new_file(argv[2], "a");
    
    X509* root_cert = read_cert("certs/ca-cert.pem");

    //printf("xa:\n");
    cert_keypair_t* ec_a = read_cert_keypair("certs/client-key.pem", "certs/client-cert.pem");

    //printf("na:\n");
    ec_keypair_t *ec_na = gen_ec_keypair(group_name);

    //printf("xb:\n");
    cert_keypair_t* ec_b = read_cert_keypair("certs/server-key.pem", "certs/server-cert.pem");

    //printf("nb:\n");
    ec_keypair_t *ec_nb = gen_ec_keypair(group_name);

    //printf("\nclient: send sigma1\n");
    sigma1_t* m1 = send_sigma1(id_b, ec_na->pub, ec_na->pub_bin, ec_na->pub_bin_len);

    //printf("\nserver: send sigma2\n");
    sigma2_t* m2 = send_sigma2(group_name, sig_name, digest_name, m1, ec_b, ec_nb);

    //printf("\nclient: validate sigma2, send sigma3, derive_session_key\n");
    int sigma2_sig_status = validate_sigma2(group_name, sig_name, digest_name, root_cert, m1, m2, ec_a, ec_na);
    //printf("\nsigma2 sig verify result: %d\n", sigma2_sig_status);
    sigma3_t *m3 = send_sigma3(group_name, sig_name, digest_name, m1, m2, ec_a, ec_na);
    session_key_t *c_sk = derive_session_key(digest_name, ec_na->priv, ec_nb->pub, m1, m2, m3);

    //printf("\nserver: validate sigma3, derive_session_key\n");
    int sigma3_sig_status = validate_sigma3(group_name, sig_name, digest_name, root_cert, m1, m2, m3, ec_b, ec_nb);
    session_key_t *s_sk = derive_session_key(digest_name, ec_nb->priv, ec_na->pub, m1, m2, m3);

    handshake_time = clock() ;

    //printf("\nclient: encryption\n");
    //printf("iv:\n");
    BIGNUM *iv_bn=BN_new();
    BN_rand(iv_bn, 128, 0, 0);
    unsigned char *iv = OPENSSL_malloc(128);
    int iv_len = BN_bn2bin(iv_bn, iv);
    //BIO_dump_indent_fp(stdout, iv, iv_len, 2);
    unsigned char *ciphertext=NULL;    
    unsigned char *tag=NULL;    
    unsigned char aad[] = "";
    size_t tag_len = 16;
    int ciphertext_len = aead_encrypt_raw("aes-256-gcm", msg, msg_len, aad, strlen(aad), c_sk->i2r_key, iv, iv_len, &ciphertext, &tag, tag_len);
    //BIO_dump_indent_fp(stdout, ciphertext, ciphertext_len, 2);

    /*printf("\nserver: decryption\n");*/
    unsigned char *recv_msg=NULL;
    size_t recv_msg_len;
    recv_msg_len = aead_decrypt_raw("aes-256-gcm",ciphertext, ciphertext_len, aad, strlen(aad), tag, tag_len, s_sk->i2r_key, iv, iv_len, &recv_msg);
    //BIO_dump_indent_fp(stdout, recv_msg, recv_msg_len, 2);

    size_t payload_len = iv_len+tag_len+ciphertext_len;
    size_t handshake_len = m1->msg_bin_len+ m2->msg_bin_len+ m3->msg_bin_len;
    size_t all_len = handshake_len + payload_len;

     end_time = clock();

    double h1 = (double)(handshake_time-start_time) / CLOCKS_PER_SEC;
    double h2 = (double)(end_time-handshake_time) / CLOCKS_PER_SEC;
    double h3 = (double)(end_time-start_time) / CLOCKS_PER_SEC;

    printf("%f,%f,%f,%d,%d,%d,%d,%d,%d\n", h1, h2, h3, m1->msg_bin_len, m2->msg_bin_len, m3->msg_bin_len, payload_len, handshake_len, all_len);
    /*printf("Time:  Done with  h1, h2, h3: %f, %f, %f sd\n", h1, h2, h3); */
    /*printf("Payload: Done with s1, s2, s3, session, handshake_len, all_len: %d, %d, %d, %d, %d, %d\n", m1->msg_bin_len, m2->msg_bin_len, m3->msg_bin_len, payload_len, handshake_len, all_len);*/

}
