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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct ec_keypair_t {
    EVP_PKEY *priv;
    EVP_PKEY *pub;
    unsigned char *pub_hex;
    unsigned char *pub_bin;
    size_t pub_bin_len;
} ec_keypair_t;


typedef struct hybrid_signcryption_t{
    unsigned char *iv;
    size_t iv_len;
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *tag;
    size_t tag_len;
    unsigned char *s;
    size_t s_len;
} hybrid_signcryption_t;

typedef struct imessage_t{
    unsigned char *iv;
    size_t iv_len;
    unsigned char *c1;
    size_t c1_len;
    unsigned char *c2;
    size_t c2_len;
    unsigned char *sig;
    size_t sig_len;
} imessage_t;

typedef struct hpke_enc_t{
    unsigned char *ye;
    size_t ye_len;
    unsigned char *ciphertext;
    size_t ciphertext_len;
    unsigned char *tag;
    size_t tag_len;
} hpke_enc_t;

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

EVP_PKEY *export_rsa_public_pkey(EVP_PKEY *rsa_priv)
{

    OSSL_LIB_CTX *libctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *rsa_pub = NULL;
    OSSL_PARAM params[3];
    BIGNUM *n = NULL, *e = NULL;
    size_t n_bin_len, e_bin_len;
    unsigned char *n_bin=NULL, *e_bin =NULL;

    EVP_PKEY_get_bn_param(rsa_priv, OSSL_PKEY_PARAM_RSA_N, &n);
    EVP_PKEY_get_bn_param(rsa_priv, OSSL_PKEY_PARAM_RSA_E, &e);

    n_bin_len = BN_num_bytes(n);
    n_bin = OPENSSL_malloc(n_bin_len);
    BN_bn2nativepad(n, n_bin, n_bin_len);

    e_bin_len = BN_num_bytes(e);
    e_bin = OPENSSL_malloc(e_bin_len);
    BN_bn2nativepad(e, e_bin, e_bin_len);

    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, n_bin, n_bin_len);
    params[1] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E, e_bin, e_bin_len);
    params[2] = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL);
    EVP_PKEY_CTX_set_params(ctx, params);

    EVP_PKEY_fromdata_init(ctx);
    EVP_PKEY_fromdata(ctx, &rsa_pub, EVP_PKEY_PUBLIC_KEY, params);

    EVP_PKEY_CTX_free(ctx);
    OSSL_LIB_CTX_free(libctx);
    BN_free(n);
    BN_free(e);
    OPENSSL_free(n_bin);
    OPENSSL_free(e_bin);

    return rsa_pub;
}

size_t rsa_oaep_encrypt(unsigned char *digest_name, EVP_PKEY *pub, unsigned char* in, size_t in_len, unsigned char ** out)
{
    int ret=0;
    OSSL_LIB_CTX *libctx=NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *propq = NULL;
    size_t out_len;

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
    params[1]= OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, digest_name, 0);
    params[2] = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pub, propq);
    EVP_PKEY_encrypt_init_ex(ctx, params);
    EVP_PKEY_encrypt(ctx, NULL, &out_len, in, in_len);
    *out = OPENSSL_zalloc(out_len);

    if( EVP_PKEY_encrypt(ctx, *out, &out_len, in, in_len) <=0 ){
        OPENSSL_free(*out);
        out_len = -1;
    }

    EVP_PKEY_CTX_free(ctx);

    return out_len;
}

size_t rsa_oaep_decrypt(unsigned char *digest_name, EVP_PKEY *priv, unsigned char* in, size_t in_len, unsigned char ** out)
{
    int ret=0;
    OSSL_LIB_CTX *libctx=NULL;
    EVP_PKEY_CTX *ctx = NULL;
    char *propq = NULL;
    size_t out_len;

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, OSSL_PKEY_RSA_PAD_MODE_OAEP, 0);
    params[1]= OSSL_PARAM_construct_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, digest_name, 0);
    params[2] = OSSL_PARAM_construct_end();

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, priv, propq);
    EVP_PKEY_decrypt_init_ex(ctx, params);
    EVP_PKEY_decrypt(ctx, NULL, &out_len, in, in_len);
    *out = OPENSSL_zalloc(out_len);

    if( EVP_PKEY_decrypt(ctx, *out, &out_len, in, in_len) <=0 ){
        OPENSSL_free(*out);
        out_len = -1;
    }

    EVP_PKEY_CTX_free(ctx);

    return out_len;
}

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

imessage_t* imessage_enc_raw(unsigned char* group_name, unsigned char* digest_name, unsigned char* sig_name, ec_keypair_t *ec_a, EVP_PKEY *yb_rsa_pkey, unsigned char* msg, size_t msg_len)
{

    //printf("88-bits L:");
    BIGNUM *L_bn=BN_new();
    BN_rand(L_bn, 88, 0, 0);
    unsigned char *L = OPENSSL_malloc(88);
    int L_len = BN_bn2bin(L_bn, L);
    //BIO_dump_indent_fp(stdout, L, L_len, 2);


    //printf("h_bin:\n");
    unsigned char *yb_bin;
    size_t yb_bin_len = EVP_PKEY_get1_encoded_public_key(yb_rsa_pkey, &yb_bin);
    unsigned char *h_bin;
    size_t h_bin_len = hmac_raw3(digest_name, L, L_len, ec_a->pub_bin, ec_a->pub_bin_len, yb_bin, yb_bin_len, msg, msg_len, &h_bin);
    //BIO_dump_indent_fp(stdout, h_bin, h_bin_len, 2);

    //printf("k:\n");
    unsigned char *k;
    size_t k_len = 16;
    k =OPENSSL_malloc(k_len);
    memcpy(k,  L, L_len);
    memcpy(k + L_len, h_bin, 5);
    //BIO_dump_indent_fp(stdout, k, k_len, 2);

    //printf("iv:\n");
    BIGNUM *iv_bn=BN_new();
    BN_rand(iv_bn, 128, 0, 0);
    unsigned char *iv = OPENSSL_malloc(128);
    int iv_len = BN_bn2bin(iv_bn, iv);
    //BIO_dump_indent_fp(stdout, iv, iv_len, 2);

    //printf("c1:\n");
    unsigned char* c1;
    int c1_len = aes_ctr_raw("aes-128-ctr", msg, msg_len, k, iv, iv_len, &c1, 1);
    //BIO_dump_indent_fp(stdout, c1, c1_len, 2);

    //printf("c2:\n");
    unsigned char *c2;
    size_t c2_len = rsa_oaep_encrypt(digest_name, yb_rsa_pkey, k, k_len, &c2);
    //BIO_dump_indent_fp(stdout, c2, c2_len, 2);

    //printf("s:\n");
    unsigned char *sig;

    const char *propq = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    size_t sig_len = 0;
    /*unsigned char *sig_value = NULL;*/
    EVP_MD_CTX *sign_context = NULL;

    libctx = OSSL_LIB_CTX_new();
    sign_context = EVP_MD_CTX_new();

    EVP_DigestSignInit_ex(sign_context, NULL, sig_name, libctx, NULL, ec_a->priv, NULL); 

    EVP_DigestSignUpdate(sign_context, iv, iv_len); 
    EVP_DigestSignUpdate(sign_context, c1, c1_len); 
    EVP_DigestSignUpdate(sign_context, c2, c2_len); 

    EVP_DigestSignFinal(sign_context, NULL, &sig_len); 

    sig = OPENSSL_malloc(sig_len);

    if (!EVP_DigestSignFinal(sign_context, sig, &sig_len)){ 
        OPENSSL_free(sig);
        sig_len = -1;
    }

    EVP_MD_CTX_free(sign_context);
    OSSL_LIB_CTX_free(libctx);
    //BIO_dump_indent_fp(stdout, sig, sig_len, 2);

    imessage_t *out = (imessage_t *)malloc(sizeof(imessage_t));
    out->iv = iv;
    out->iv_len = iv_len;
    out->c1 = c1;
    out->c1_len = c1_len;
    out->c2 = c2;
    out->c2_len = c2_len;
    out->sig = sig;
    out->sig_len = sig_len;

    OPENSSL_free(L);
    /*OPENSSL_free(yb_bin);*/
    OPENSSL_free(h_bin);
    OPENSSL_free(k);

    return out;
}

int imessage_dec_raw(unsigned char* group_name, unsigned char* digest_name, unsigned char* sig_name, EVP_PKEY *xb_rsa_pkey, EVP_PKEY *ya_pkey, imessage_t *c, unsigned char** msg)
{

    BN_CTX *bnctx = BN_CTX_new();
    int nid = OBJ_sn2nid(group_name);
    EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);

    const char *propq = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    EVP_MD_CTX *verify_context = NULL;
    int ret = 0;

    libctx = OSSL_LIB_CTX_new();
    verify_context = EVP_MD_CTX_new();

    EVP_DigestVerifyInit_ex(verify_context, NULL, sig_name, libctx, NULL, ya_pkey, NULL); 

    EVP_DigestVerifyUpdate(verify_context, c->iv, c->iv_len); 
    EVP_DigestVerifyUpdate(verify_context, c->c1, c->c1_len); 
    EVP_DigestVerifyUpdate(verify_context, c->c2, c->c2_len); 

    if (EVP_DigestVerifyFinal(verify_context, c->sig, c->sig_len)) {
        ret = 1;
    }

    EVP_MD_CTX_free(verify_context);
    OSSL_LIB_CTX_free(libctx);
    OPENSSL_free(bnctx);
    OPENSSL_free(group);

    if(ret!=1)
        return -1;
    //printf("imessage's ecdsa verify: success!\n");

    //printf("rsa dec k :\n");
    unsigned char *k;
    size_t k_len = rsa_oaep_decrypt(digest_name, xb_rsa_pkey, c->c2, c->c2_len, &k);
    //BIO_dump_indent_fp(stdout, k, k_len, 2);
    unsigned char k_tail[5];
    memcpy(k_tail, k+11, 5);

    //printf("dec msg:\n");
    size_t msg_len;
    msg_len = aes_ctr_raw("aes-128-ctr", c->c1, c->c1_len, k, c->iv, c->iv_len, msg, 0);
    //BIO_dump_indent_fp(stdout, *msg, msg_len, 2);

    //printf("h_bin:\n");
    unsigned char *yb_bin;
    size_t yb_bin_len = EVP_PKEY_get1_encoded_public_key(xb_rsa_pkey, &yb_bin);
    unsigned char *ya_bin;
    size_t ya_bin_len = EVP_PKEY_get1_encoded_public_key(ya_pkey, &ya_bin);
    unsigned char *h_bin;
    size_t h_bin_len = hmac_raw3(digest_name, k, 11, ya_bin, ya_bin_len, yb_bin, yb_bin_len, *msg, msg_len, &h_bin);
    //BIO_dump_indent_fp(stdout, h_bin, h_bin_len, 2);
    unsigned char h_head[5];
    memcpy(h_head, h_bin, 5);

    if(memcmp(k_tail, h_head, 5)==0){
        //printf("imessage's hmac verify: success!\n");
    }else{
        msg_len = -1;
        OPENSSL_free(*msg);
    }

    OPENSSL_free(k);
    /*OPENSSL_free(yb_bin);*/
    /*OPENSSL_free(ya_bin);*/
    OPENSSL_free(h_bin);

    return msg_len;
}


hpke_enc_t* hpke_auth_enc_raw(unsigned char* group_name, unsigned char* digest_name, ec_keypair_t *ec_a, unsigned char* yb_hex, unsigned char* msg, size_t msg_len)
{
    unsigned char psk[] = "";
    unsigned char psk_id[] = "";
    unsigned char info[] = "";
    uint64_t seq = 0;

    //printf("xe:\n");
    ec_keypair_t *ec_e = gen_ec_keypair(group_name);

    //printf("yb:%s\n", yb_hex);
    EVP_PKEY *yb_pkey=pubhex2pkey(group_name, yb_hex);
    size_t yb_len;
    unsigned char* yb = OPENSSL_hexstr2buf(yb_hex, &yb_len);

    //printf("z_ER:\n");
    unsigned char *zER;
    size_t zERlen;
    zER = ecdh_raw(ec_e->priv, yb_pkey, &zERlen);
    //BIO_dump_indent_fp(stdout, zER, zERlen, 2);

    //printf("z_SR:\n");
    unsigned char *zSR;
    size_t zSRlen;
    zSR = ecdh_raw(ec_a->priv, yb_pkey, &zSRlen);
    //BIO_dump_indent_fp(stdout, zSR, zSRlen, 2);


    //printf("dh:\n");
    unsigned char *dh;
    size_t dh_len = zERlen + zSRlen;
    dh =OPENSSL_malloc(dh_len);
    memcpy(dh,  zER, zERlen);
    memcpy(dh + zERlen, zSR, zSRlen);
    //BIO_dump_indent_fp(stdout, dh, dh_len, 2);

    //printf("kem_context:\n");
    unsigned char *kem_context;
    size_t kem_context_len = ec_e->pub_bin_len + yb_len + ec_a->pub_bin_len;
    kem_context = OPENSSL_malloc(kem_context_len);
    memcpy(kem_context, ec_e->pub_bin, ec_e->pub_bin_len);
    memcpy(kem_context + ec_e->pub_bin_len, yb, yb_len);
    memcpy(kem_context + ec_e->pub_bin_len + ec_a->pub_bin_len, ec_a->pub_bin, ec_a->pub_bin_len);
    //BIO_dump_indent_fp(stdout, kem_context, kem_context_len, 2);

    //printf("shared_secret:\n");
    int kem_id = 0x0010;
    unsigned char suite_id_kem[] = { 'K', 'E', 'M', kem_id >> 8, kem_id & 0xff };
    unsigned char* shared_secret;
    size_t shared_secret_len = ExtractAndExpand(suite_id_kem, sizeof(suite_id_kem), dh, dh_len, kem_context, kem_context_len, &shared_secret);


    int kdf_id = 1;
    /*int aead_id = 2; //aes-256-gcm*/
    int aead_id = 1; //aes-128-gcm
    unsigned char suite_id[] = { 'H', 'P', 'K', 'E',  
        kem_id >> 8, kem_id & 0xff , 
        kdf_id >> 8, kdf_id & 0xff , 
        aead_id >> 8, aead_id & 0xff , 
    };

    //printf("psk_id_hash:\n");
    unsigned char *psk_id_hash;
    int psk_id_hash_len = LabeledExtract(suite_id, sizeof(suite_id), "", strlen(""), "psk_id_hash", strlen("psk_id_hash"), psk_id, strlen(psk_id), 32, &psk_id_hash);

    //printf("info_hash:\n");
    unsigned char *info_hash;
    int info_hash_len =  LabeledExtract(suite_id, sizeof(suite_id), "", strlen(""), "info_hash", strlen("info_hash"), info, strlen(info), 32, &info_hash);

    //printf("key_schedule_context:\n");
    unsigned char mode[] = { 0x02, };
    unsigned char *key_schedule_context;
    int key_schedule_context_len = sizeof(mode) + psk_id_hash_len + info_hash_len;
    key_schedule_context = OPENSSL_malloc(key_schedule_context_len);
    memcpy(key_schedule_context, mode, sizeof(mode));
    memcpy(key_schedule_context +sizeof(mode), psk_id_hash, psk_id_hash_len);
    memcpy(key_schedule_context +sizeof(mode)+psk_id_hash_len, info_hash, info_hash_len);
    //BIO_dump_indent_fp(stdout, key_schedule_context, key_schedule_context_len, 2);

    //printf("secret:\n");
    unsigned char *secret;
    size_t secret_len = LabeledExtract(suite_id, sizeof(suite_id), shared_secret, shared_secret_len, "secret", strlen("secret"), psk, strlen(psk), 32, &secret);   

    //printf("key:\n");
    unsigned char *key;
    size_t key_len = LabeledExpand(suite_id, sizeof(suite_id), secret, secret_len, "key", strlen("key"), key_schedule_context, key_schedule_context_len, 16, &key);

    //printf("base_nonce:\n");
    unsigned char *base_nonce;
    size_t base_nonce_len =  LabeledExpand(suite_id, sizeof(suite_id), secret, secret_len, "base_nonce", strlen("base_nonce"), key_schedule_context, key_schedule_context_len, 12, &base_nonce);

    //printf("nonce:\n");
    uint8_t *nonce;
    hpke_nonce_xor(12, seq, base_nonce, &nonce);
    //BIO_dump_indent_fp(stdout, nonce, base_nonce_len, 2);

    //printf("msg:\n");
    //BIO_dump_indent_fp(stdout, msg, msg_len, 2);

    //printf("enc ciphertext:\n");
    unsigned char *ciphertext=NULL;    
    unsigned char *tag=NULL;    
    unsigned char aad[] = "";
    size_t tag_len = 16;
    int ciphertext_len = aead_encrypt_raw("aes-128-gcm", msg, msg_len, aad, strlen(aad), key, nonce, base_nonce_len, &ciphertext, &tag, tag_len);
    /*int ciphertext_len = aes_ctr_raw("aes-256-ctr", msg, msg_len, key, nonce,  base_nonce_len, &ciphertext, 1);*/
    //BIO_dump_indent_fp(stdout, ciphertext, ciphertext_len, 2);
    //printf("enc tag:\n");
    //BIO_dump_indent_fp(stdout, tag, tag_len, 2);

    hpke_enc_t *out = (hpke_enc_t *)malloc(sizeof(hpke_enc_t));
    out->ye = ec_e->pub_bin;
    out->ye_len = ec_e->pub_bin_len;
    out->ciphertext = ciphertext;
    out->ciphertext_len = ciphertext_len;
    out->tag = tag;
    out->tag_len = tag_len;

    OPENSSL_free(base_nonce);
    OPENSSL_free(key);
    OPENSSL_free(secret);
    OPENSSL_free(key_schedule_context);
    OPENSSL_free(info_hash);
    OPENSSL_free(psk_id_hash);
    OPENSSL_free(shared_secret);
    OPENSSL_free(kem_context);
    OPENSSL_free(dh);
    OPENSSL_free(zER);
    OPENSSL_free(zSR);
    EVP_PKEY_free(yb_pkey);
    EVP_PKEY_free(ec_e->priv);
    EVP_PKEY_free(ec_e->pub);
    OPENSSL_free(ec_e->pub_hex);

    return out;
}

size_t hpke_auth_dec_raw(unsigned char* group_name, unsigned char* digest_name, EVP_PKEY *xb_pkey, EVP_PKEY *ya_pkey, hpke_enc_t *c, unsigned char** msg)
{
    unsigned char psk[] = "";
    unsigned char psk_id[] = "";
    unsigned char info[] = "";
    uint64_t seq = 0;

    BN_CTX *bnctx = BN_CTX_new();
    int nid = OBJ_sn2nid(group_name);
    EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);

    unsigned char* ye_hex = bin2hex(c->ye, c->ye_len);
    EVP_PKEY *ye_pkey=evp_pkey_from_point_hex(group, ye_hex, bnctx);


    //printf("z_ER:\n");
    unsigned char *zER;
    size_t zERlen;
    zER = ecdh_raw(xb_pkey, ye_pkey, &zERlen);
    //BIO_dump_indent_fp(stdout, zER, zERlen, 2);

    //printf("z_SR:\n");
    unsigned char *zSR;
    size_t zSRlen;
    zSR = ecdh_raw(xb_pkey, ya_pkey, &zSRlen);
    //BIO_dump_indent_fp(stdout, zSR, zSRlen, 2);

    //printf("dh:\n");
    unsigned char *dh;
    size_t dh_len = zERlen + zSRlen;
    dh =OPENSSL_malloc(dh_len);
    memcpy(dh,  zER, zERlen);
    memcpy(dh + zERlen, zSR, zSRlen);
    //BIO_dump_indent_fp(stdout, dh, dh_len, 2);

    //printf("kem_context:\n");
    unsigned char *kem_context;
    unsigned char *yb_bin;
    size_t yb_bin_len = EVP_PKEY_get1_encoded_public_key(xb_pkey, &yb_bin);
    unsigned char *ya_bin;
    size_t ya_bin_len = EVP_PKEY_get1_encoded_public_key(ya_pkey, &ya_bin);
    size_t kem_context_len = c->ye_len + yb_bin_len + ya_bin_len;
    kem_context = OPENSSL_malloc(kem_context_len);
    memcpy(kem_context, c->ye, c->ye_len);
    memcpy(kem_context + c->ye_len, yb_bin, yb_bin_len);
    memcpy(kem_context + c->ye_len + yb_bin_len, ya_bin, ya_bin_len);
    //BIO_dump_indent_fp(stdout, kem_context, kem_context_len, 2);


    //printf("shared_secret:\n");
    int kem_id = 0x0010;
    unsigned char suite_id_kem[] = { 'K', 'E', 'M', kem_id >> 8, kem_id & 0xff };
    unsigned char* shared_secret;
    size_t shared_secret_len = ExtractAndExpand(suite_id_kem, sizeof(suite_id_kem), dh, dh_len, kem_context, kem_context_len, &shared_secret);

    int kdf_id = 1;
    /*int aead_id = 2; //aes-256-gcm*/
    int aead_id = 1; //aes-128-gcm
    unsigned char suite_id[] = { 'H', 'P', 'K', 'E',  
        kem_id >> 8, kem_id & 0xff , 
        kdf_id >> 8, kdf_id & 0xff , 
        aead_id >> 8, aead_id & 0xff , 
    };

    //printf("psk_id_hash:\n");
    unsigned char *psk_id_hash;
    int psk_id_hash_len = LabeledExtract(suite_id, sizeof(suite_id), "", strlen(""), "psk_id_hash", strlen("psk_id_hash"), psk_id, strlen(psk_id), 32, &psk_id_hash);

    //printf("info_hash:\n");
    unsigned char *info_hash;
    int info_hash_len =  LabeledExtract(suite_id, sizeof(suite_id), "", strlen(""), "info_hash", strlen("info_hash"), info, strlen(info), 32, &info_hash);

    //printf("key_schedule_context:\n");
    unsigned char mode[] = { 0x02, };
    unsigned char *key_schedule_context;
    int key_schedule_context_len = sizeof(mode) + psk_id_hash_len + info_hash_len;
    key_schedule_context = OPENSSL_malloc(key_schedule_context_len);
    memcpy(key_schedule_context, mode, sizeof(mode));
    memcpy(key_schedule_context +sizeof(mode), psk_id_hash, psk_id_hash_len);
    memcpy(key_schedule_context +sizeof(mode)+psk_id_hash_len, info_hash, info_hash_len);
    //BIO_dump_indent_fp(stdout, key_schedule_context, key_schedule_context_len, 2);

    //printf("secret:\n");
    unsigned char *secret;
    size_t secret_len = LabeledExtract(suite_id, sizeof(suite_id), shared_secret, shared_secret_len, "secret", strlen("secret"), psk, strlen(psk), 32, &secret);   

    //printf("key:\n");
    unsigned char *key;
    size_t key_len = LabeledExpand(suite_id, sizeof(suite_id), secret, secret_len, "key", strlen("key"), key_schedule_context, key_schedule_context_len, 16, &key);

    //printf("base_nonce:\n");
    unsigned char *base_nonce;
    size_t base_nonce_len =  LabeledExpand(suite_id, sizeof(suite_id), secret, secret_len, "base_nonce", strlen("base_nonce"), key_schedule_context, key_schedule_context_len, 12, &base_nonce);

    //printf("nonce:\n");
    uint8_t *nonce;
    hpke_nonce_xor(12, seq, base_nonce, &nonce);
    //BIO_dump_indent_fp(stdout, nonce, base_nonce_len, 2);

    //printf("ciphertext:\n");
    //BIO_dump_indent_fp(stdout, c->ciphertext, c->ciphertext_len, 2);

    //printf("tag:\n");
    //BIO_dump_indent_fp(stdout, c->tag, c->tag_len, 2);

    //printf("dec msg:\n");
    size_t msg_len;
    unsigned char aad[] ="";
    /*msg_len = aes_ctr_raw("aes-256-ctr", c->ciphertext, c->ciphertext_len, key, nonce, base_nonce_len, msg, 0);*/
    msg_len = aead_decrypt_raw("aes-128-gcm",c->ciphertext, c->ciphertext_len, aad, strlen(aad), c->tag, c->tag_len, key, nonce, base_nonce_len, msg);
    //BIO_dump_indent_fp(stdout, *msg, msg_len, 2);


    OPENSSL_free(bnctx);
    OPENSSL_free(group);
    OPENSSL_free(ye_pkey);
    OPENSSL_free(zER);
    OPENSSL_free(zSR);
    OPENSSL_free(dh);
    OPENSSL_free(base_nonce);
    OPENSSL_free(key);
    OPENSSL_free(secret);
    OPENSSL_free(key_schedule_context);
    OPENSSL_free(info_hash);
    OPENSSL_free(psk_id_hash);
    OPENSSL_free(shared_secret);
    OPENSSL_free(kem_context);

    return msg_len;
}

ecies_encrypt_t * ecies_encrpyt_raw(unsigned char* group_name, unsigned char* digest_name, EVP_PKEY *yb_pkey, unsigned char* msg, size_t msg_len)
{

    unsigned char salt[] = "";
    unsigned char info[] = "";
    unsigned int  okm_len = 16;

    //printf("xe:\n");
    ec_keypair_t *ec_e = gen_ec_keypair(group_name);

    /*printf("yb:%s\n", yb_hex);*/
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
    int ciphertext_len = aes_ctr_raw("aes-128-ctr", msg, msg_len, okm, iv, iv_len, &ciphertext, 1);
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
    msg_len = aes_ctr_raw("aes-128-ctr", c->ciphertext, c->ciphertext_len, okm, c->iv, c->iv_len, msg, 0);
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


int ecies_signature_dec_raw(unsigned char* group_name, unsigned char* sig_name, EVP_PKEY *xb_pkey, unsigned char* digest_name, EVP_PKEY *ya_pkey, ecies_signature_t *ec, unsigned char** msg)
{


    /*BN_CTX *bnctx = BN_CTX_new();*/
    /*int nid = OBJ_sn2nid(group_name);*/
    /*EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);*/

    /*EVP_PKEY *ya_pkey=evp_pkey_from_point_hex(group, ya_hex, bnctx);*/

    const char *propq = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    /*unsigned char *sig_value = NULL;*/
    EVP_MD_CTX *verify_context = NULL;
    int ret = 0;

    libctx = OSSL_LIB_CTX_new();
    verify_context = EVP_MD_CTX_new();

    EVP_DigestVerifyInit_ex(verify_context, NULL, sig_name, libctx, NULL, ya_pkey, NULL); 

    ecies_encrypt_t *c = ec->c;
    EVP_DigestVerifyUpdate(verify_context, c->ye, c->ye_len); 
    EVP_DigestVerifyUpdate(verify_context, c->iv, c->iv_len); 
    EVP_DigestVerifyUpdate(verify_context, c->ciphertext, c->ciphertext_len); 

    if (EVP_DigestVerifyFinal(verify_context, ec->sig, ec->sig_len)) {
        ret = 1;
    }

    EVP_MD_CTX_free(verify_context);
    OSSL_LIB_CTX_free(libctx);
    /*OPENSSL_free(bnctx);*/
    /*OPENSSL_free(group);*/
    /*OPENSSL_free(ya_pkey);*/

    if(ret!=1)
        return -1;
    //printf("ecies's ecdsa verify: success!\n");

    int msg_len =    ecies_decrypt_raw(group_name, digest_name, xb_pkey, c, msg);
    return msg_len;
}

ecies_signature_t * ecies_signature_enc_raw(unsigned char* group_name, unsigned char* sig_name, EVP_PKEY *xa_pkey, unsigned char* digest_name, EVP_PKEY *yb_pkey, unsigned char* msg, size_t msg_len)
{

    ecies_signature_t *out = (ecies_signature_t *)malloc(sizeof(ecies_signature_t));

    ecies_encrypt_t *c = ecies_encrpyt_raw(group_name, digest_name, yb_pkey, msg, msg_len);
    out->c = c;

    unsigned char *sig;

    const char *propq = NULL;
    OSSL_LIB_CTX *libctx = NULL;
    size_t sig_len = 0;
    /*unsigned char *sig_value = NULL;*/
    EVP_MD_CTX *sign_context = NULL;

    libctx = OSSL_LIB_CTX_new();
    sign_context = EVP_MD_CTX_new();

    EVP_DigestSignInit_ex(sign_context, NULL, sig_name, libctx, NULL, xa_pkey, NULL); 

    EVP_DigestSignUpdate(sign_context, c->ye, c->ye_len); 
    EVP_DigestSignUpdate(sign_context, c->iv, c->iv_len); 
    EVP_DigestSignUpdate(sign_context, c->ciphertext, c->ciphertext_len); 

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

int hybrid_unsigncryption_raw(unsigned char* group_name, unsigned char* digest_name, ec_keypair_t *ec_b, EVP_PKEY *ya_pkey, hybrid_signcryption_t *c, 
        unsigned char* id_a, size_t id_a_len, 
        unsigned char* id_b, size_t id_b_len, 
        unsigned char* psk, size_t psk_len, 
        unsigned char** msg)
{
    BN_CTX * bnctx= BN_CTX_new();
    int nid = OBJ_sn2nid(group_name);
    EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);


    //printf("yb point:\n");
    //printf("%s\n", ec_b->pub_hex);

    //printf("ya point:\n");
    unsigned char *ya;
    size_t ya_len = EVP_PKEY_get1_encoded_public_key(ya_pkey, &ya);

    unsigned char *ya_hex = bin2hex(ya, ya_len);

    EC_POINT *ya_point = EC_POINT_new(group);
    EC_POINT_hex2point(group, ya_hex, ya_point, bnctx);

    //printf("%s\n", ya_hex);

    //printf("order:\n");
    BIGNUM *bn_q = get_pkey_bn_param(ec_b->priv,OSSL_PKEY_PARAM_EC_ORDER); 
    //printf("%s\n", BN_bn2hex(bn_q));

    //printf("ec_b priv:\n");
    BIGNUM *bn_xb = get_pkey_bn_param(ec_b->priv, OSSL_PKEY_PARAM_PRIV_KEY);
    //printf("%s\n", BN_bn2hex(bn_xb));

    //printf("z point:\n");
    BIGNUM *bn_t = BN_new();
    BN_bin2bn(c->tag, c->tag_len, bn_t);
    BN_mod(bn_t, bn_t, bn_q, bnctx);

    BIGNUM *bn_one = BN_new();
    BN_one(bn_one);


    EC_POINT *z_point = EC_POINT_new(group);
    EC_POINT_mul(group, z_point, bn_t, ya_point, bn_one, bnctx);

    BIGNUM *bn_s = BN_new();
    BN_bin2bn(c->s, c->s_len, bn_s);
    BIGNUM *bn_v = BN_new();
    BN_mod_mul(bn_v, bn_s, bn_xb, bn_q, bnctx);
    EC_POINT_mul(group, z_point, NULL, z_point, bn_v, bnctx);

    char *z_hex = EC_POINT_point2hex(group, z_point, 4, bnctx);
    //printf("%s\n", z_hex);

    //printf("ikm:\n");
    size_t ikm_len;
    unsigned char* ikm = digest_raw(digest_name, z_hex, strlen(z_hex), &ikm_len);
    //BIO_dump_indent_fp(stdout, ikm, ikm_len, 2);

    //printf("info:\n");
    unsigned char* info;
    size_t info_len = ya_len + ec_b->pub_bin_len +  id_a_len + id_b_len + psk_len;
    info = OPENSSL_malloc(info_len);
    memcpy(info , ya, ya_len);
    memcpy(info + ya_len, ec_b->pub_bin, ec_b->pub_bin_len);
    memcpy(info + ec_b->pub_bin_len + ya_len, id_a, id_a_len);
    memcpy(info + ec_b->pub_bin_len + ya_len + id_a_len, id_b, id_b_len);
    memcpy(info + ec_b->pub_bin_len + ya_len + id_a_len + id_b_len, psk, psk_len);
    //BIO_dump_indent_fp(stdout, info, info_len, 2);
    //

    //printf("k:\n");
    unsigned char salt[] = "";
    int okm_len = 16;
    unsigned char *okm;
    hkdf_raw(0, digest_name, ikm, ikm_len, salt, strlen(salt), info, info_len, &okm, okm_len);
    //BIO_dump_indent_fp(stdout, okm, okm_len, 2);

    //printf("iv:\n");
    //BIO_dump_indent_fp(stdout, c->iv, c->iv_len, 2);

    //printf("dec msg:\n");
    size_t msg_len;
    unsigned char aad[] ="";
    /*msg_len = aes_ctr_raw("aes-256-ctr", c->ciphertext, c->ciphertext_len, key, nonce, base_nonce_len, msg, 0);*/
    msg_len = aead_decrypt_raw("aes-128-gcm",c->ciphertext, c->ciphertext_len, aad, strlen(aad), c->tag, c->tag_len, okm, c->iv, c->iv_len, msg);
    //BIO_dump_indent_fp(stdout, *msg, msg_len, 2);

    EC_GROUP_free(group); 
    BN_CTX_free(bnctx);
    OPENSSL_free(ya);
    OPENSSL_free(ya_hex);
    EC_POINT_free(ya_point);
    EC_POINT_free(z_point);
    BN_free(bn_q);
    BN_free(bn_xb);
    BN_free(bn_t);
    BN_free(bn_v);
    BN_free(bn_s);
    BN_free(bn_one);
    OPENSSL_free(z_hex);
    OPENSSL_free(ikm);
    OPENSSL_free(okm);
    OPENSSL_free(info);

    return msg_len;
}

hybrid_signcryption_t* hybrid_signcryption_raw(unsigned char* group_name, unsigned char* digest_name, ec_keypair_t *ec_a, EVP_PKEY *yb_pkey, 
        unsigned char* id_a, size_t id_a_len, 
        unsigned char* id_b, size_t id_b_len, 
        unsigned char* psk, size_t psk_len, 
        unsigned char* msg, size_t msg_len)
{
    BN_CTX * bnctx= BN_CTX_new();
    int nid = OBJ_sn2nid(group_name);
    EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);

    //printf("ya point:\n");
    //printf("%s\n", ec_a->pub_hex);

    //printf("yb point:\n");
    unsigned char *yb;
    size_t yb_len = EVP_PKEY_get1_encoded_public_key(yb_pkey, &yb);


    unsigned char *yb_hex = bin2hex(yb, yb_len);

    EC_POINT *yb_point = EC_POINT_new(group);
    EC_POINT_hex2point(group, yb_hex, yb_point, bnctx);

    //printf("%s\n", yb_hex);

    //printf("order:\n");
    BIGNUM *bn_q = get_pkey_bn_param(ec_a->priv,OSSL_PKEY_PARAM_EC_ORDER); 
    //printf("%s\n", BN_bn2hex(bn_q));

    //printf("r:\n");
    BIGNUM *bn_r = BN_new();
    while(1){
        BN_rand_range(bn_r, bn_q);
        if(BN_is_one(bn_r)==0 && BN_is_zero(bn_r)==0)
            break;
    }
    //printf("%s\n", BN_bn2hex(bn_r));

    //printf("z point:\n");
    EC_POINT *z_point = EC_POINT_new(group);
    EC_POINT_mul(group, z_point, NULL, yb_point, bn_r, bnctx);
    char *z_hex = EC_POINT_point2hex(group, z_point, 4, bnctx);
    //printf("%s\n", z_hex);

    //printf("ikm:\n");
    size_t ikm_len;
    unsigned char* ikm = digest_raw(digest_name, z_hex, strlen(z_hex), &ikm_len);
    //BIO_dump_indent_fp(stdout, ikm, ikm_len, 2);

    //printf("info:\n");
    unsigned char* info;
    size_t info_len = ec_a->pub_bin_len + yb_len + id_a_len + id_b_len + psk_len;
    info = OPENSSL_malloc(info_len);
    memcpy(info, ec_a->pub_bin, ec_a->pub_bin_len);
    memcpy(info + ec_a->pub_bin_len, yb, yb_len);
    memcpy(info + ec_a->pub_bin_len + yb_len, id_a, id_a_len);
    memcpy(info + ec_a->pub_bin_len + yb_len + id_a_len, id_b, id_b_len);
    memcpy(info + ec_a->pub_bin_len + yb_len + id_a_len + id_b_len, psk, psk_len);
    //BIO_dump_indent_fp(stdout, info, info_len, 2);

    //printf("k:\n");
    unsigned char salt[] = "";
    int okm_len = 16;
    unsigned char *okm;
    hkdf_raw(0, digest_name, ikm, ikm_len, salt, strlen(salt), info, info_len, &okm, okm_len);
    //BIO_dump_indent_fp(stdout, okm, okm_len, 2);

    //printf("iv:\n");
    BIGNUM *iv_bn=BN_new();
    BN_rand(iv_bn, 128, 0, 0);
    unsigned char *iv = OPENSSL_malloc(128);
    int iv_len = BN_bn2bin(iv_bn, iv);
    //BIO_dump_indent_fp(stdout, iv, iv_len, 2);

    //printf("msg:\n");
    //BIO_dump_indent_fp(stdout, msg, msg_len, 2);

    //printf("enc ciphertext:\n");
    unsigned char *ciphertext=NULL;    
    unsigned char *tag=NULL;    
    unsigned char aad[] = "";
    size_t tag_len = 16;
    int ciphertext_len = aead_encrypt_raw("aes-128-gcm", msg, msg_len, aad, strlen(aad), okm, iv, iv_len, &ciphertext, &tag, tag_len);
    //BIO_dump_indent_fp(stdout, ciphertext, ciphertext_len, 2);

    //printf("enc tag:\n");
    //BIO_dump_indent_fp(stdout, tag, tag_len, 2);
    BIGNUM *bn_t = BN_new();
    BN_bin2bn(tag, tag_len, bn_t);

    //printf("ec_a priv:\n");
    BIGNUM *bn_xa = get_pkey_bn_param(ec_a->priv, OSSL_PKEY_PARAM_PRIV_KEY);
    //printf("%s\n", BN_bn2hex(bn_xa));

    //printf("s:\n");
    BIGNUM *bn_s = BN_new(); 
    BN_mod_add(bn_s, bn_t, bn_xa, bn_q, bnctx);
    BN_mod_inverse(bn_s, bn_s, bn_q, bnctx);
    BN_mod_mul(bn_s, bn_r, bn_s, bn_q, bnctx);
    size_t s_bin_len = BN_num_bytes(bn_s);
    unsigned char* s_bin = OPENSSL_malloc(s_bin_len);
    BN_bn2bin(bn_s, s_bin);
    //printf("%s\n", BN_bn2hex(bn_s));
    /*BN_print(stdout, bn_s);*/

    hybrid_signcryption_t *out = (hybrid_signcryption_t *)malloc(sizeof(hybrid_signcryption_t));
    out->iv = iv;
    out->iv_len = iv_len;
    out->tag = tag;
    out->tag_len = tag_len;
    out->ciphertext = ciphertext;
    out->ciphertext_len = ciphertext_len;
    out->s = s_bin;
    out->s_len = s_bin_len;

    EC_GROUP_free(group); 
    BN_CTX_free(bnctx);
    OPENSSL_free(yb);
    OPENSSL_free(yb_hex);
    EC_POINT_free(yb_point);
    BN_free(bn_q);
    BN_free(bn_r);
    BN_free(bn_t);
    BN_free(bn_xa);
    BN_free(bn_s);
    EC_POINT_free(z_point);
    OPENSSL_free(z_hex);
    OPENSSL_free(ikm);
    OPENSSL_free(okm);
    OPENSSL_free(info);

    return out;
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

void main(int argc, char *argv[]){

    /*unsigned char msg[]= "justfortest666xxxyyyzzz";*/
    /*size_t msg_len = strlen(msg);*/
    unsigned char *msg;
    size_t msg_len = read_file(argv[1], &msg);

    unsigned char* group_name = "prime256v1";
    unsigned char *digest_name="SHA256";
    unsigned char *sig_name="SHA256";
    unsigned char *sig_name_sha1="SHA1";
    unsigned char psk[] = "";
    unsigned char psk_id[] = "";
    unsigned char id_a[]="a";
    unsigned char id_b[]="b";

    BIO *out_bio;
    out_bio = BIO_new_file(argv[2], "a");

    //printf("xa:\n");
    ec_keypair_t *ec_a = gen_ec_keypair(group_name);

    //printf("xb:\n");
    ec_keypair_t *ec_b = gen_ec_keypair(group_name);

    //printf("rsa private:\n");
    EVP_PKEY *rsa_xb = EVP_RSA_gen(1024);
    //    PEM_write_PrivateKey(stdout,  rsa_xb, NULL, NULL, 0, NULL, NULL);

    //printf("rsa public:\n");
    EVP_PKEY *rsa_yb = export_rsa_public_pkey(rsa_xb);
    //    PEM_write_PUBKEY(stdout,  rsa_yb);

    clock_t start_time = clock();
    //printf("\necies_signature_enc_raw:\n");
    ecies_signature_t *ec = ecies_signature_enc_raw(group_name, sig_name, ec_a->priv, digest_name, ec_b->pub, msg, msg_len);
    double elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    size_t all_len = ec->sig_len + ec->c->ye_len + ec->c->iv_len + ec->c->ciphertext_len;

    start_time = clock();
    //printf("\necies_signature_dec_raw:\n");
    unsigned char *msg_ec;
    size_t msg_ec_len;
    msg_ec_len = ecies_signature_dec_raw(group_name, sig_name, ec_b->priv, digest_name, ec_a->pub, ec, &msg_ec);
    double elapsed_time2 = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    //printf("Default:  Done with  %f sd\n", elapsed_time2);
    BIO_printf(out_bio, "ecies_signature,%d,%f,%f,%d,%d,%d,%d,%d,%d,%d\n", msg_len, elapsed_time, elapsed_time2, all_len, ec->c->iv_len, ec->c->ciphertext_len, 0, ec->sig_len, 0, ec->c->ye_len );

    start_time = clock();
    //printf("\nhpke_auth_enc_raw:\n");
    hpke_enc_t *hpke = hpke_auth_enc_raw(group_name, digest_name, ec_a, ec_b->pub_hex, msg, msg_len);
    elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    //printf("Default:  Done with  %f sd\n", elapsed_time);

    all_len = hpke->tag_len + hpke->ye_len + hpke->ciphertext_len;

    start_time = clock();
    //printf("\nhpke_auth_dec_raw:\n");
    unsigned char *msg_hpke;
    size_t msg_hpke_len;
    msg_hpke_len = hpke_auth_dec_raw(group_name, digest_name, ec_b->priv, ec_a->pub, hpke, &msg_hpke);
    elapsed_time2 = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    //printf("Default:  Done with  %f sd\n", elapsed_time2);
    BIO_printf(out_bio, "hpke_auth,%d,%f,%f,%d,%d,%d,%d,%d,%d,%d\n", msg_len, elapsed_time, elapsed_time2, all_len, 0,  hpke->ciphertext_len, hpke->tag_len, 0, 0, hpke->ye_len );

    start_time = clock();
    //printf("\nimessage_enc_raw\n");
    imessage_t* imsg = imessage_enc_raw(group_name, digest_name, sig_name_sha1, ec_a, rsa_yb, msg, msg_len);
    elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    //printf("Default:  Done with  %f sd\n", elapsed_time);


    all_len = imsg->iv_len + imsg->c1_len + imsg->c2_len + imsg->sig_len;

    start_time = clock();
    //printf("\nimessage_dec_raw:\n");
    unsigned char *msg_imsg;
    size_t msg_imsg_len;
    msg_imsg_len = imessage_dec_raw(group_name, digest_name, sig_name_sha1, rsa_xb, ec_a->pub, imsg, &msg_imsg);
    elapsed_time2 = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    //printf("Default:  Done with  %f sd\n", elapsed_time2);
    BIO_printf(out_bio, "imessage,%d,%f,%f,%d,%d,%d,%d,%d,%d,%d\n", msg_len, elapsed_time, elapsed_time2, all_len, imsg->iv_len, imsg->c1_len, 0, imsg->sig_len, imsg->c2_len, 0 );

    start_time = clock();
    //printf("\nhybrid_signcryption_raw\n");
    hybrid_signcryption_t* hybrid_sc = hybrid_signcryption_raw(group_name, digest_name, ec_a, ec_b->pub, 
            id_a, strlen(id_a), 
            id_b, strlen(id_b), 
            psk, strlen(psk), 
            msg, msg_len);
    elapsed_time = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    //printf("Default:  Done with  %f sd\n", elapsed_time);

    all_len = hybrid_sc->iv_len + hybrid_sc->ciphertext_len + hybrid_sc->tag_len + hybrid_sc->s_len;

    start_time = clock();
    //printf("\nhybrid_unsigncryption_raw\n");
    unsigned char *msg_hybrid;
    size_t msg_hybrid_len;
    msg_hybrid_len = hybrid_unsigncryption_raw(group_name, digest_name, 
            ec_b, ec_a->pub, hybrid_sc, 
            id_a, strlen(id_a), 
            id_b, strlen(id_b), 
            psk, strlen(psk), 
            &msg_hybrid);
    elapsed_time2 = (double)(clock() - start_time) / CLOCKS_PER_SEC;
    //printf("Default:  Done with  %f sd\n", elapsed_time2);
    //type,msg_len,enc_elapsed_time_sd, dec_elapsed_time_sd, all_len, iv_len, ciphertext_len, tag_len, sig_len, c2_len, e_len
    BIO_printf(out_bio, "hybrid_signcryption,%d,%f,%f,%d,%d,%d,%d,%d,%d,%d\n", msg_len, elapsed_time, elapsed_time2, all_len, hybrid_sc->iv_len, hybrid_sc->ciphertext_len, hybrid_sc->tag_len, hybrid_sc->s_len, 0, 0 );


    OPENSSL_free(ec_a);
    OPENSSL_free(ec_b);
}


