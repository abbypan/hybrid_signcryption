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
#include <cbor.h>

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
    unsigned char *iv;
    size_t iv_len;
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
    hkdf_raw(0, digest_name, z, zlen, salt, strlen(salt), info, strlen(info), &okm, okm_len+12);
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

int hybrid_unsigncryption_raw(unsigned char* group_name, unsigned char* digest_name, cert_keypair_t *ec_b, 
ec_keypair_t *ec_nb, 
        EVP_PKEY *ya_pkey, 
EVP_PKEY *na_pkey,
        hybrid_signcryption_t *c, 
        unsigned char* id_a, size_t id_a_len, 
        unsigned char* id_b, size_t id_b_len, 
        unsigned char** msg)
{
    BN_CTX * bnctx= BN_CTX_new();
    int nid = OBJ_sn2nid(group_name);
    EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);


    //printf("yb point:\n");
    //printf("%s\n", ec_b->pub_hex);

    //printf("nb point:\n");
    //printf("%s\n", ec_nb->pub_hex);

    //printf("ya point:\n");
    unsigned char *ya;
    size_t ya_len = EVP_PKEY_get1_encoded_public_key(ya_pkey, &ya);
    unsigned char *ya_hex = bin2hex(ya, ya_len);
    EC_POINT *ya_point = EC_POINT_new(group);
    EC_POINT_hex2point(group, ya_hex, ya_point, bnctx);
    //printf("%s\n", ya_hex);

    //printf("na point:\n");
    unsigned char *na;
    size_t na_len = EVP_PKEY_get1_encoded_public_key(na_pkey, &na);
    unsigned char *na_hex = bin2hex(na, na_len);
    EC_POINT *na_point = EC_POINT_new(group);
    EC_POINT_hex2point(group, na_hex, na_point, bnctx);
    //printf("%s\n", na_hex);

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
    EC_POINT_add(group, z_point, z_point, na_point, bnctx);

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
    size_t info_len = ya_len + ec_b->pub_bin_len +  id_a_len + id_b_len +na_len + ec_nb->pub_bin_len  ;
    info = OPENSSL_malloc(info_len);
    memcpy(info , ya, ya_len);
    memcpy(info + ya_len, ec_b->pub_bin, ec_b->pub_bin_len);
    memcpy(info + ec_b->pub_bin_len + ya_len, id_a, id_a_len);
    memcpy(info + ec_b->pub_bin_len + ya_len + id_a_len, id_b, id_b_len);
    memcpy(info + ec_b->pub_bin_len + ya_len + id_a_len + id_b_len, na, na_len);
    memcpy(info + ec_b->pub_bin_len + ya_len + id_a_len + id_b_len+na_len, ec_nb->pub_bin, ec_nb->pub_bin_len);
    //BIO_dump_indent_fp(stdout, info, info_len, 2);
    //

    //printf("k:\n");
    unsigned char salt[] = "";
    int okm_len = 32;
    unsigned char *okm;
    hkdf_raw(0, digest_name, ikm, ikm_len, salt, strlen(salt), info, info_len, &okm, okm_len+12);
    //BIO_dump_indent_fp(stdout, okm, okm_len, 2);

    //printf("iv:\n");
    //BIO_dump_indent_fp(stdout, okm+okm_len, 12, 2);

    //printf("dec msg:\n");
    size_t msg_len;
    unsigned char aad[] ="";
    /*msg_len = aes_ctr_raw("aes-256-ctr", c->ciphertext, c->ciphertext_len, key, nonce, base_nonce_len, msg, 0);*/
    msg_len = aead_decrypt_raw("aes-256-gcm",c->ciphertext, c->ciphertext_len, aad, strlen(aad), c->tag, c->tag_len, okm, okm+okm_len, 12, msg);
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

hybrid_signcryption_t* hybrid_signcryption_raw(unsigned char* group_name, unsigned char* digest_name, cert_keypair_t *ec_a, ec_keypair_t *ec_na, EVP_PKEY *yb_pkey, EVP_PKEY *nb_pkey,
        unsigned char* id_a, size_t id_a_len, 
        unsigned char* id_b, size_t id_b_len, 
        unsigned char* msg, size_t msg_len)
{
    BN_CTX * bnctx= BN_CTX_new();
    int nid = OBJ_sn2nid(group_name);
    EC_GROUP *group  = EC_GROUP_new_by_curve_name(nid);

    //printf("ya point:\n");
    //printf("%s\n", ec_a->pub_hex);

    //printf("na point:\n");
    //printf("%s\n", ec_na->pub_hex);

    //printf("yb point:\n");
    unsigned char *yb;
    size_t yb_len = EVP_PKEY_get1_encoded_public_key(yb_pkey, &yb);
    unsigned char *yb_hex = bin2hex(yb, yb_len);
    EC_POINT *yb_point = EC_POINT_new(group);
    EC_POINT_hex2point(group, yb_hex, yb_point, bnctx);
    //printf("%s\n", yb_hex);

    //printf("nb point:\n");
    unsigned char *nb;
    size_t nb_len = EVP_PKEY_get1_encoded_public_key(nb_pkey, &nb);
    unsigned char *nb_hex = bin2hex(nb, nb_len);
    EC_POINT *nb_point = EC_POINT_new(group);
    EC_POINT_hex2point(group, nb_hex, nb_point, bnctx);
    //printf("%s\n", nb_hex);

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
    size_t info_len = ec_a->pub_bin_len + yb_len + id_a_len + id_b_len + ec_na->pub_bin_len + nb_len;
    info = OPENSSL_malloc(info_len);
    memcpy(info, ec_a->pub_bin, ec_a->pub_bin_len);
    memcpy(info + ec_a->pub_bin_len, yb, yb_len);
    memcpy(info + ec_a->pub_bin_len + yb_len, id_a, id_a_len);
    memcpy(info + ec_a->pub_bin_len + yb_len + id_a_len, id_b, id_b_len);
    memcpy(info + ec_a->pub_bin_len + yb_len + id_a_len + id_b_len, ec_na->pub_bin, ec_na->pub_bin_len);
    memcpy(info + ec_a->pub_bin_len + yb_len + id_a_len + id_b_len+ ec_na->pub_bin_len, nb, nb_len);
    //BIO_dump_indent_fp(stdout, info, info_len, 2);

    //printf("k:\n");
    unsigned char salt[] = "";
    int okm_len = 32;
    unsigned char *okm;
    hkdf_raw(0, digest_name, ikm, ikm_len, salt, strlen(salt), info, info_len, &okm, okm_len+12);
    //BIO_dump_indent_fp(stdout, okm, okm_len, 2);

    //printf("iv:\n");
    /*BIGNUM *iv_bn=BN_new();*/
    /*BN_rand(iv_bn, 128, 0, 0);*/
    /*unsigned char *iv = OPENSSL_malloc(128);*/
    /*int iv_len = BN_bn2bin(iv_bn, iv);*/
    int iv_len = 12;
    unsigned char *iv = okm + okm_len;
    //BIO_dump_indent_fp(stdout, iv, iv_len, 2);

    //printf("msg:\n");
    //BIO_dump_indent_fp(stdout, msg, msg_len, 2);

    //printf("enc ciphertext:\n");
    unsigned char *ciphertext=NULL;    
    unsigned char *tag=NULL;    
    unsigned char aad[] = "";
    size_t tag_len = 16;
    int ciphertext_len = aead_encrypt_raw("aes-256-gcm", msg, msg_len, aad, strlen(aad), okm, iv, iv_len, &ciphertext, &tag, tag_len);
    //BIO_dump_indent_fp(stdout, ciphertext, ciphertext_len, 2);

    //printf("enc tag:\n");
    //BIO_dump_indent_fp(stdout, tag, tag_len, 2);
    BIGNUM *bn_t = BN_new();
    BN_bin2bn(tag, tag_len, bn_t);

    //printf("ec_a priv:\n");
    BIGNUM *bn_xa = get_pkey_bn_param(ec_a->priv, OSSL_PKEY_PARAM_PRIV_KEY);
    //printf("%s\n", BN_bn2hex(bn_xa));

    //printf("ec_na priv:\n");
    BIGNUM *bn_na = get_pkey_bn_param(ec_na->priv, OSSL_PKEY_PARAM_PRIV_KEY);
    //printf("%s\n", BN_bn2hex(bn_na));

    //printf("s:\n");
    BIGNUM *bn_s = BN_new(); 
    BN_mod_add(bn_s, bn_t, bn_xa, bn_q, bnctx);
    BN_mod_add(bn_s, bn_s, bn_na, bn_q, bnctx);
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
    double start_time = clock();

    unsigned char* group_name = "prime256v1";
    unsigned char *digest_name="SHA256";
    unsigned char *sig_name="SHA256";
    unsigned char *sig_name_sha1="SHA1";
    unsigned char id_a[]="a";
    unsigned char id_b[]="b";
    double m1_time;
    double signcryption_time;
    double unsigncryption_time;
    double all_time;


    unsigned char *msg;
    size_t msg_len = read_file(argv[1], &msg);

    X509* root_cert = read_cert("certs/ca-cert.pem");

    BIO *out_bio;
    out_bio = BIO_new_file(argv[2], "a");

    //printf("xa:\n");
    cert_keypair_t* ec_a = read_cert_keypair("certs/client-key.pem", "certs/client-cert.pem");

    //printf("na:\n");
    ec_keypair_t *ec_na = gen_ec_keypair(group_name);

    //printf("xb:\n");
    cert_keypair_t* ec_b = read_cert_keypair("certs/server-key.pem", "certs/server-cert.pem");

    //printf("nb:\n");
    ec_keypair_t *ec_nb = gen_ec_keypair(group_name);

    //printf("\nhybrid_signcryption_raw\n");


    //msg1: get cert_b, id_b; validate cert_b
    unsigned char* m1;
    size_t m1_size;
    cbor_item_t *item = cbor_new_indefinite_array();
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(ec_b->cert_der, ec_b->cert_der_len)));
    cbor_array_push(
            item, cbor_move(cbor_build_bytestring(id_b, strlen(id_b))));
    cbor_serialize_alloc(item, &m1, &m1_size);
    cbor_decref(&item);
    int verify_receiver_cert_status = verify_cert(ec_b->cert, root_cert);
    //printf("verify receiver cert:%d\n", verify_receiver_cert_status);

    m1_time=clock();

    //msg2: signcryption
    hybrid_signcryption_t* hybrid_sc = hybrid_signcryption_raw(group_name, digest_name, ec_a, ec_na, ec_b->pub, ec_nb->pub,
            id_a, strlen(id_a), 
            id_b, strlen(id_b), 
            msg, msg_len);
    size_t m2_size = hybrid_sc->ciphertext_len + hybrid_sc->tag_len + hybrid_sc->s_len + ec_a->cert_der_len;

    signcryption_time = clock();

    /*printf("\nhybrid_unsigncryption_raw\n");*/
    unsigned char *msg_hybrid;
    size_t msg_hybrid_len;
    msg_hybrid_len = hybrid_unsigncryption_raw(group_name, digest_name, 
            ec_b, ec_nb, ec_a->pub, ec_na->pub, hybrid_sc, 
            id_a, strlen(id_a), 
            id_b, strlen(id_b), 
            &msg_hybrid);

    unsigncryption_time = clock();

    double h1 = (double)(m1_time-start_time) / CLOCKS_PER_SEC;
    double h2 = (double)(signcryption_time-m1_time) / CLOCKS_PER_SEC;
    double h3 = (double)(unsigncryption_time-signcryption_time) / CLOCKS_PER_SEC;
    double h4 = (double)(unsigncryption_time - start_time) / CLOCKS_PER_SEC;

    size_t all_len = m1_size+m2_size;
    printf("%f,%f,%f,%f,%ld,%ld,%ld\n",  h1, h2, h3, h4, m1_size, m2_size, all_len);
    /*printf("Time:  Done with  h1, h2, h3, h4: %f, %f, %f, %f sd\n", h1, h2, h3, h4); */
    /*printf("Payload: Done with m1_len, m2_len, all_len: %ld, %ld, %ld\n", m1_size, m2_size, all_len);*/

    OPENSSL_free(ec_a);
    OPENSSL_free(ec_b);
}
