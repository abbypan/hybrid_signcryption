//https://github.com/kulkarniamit/openssl-evp-demo/blob/master/openssl_evp_demo.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define ERR_EVP_CIPHER_INIT -1
#define ERR_EVP_CIPHER_UPDATE -2
#define ERR_EVP_CIPHER_FINAL -3
#define ERR_EVP_CTX_NEW -4

#define AES_256_KEY_SIZE 32
#define AES_BLOCK_SIZE 16
#define BUFSIZE 1024
#define TAGSIZE 16

typedef struct _cipher_params_t{
    unsigned char *key;
    unsigned char *iv;
    unsigned int encrypt;
    const EVP_CIPHER *cipher_type;
}cipher_params_t;

void cleanup(cipher_params_t *params, FILE *ifp, FILE *ofp, FILE *tag, int rc){
    free(params);
    fclose(ifp);
    fclose(ofp);
    fclose(tag);
    exit(rc);
}

unsigned char* hex2bin(const char* hexstr, size_t* size)
{
    size_t hexstrLen = strlen(hexstr);
    size_t bytesLen = hexstrLen / 2;

    unsigned char* bytes = (unsigned char*) malloc(bytesLen);

    int count = 0;
    const char* pos = hexstr;

    for(count = 0; count < bytesLen; count++) {
        sscanf(pos, "%2hhx", &bytes[count]);
        pos += 2;
    }

    if( size != NULL )
        *size = bytesLen;

    return bytes;
}

char *bin2hex(const unsigned char *bin, size_t len)
{
	char   *out;
	size_t  i;

	if (bin == NULL || len == 0)
		return NULL;

	out = malloc(len*2+1);
	for (i=0; i<len; i++) {
		out[i*2]   = "0123456789ABCDEF"[bin[i] >> 4];
		out[i*2+1] = "0123456789ABCDEF"[bin[i] & 0x0F];
	}
	out[len*2] = '\0';

	return out;
}

void file_encrypt_decrypt(cipher_params_t *params, unsigned char* aad, int aad_len, FILE *ifp, FILE *ofp, FILE *tfp){
    int cipher_block_size = EVP_CIPHER_block_size(params->cipher_type);
    unsigned char in_buf[BUFSIZE], out_buf[BUFSIZE + cipher_block_size];

    int num_bytes_read, out_len;
    EVP_CIPHER_CTX *ctx;
    unsigned char tag[TAGSIZE];

    ctx = EVP_CIPHER_CTX_new();
    if(ctx == NULL){
        fprintf(stderr, "ERROR: EVP_CIPHER_CTX_new failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp, tfp, ERR_EVP_CTX_NEW);
    }

    if(!EVP_CipherInit_ex(ctx, params->cipher_type, NULL, NULL, NULL, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        cleanup(params, ifp, ofp, tfp, ERR_EVP_CIPHER_INIT);
    }

    /*OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == AES_256_KEY_SIZE);*/
    /*OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == AES_BLOCK_SIZE);*/

    if(!EVP_CipherInit_ex(ctx, NULL, NULL, params->key, params->iv, params->encrypt)){
        fprintf(stderr, "ERROR: EVP_CipherInit_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, tfp, ERR_EVP_CIPHER_INIT);
    }

    int len = 0;
    /*fprintf(stdout, "aad %s, aad len: %d\n", aad, aad_len);*/
    if(1 != EVP_CipherUpdate(ctx, NULL, &len, aad, aad_len)){
        fprintf(stderr, "ERROR: EVP_CipherUpdate aad failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
    }

    while(1){
        num_bytes_read = fread(in_buf, sizeof(unsigned char), BUFSIZE, ifp);
        if (ferror(ifp)){
            fprintf(stderr, "ERROR: fread error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, tfp, errno);
        }
        if(!EVP_CipherUpdate(ctx, out_buf, &out_len, in_buf, num_bytes_read)){
            fprintf(stderr, "ERROR: EVP_CipherUpdate failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, tfp, ERR_EVP_CIPHER_UPDATE);
        }
        fwrite(out_buf, sizeof(unsigned char), out_len, ofp);
        if (ferror(ofp)) {
            fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
            EVP_CIPHER_CTX_cleanup(ctx);
            cleanup(params, ifp, ofp, tfp, errno);
        }
        if (num_bytes_read < BUFSIZE) {
            break;
        }
    }

    if(! params->encrypt){
        fread(tag, sizeof(unsigned char), TAGSIZE, tfp);
        /*fprintf(stdout, "tag hexdump: %s,\n", bin2hex(tag, TAGSIZE));*/
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAGSIZE, tag)){
            fprintf(stderr, "ERROR: EVP GCM SET TAG fail. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
    }

    if(!EVP_CipherFinal_ex(ctx, out_buf, &out_len)){
        fprintf(stderr, "ERROR: EVP_CipherFinal_ex failed. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, tfp, ERR_EVP_CIPHER_FINAL);
    }
    fwrite(out_buf, sizeof(unsigned char), out_len, ofp);

    if(params->encrypt){
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAGSIZE, tag)){
            fprintf(stderr, "ERROR: EVP GCM GET TAG fail. OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
        }
        /*fprintf(stdout, "tag hexdump: %s,\n", bin2hex(tag, TAGSIZE));*/
        fwrite(tag, sizeof(unsigned char), TAGSIZE, tfp);
    }

    if (ferror(ofp)) {
        fprintf(stderr, "ERROR: fwrite error: %s\n", strerror(errno));
        EVP_CIPHER_CTX_cleanup(ctx);
        cleanup(params, ifp, ofp, tfp, errno);
    }
    EVP_CIPHER_CTX_cleanup(ctx);
}

int main(int argc, char *argv[]) {
    FILE *f_src, *f_dst, *f_tag;

    if (argc != 8) {
        printf("Usage: %s key iv aad src_file dst_file tag_file is_encrypt\n", argv[0]);
        return -1;
    }

    cipher_params_t *params = (cipher_params_t *)malloc(sizeof(cipher_params_t));
    if (!params) {
        fprintf(stderr, "ERROR: malloc error: %s\n", strerror(errno));
        return errno;
    }

    unsigned char *key = hex2bin(argv[1], NULL);

    unsigned char *iv = hex2bin(argv[2], NULL);

    unsigned char *aad = argv[3];
    int aad_len = strlen(aad);

    params->key = key;
    params->iv = iv;

    params->encrypt = atoi(argv[7]);

    params->cipher_type = EVP_aes_256_gcm();

    f_src = fopen(argv[4], "rb");
    if (!f_src) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    f_dst = fopen(argv[5], "wb");
    if (!f_dst) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }

    if(params->encrypt){
        f_tag = fopen(argv[6], "wb");
    }else{
        f_tag = fopen(argv[6], "rb");
    }
    if (!f_tag) {
        fprintf(stderr, "ERROR: fopen error: %s\n", strerror(errno));
        return errno;
    }


    file_encrypt_decrypt(params, aad, aad_len, f_src, f_dst, f_tag);

    fclose(f_src);
    fclose(f_dst);
    fclose(f_tag);

    free(params);
    free(key);
    free(iv);

    return 0;
}
