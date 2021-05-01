#include <openssl/evp.h>

 EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
 int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx);
 void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);

 int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
 int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       int *outl, const unsigned char *in, int inl);
 int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

 int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                        ENGINE *impl, const unsigned char *key, const unsigned char *iv);
 int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                       int *outl, const unsigned char *in, int inl);
 int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

 int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                       ENGINE *impl, const unsigned char *key, const unsigned char *iv, int enc);
 int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out,
                      int *outl, const unsigned char *in, int inl);
 int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

 int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                     const unsigned char *key, const unsigned char *iv);
 int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

 int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                     const unsigned char *key, const unsigned char *iv);
 int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

 int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                    const unsigned char *key, const unsigned char *iv, int enc);
 int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);

 int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *x, int padding);
 int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);
 int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
 int EVP_CIPHER_CTX_rand_key(EVP_CIPHER_CTX *ctx, unsigned char *key);

 const EVP_CIPHER *EVP_get_cipherbyname(const char *name);
 const EVP_CIPHER *EVP_get_cipherbynid(int nid);
 const EVP_CIPHER *EVP_get_cipherbyobj(const ASN1_OBJECT *a);

 int EVP_CIPHER_nid(const EVP_CIPHER *e);
 int EVP_CIPHER_block_size(const EVP_CIPHER *e);
 int EVP_CIPHER_key_length(const EVP_CIPHER *e);
 int EVP_CIPHER_iv_length(const EVP_CIPHER *e);
 unsigned long EVP_CIPHER_flags(const EVP_CIPHER *e);
 unsigned long EVP_CIPHER_mode(const EVP_CIPHER *e);
 int EVP_CIPHER_type(const EVP_CIPHER *ctx);

 const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);
 int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx);
 int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);
 int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);
 int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);
 void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);
 void EVP_CIPHER_CTX_set_app_data(const EVP_CIPHER_CTX *ctx, void *data);
 int EVP_CIPHER_CTX_type(const EVP_CIPHER_CTX *ctx);
 int EVP_CIPHER_CTX_mode(const EVP_CIPHER_CTX *ctx);

 int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
 int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);
