#ifndef SK_CRYPTO_H
#define SK_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void sk_crypto_init (void);

int  sk_crypto_dh_keypair          (unsigned char **out_pub_bytes,
                                    size_t        *out_pub_len,
                                    void          **out_priv);

void sk_crypto_dh_priv_free        (void *priv);

int  sk_crypto_dh_shared           (const unsigned char *peer_pub,
                                    size_t              peer_pub_len,
                                    void               *our_priv,
                                    unsigned char     **out_shared,
                                    size_t             *out_shared_len);

int  sk_crypto_hkdf_sha256_aes128  (const unsigned char *ikm,
                                    size_t              ikm_len,
                                    unsigned char      *out_key);

int  sk_crypto_aes128_cbc_enc      (const unsigned char *key,
                                    const unsigned char *iv,
                                    const unsigned char *pt, size_t pt_len,
                                    unsigned char     **out_ct,
                                    size_t             *out_ct_len);

int  sk_crypto_aes128_cbc_dec      (const unsigned char *key,
                                    const unsigned char *iv,
                                    const unsigned char *ct, size_t ct_len,
                                    unsigned char     **out_pt,
                                    size_t             *out_pt_len);

int  sk_crypto_argon2id            (const char          *passphrase,
                                    size_t              pp_len,
                                    const unsigned char *salt,
                                    unsigned char      *out_key);

int  sk_crypto_secretstream_seal   (const unsigned char *key,
                                    const unsigned char *pt, size_t pt_len,
                                    unsigned char     **out_blob,
                                    size_t             *out_blob_len);

int  sk_crypto_secretstream_open   (const unsigned char *key,
                                    const unsigned char *blob, size_t blob_len,
                                    unsigned char     **out_pt,
                                    size_t             *out_pt_len);

void sk_crypto_random              (unsigned char *buf, size_t len);

void sk_crypto_free                (void *p);

#ifdef __cplusplus
}
#endif

#endif
