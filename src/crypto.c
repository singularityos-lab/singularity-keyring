/*
 * crypto.c - cryptographic primitives for singularity-keyring.
 *
 * Glue around libgcrypt (DH MODP-2048, AES-128-CBC, HKDF-SHA256) for the
 * `dh-ietf` Secret Service transport algorithm, plus libsodium (Argon2id +
 * XChaCha20-Poly1305 secretstream) for on-disk encryption.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <sodium.h>

#define MODP_2048_HEX                                                          \
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"        \
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"        \
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"        \
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"        \
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"        \
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"        \
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"        \
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"

/* Singleton prime/generator init. */
static gcry_mpi_t MODP_PRIME = NULL;
static gcry_mpi_t MODP_GEN   = NULL;

void
sk_crypto_init (void)
{
    if (sodium_init () < 0) {
        fprintf (stderr, "sk_crypto_init: libsodium init failed\n");
        return;
    }
    if (!gcry_check_version (GCRYPT_VERSION)) {
        fprintf (stderr, "sk_crypto_init: libgcrypt version mismatch\n");
        return;
    }
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);
    gcry_control (GCRYCTL_INIT_SECMEM, 65536, 0);
    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    if (MODP_PRIME == NULL) {
        size_t scan = 0;
        gcry_mpi_scan (&MODP_PRIME, GCRYMPI_FMT_HEX,
                       (const unsigned char *) MODP_2048_HEX, 0, &scan);
        MODP_GEN = gcry_mpi_set_ui (NULL, 2);
    }
}

/* Helper: serialise an MPI as fixed-width big-endian bytes (2048 bits = 256). */
static unsigned char *
mpi_to_fixed (gcry_mpi_t mpi, size_t fixed_len, size_t *out_len)
{
    unsigned char *raw = NULL;
    size_t raw_len     = 0;
    if (gcry_mpi_aprint (GCRYMPI_FMT_USG, &raw, &raw_len, mpi) != 0)
        return NULL;

    unsigned char *padded = (unsigned char *) malloc (fixed_len);
    if (!padded) { gcry_free (raw); return NULL; }
    memset (padded, 0, fixed_len);
    if (raw_len <= fixed_len) {
        memcpy (padded + (fixed_len - raw_len), raw, raw_len);
    } else {
        memcpy (padded, raw + (raw_len - fixed_len), fixed_len);
    }
    gcry_free (raw);
    *out_len = fixed_len;
    return padded;
}

/* Generate a DH MODP-2048 keypair. The opaque private handle is returned
 * via out_priv (caller must free with sk_crypto_dh_priv_free). The public
 * key is a 256-byte big-endian representation of g^priv mod p. */
int
sk_crypto_dh_keypair (unsigned char **out_pub_bytes,
                      size_t        *out_pub_len,
                      void          **out_priv)
{
    if (MODP_PRIME == NULL) sk_crypto_init ();

    /* Random 256-bit secret. */
    gcry_mpi_t priv = gcry_mpi_snew (256);
    if (!priv) return -1;
    gcry_mpi_randomize (priv, 256, GCRY_STRONG_RANDOM);

    /* pub = g^priv mod p. */
    gcry_mpi_t pub = gcry_mpi_new (2048);
    if (!pub) { gcry_mpi_release (priv); return -1; }
    gcry_mpi_powm (pub, MODP_GEN, priv, MODP_PRIME);

    unsigned char *pub_bytes = mpi_to_fixed (pub, 256, out_pub_len);
    gcry_mpi_release (pub);

    if (!pub_bytes) { gcry_mpi_release (priv); return -1; }

    *out_pub_bytes = pub_bytes;
    *out_priv      = priv;
    return 0;
}

void
sk_crypto_dh_priv_free (void *priv)
{
    if (priv) gcry_mpi_release ((gcry_mpi_t) priv);
}

int
sk_crypto_dh_shared (const unsigned char *peer_pub,
                     size_t              peer_pub_len,
                     void               *our_priv,
                     unsigned char     **out_shared,
                     size_t             *out_shared_len)
{
    if (!MODP_PRIME || !our_priv || !peer_pub) return -1;

    gcry_mpi_t peer = NULL;
    if (gcry_mpi_scan (&peer, GCRYMPI_FMT_USG, peer_pub, peer_pub_len, NULL) != 0)
        return -1;

    gcry_mpi_t shared = gcry_mpi_new (2048);
    if (!shared) { gcry_mpi_release (peer); return -1; }
    gcry_mpi_powm (shared, peer, (gcry_mpi_t) our_priv, MODP_PRIME);

    *out_shared = mpi_to_fixed (shared, 256, out_shared_len);
    gcry_mpi_release (peer);
    gcry_mpi_release (shared);
    return (*out_shared == NULL) ? -1 : 0;
}

/* HKDF-SHA256-extract with empty salt + empty info, output 16 bytes for
 * AES-128. This matches the Secret Service spec (RFC 5869 extract step
 * with zero-length salt followed by one-block expand). */
int
sk_crypto_hkdf_sha256_aes128 (const unsigned char *ikm,
                              size_t              ikm_len,
                              unsigned char      *out_key /* 16 bytes */)
{
    /* HKDF-Extract: HMAC-SHA256(salt=zero, IKM) */
    unsigned char zero_salt[32] = {0};
    unsigned char prk[32];
    gcry_mac_hd_t hd = NULL;

    if (gcry_mac_open (&hd, GCRY_MAC_HMAC_SHA256, 0, NULL) != 0) return -1;
    if (gcry_mac_setkey (hd, zero_salt, 32) != 0) { gcry_mac_close (hd); return -1; }
    if (gcry_mac_write  (hd, ikm, ikm_len)  != 0) { gcry_mac_close (hd); return -1; }
    size_t prk_len = sizeof (prk);
    if (gcry_mac_read   (hd, prk, &prk_len) != 0) { gcry_mac_close (hd); return -1; }
    gcry_mac_close (hd);

    /* HKDF-Expand single block: T(1) = HMAC-SHA256(PRK, 0x01) */
    unsigned char t1[32];
    unsigned char counter = 0x01;
    if (gcry_mac_open (&hd, GCRY_MAC_HMAC_SHA256, 0, NULL) != 0) return -1;
    if (gcry_mac_setkey (hd, prk, 32) != 0) { gcry_mac_close (hd); return -1; }
    if (gcry_mac_write  (hd, &counter, 1) != 0) { gcry_mac_close (hd); return -1; }
    size_t t1_len = sizeof (t1);
    if (gcry_mac_read   (hd, t1, &t1_len) != 0) { gcry_mac_close (hd); return -1; }
    gcry_mac_close (hd);

    memcpy (out_key, t1, 16);
    return 0;
}

int
sk_crypto_aes128_cbc_enc (const unsigned char *key /* 16 */,
                          const unsigned char *iv  /* 16 */,
                          const unsigned char *pt, size_t pt_len,
                          unsigned char     **out_ct,
                          size_t             *out_ct_len)
{
    /* PKCS#7 pad to block size. */
    size_t pad = 16 - (pt_len % 16);
    size_t padded_len = pt_len + pad;
    unsigned char *padded = (unsigned char *) malloc (padded_len);
    if (!padded) return -1;
    memcpy (padded, pt, pt_len);
    memset (padded + pt_len, (int) pad, pad);

    gcry_cipher_hd_t hd = NULL;
    if (gcry_cipher_open (&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0) != 0) {
        free (padded); return -1;
    }
    if (gcry_cipher_setkey (hd, key, 16) != 0) { gcry_cipher_close (hd); free (padded); return -1; }
    if (gcry_cipher_setiv  (hd, iv,  16) != 0) { gcry_cipher_close (hd); free (padded); return -1; }

    unsigned char *ct = (unsigned char *) malloc (padded_len);
    if (!ct) { gcry_cipher_close (hd); free (padded); return -1; }
    if (gcry_cipher_encrypt (hd, ct, padded_len, padded, padded_len) != 0) {
        gcry_cipher_close (hd); free (padded); free (ct); return -1;
    }
    gcry_cipher_close (hd);
    free (padded);

    *out_ct      = ct;
    *out_ct_len  = padded_len;
    return 0;
}

int
sk_crypto_aes128_cbc_dec (const unsigned char *key /* 16 */,
                          const unsigned char *iv  /* 16 */,
                          const unsigned char *ct, size_t ct_len,
                          unsigned char     **out_pt,
                          size_t             *out_pt_len)
{
    if (ct_len == 0 || (ct_len % 16) != 0) return -1;

    gcry_cipher_hd_t hd = NULL;
    if (gcry_cipher_open (&hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0) != 0)
        return -1;
    if (gcry_cipher_setkey (hd, key, 16) != 0) { gcry_cipher_close (hd); return -1; }
    if (gcry_cipher_setiv  (hd, iv,  16) != 0) { gcry_cipher_close (hd); return -1; }

    unsigned char *padded = (unsigned char *) malloc (ct_len);
    if (!padded) { gcry_cipher_close (hd); return -1; }
    if (gcry_cipher_decrypt (hd, padded, ct_len, ct, ct_len) != 0) {
        gcry_cipher_close (hd); free (padded); return -1;
    }
    gcry_cipher_close (hd);

    unsigned char pad = padded[ct_len - 1];
    if (pad == 0 || pad > 16 || pad > ct_len) { free (padded); return -1; }
    for (size_t i = ct_len - pad; i < ct_len; i++) {
        if (padded[i] != pad) { free (padded); return -1; }
    }

    *out_pt_len = ct_len - pad;
    *out_pt     = padded;
    return 0;
}

/* Argon2id KDF: passphrase -> 32-byte key, salt is 16 bytes. */
int
sk_crypto_argon2id (const char         *passphrase, size_t pp_len,
                    const unsigned char *salt /* 16 */,
                    unsigned char      *out_key /* 32 */)
{
    /* Use libsodium's interactive limits (~64 MiB, ~few seconds). */
    return crypto_pwhash (out_key, 32,
                          passphrase, pp_len,
                          salt,
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE,
                          crypto_pwhash_ALG_ARGON2ID13);
}

/* Single-shot file encryption: header || ciphertext+tag using libsodium's
 * secretstream (XChaCha20-Poly1305). One stream chunk with FINAL tag. */
int
sk_crypto_secretstream_seal (const unsigned char *key /* 32 */,
                             const unsigned char *pt, size_t pt_len,
                             unsigned char     **out_blob,
                             size_t             *out_blob_len)
{
    crypto_secretstream_xchacha20poly1305_state st;
    size_t header_len = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    size_t ct_len     = pt_len + crypto_secretstream_xchacha20poly1305_ABYTES;
    size_t total      = header_len + ct_len;

    unsigned char *blob = (unsigned char *) malloc (total);
    if (!blob) return -1;

    if (crypto_secretstream_xchacha20poly1305_init_push (&st, blob, key) != 0) {
        free (blob); return -1;
    }
    unsigned long long clen = 0;
    if (crypto_secretstream_xchacha20poly1305_push (&st,
            blob + header_len, &clen,
            pt, pt_len, NULL, 0,
            crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0) {
        free (blob); return -1;
    }
    *out_blob     = blob;
    *out_blob_len = header_len + (size_t) clen;
    return 0;
}

int
sk_crypto_secretstream_open (const unsigned char *key /* 32 */,
                             const unsigned char *blob, size_t blob_len,
                             unsigned char     **out_pt,
                             size_t             *out_pt_len)
{
    size_t header_len = crypto_secretstream_xchacha20poly1305_HEADERBYTES;
    if (blob_len < header_len + crypto_secretstream_xchacha20poly1305_ABYTES)
        return -1;

    crypto_secretstream_xchacha20poly1305_state st;
    if (crypto_secretstream_xchacha20poly1305_init_pull (&st, blob, key) != 0)
        return -1;

    size_t ct_len = blob_len - header_len;
    unsigned char *pt = (unsigned char *) malloc (ct_len);
    if (!pt) return -1;
    unsigned long long mlen = 0;
    unsigned char tag = 0;
    if (crypto_secretstream_xchacha20poly1305_pull (&st,
            pt, &mlen, &tag,
            blob + header_len, ct_len, NULL, 0) != 0) {
        free (pt); return -1;
    }
    if (tag != crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
        free (pt); return -1;
    }
    *out_pt     = pt;
    *out_pt_len = (size_t) mlen;
    return 0;
}

void
sk_crypto_random (unsigned char *buf, size_t len)
{
    randombytes_buf (buf, len);
}

void
sk_crypto_free (void *p)
{
    free (p);
}
