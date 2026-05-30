/* Vala bindings for crypto.c. Kept narrow on purpose: only what the
   keyring needs. All raw pointer output buffers are owned by the caller
   and must be released via sk_crypto_free(). */

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_init")]
public extern void sk_crypto_init ();

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_dh_keypair")]
public extern int sk_crypto_dh_keypair (out uint8 *out_pub_bytes, out size_t out_pub_len, out void *out_priv);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_dh_priv_free")]
public extern void sk_crypto_dh_priv_free (void *priv);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_dh_shared")]
public extern int sk_crypto_dh_shared ([CCode (array_length = false)] uint8[] peer_pub, size_t peer_pub_len, void *our_priv, out uint8 *out_shared, out size_t out_shared_len);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_hkdf_sha256_aes128")]
public extern int sk_crypto_hkdf_sha256_aes128 ([CCode (array_length = false)] uint8[] ikm, size_t ikm_len, [CCode (array_length = false)] uint8[] out_key);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_aes128_cbc_enc")]
public extern int sk_crypto_aes128_cbc_enc ([CCode (array_length = false)] uint8[] key, [CCode (array_length = false)] uint8[] iv, [CCode (array_length = false)] uint8[] pt, size_t pt_len, out uint8 *out_ct, out size_t out_ct_len);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_aes128_cbc_dec")]
public extern int sk_crypto_aes128_cbc_dec ([CCode (array_length = false)] uint8[] key, [CCode (array_length = false)] uint8[] iv, [CCode (array_length = false)] uint8[] ct, size_t ct_len, out uint8 *out_pt, out size_t out_pt_len);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_argon2id")]
public extern int sk_crypto_argon2id (string passphrase, size_t pp_len, [CCode (array_length = false)] uint8[] salt, [CCode (array_length = false)] uint8[] out_key);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_secretstream_seal")]
public extern int sk_crypto_secretstream_seal ([CCode (array_length = false)] uint8[] key, [CCode (array_length = false)] uint8[] pt, size_t pt_len, out uint8 *out_blob, out size_t out_blob_len);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_secretstream_open")]
public extern int sk_crypto_secretstream_open ([CCode (array_length = false)] uint8[] key, [CCode (array_length = false)] uint8[] blob, size_t blob_len, out uint8 *out_pt, out size_t out_pt_len);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_random")]
public extern void sk_crypto_random ([CCode (array_length = false)] uint8[] buf, size_t len);

[CCode (cheader_filename = "crypto.h", cname = "sk_crypto_free")]
public extern void sk_crypto_free (void *p);
