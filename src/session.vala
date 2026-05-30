// session.vala - org.freedesktop.Secret.Session DBus object.
//
// Two transports are supported:
//   "plain"   - no encryption, parameters always empty, value is raw.
//   "dh-ietf" - Diffie-Hellman over RFC 3526 group 14 (MODP-2048) shared
//               with HKDF-SHA256 to produce a 16-byte key; per-secret IV
//               is sent as the parameters field; AES-128-CBC with PKCS#7
//               padding.

using GLib;

namespace Singularity.Keyring {

    [DBus (name = "org.freedesktop.Secret.Session")]
    public class SecretSession : Object {

        public enum Algorithm { PLAIN, DH_IETF }

        private string    _path;
        private Algorithm _algo;
        private uint8[]?  _aes_key = null;

        internal signal void session_closed ();

        public SecretSession.plain (string path) {
            _path = path;
            _algo = Algorithm.PLAIN;
        }

        public SecretSession.dh_ietf (string path, uint8[] aes_key) {
            _path    = path;
            _algo    = Algorithm.DH_IETF;
            _aes_key = aes_key;
        }

        public string get_path () { return _path; }
        public Algorithm algorithm { get { return _algo; } }

        public void close () throws GLib.Error {
            session_closed ();
        }

        public void wrap (uint8[] plain,
                          string  content_type,
                          out uint8[] out_params,
                          out uint8[] out_value,
                          out string  out_content_type) throws Error {
            out_content_type = content_type;
            if (_algo == Algorithm.PLAIN) {
                out_params = new uint8[0];
                out_value  = plain;
                return;
            }
            uint8[] iv = new uint8[16];
            sk_crypto_random (iv, 16);
            uint8 *ct = null;
            size_t ct_len = 0;
            if (sk_crypto_aes128_cbc_enc (_aes_key, iv, plain, plain.length, out ct, out ct_len) != 0) {
                throw new IOError.FAILED ("Session.wrap: AES encrypt failed");
            }
            uint8[] value = new uint8[ct_len];
            Memory.copy (value, ct, ct_len);
            sk_crypto_free (ct);
            out_params = iv;
            out_value  = value;
        }

        public uint8[] unwrap (uint8[] params_, uint8[] value) throws Error {
            if (_algo == Algorithm.PLAIN) return value;
            if (params_.length != 16) {
                throw new IOError.INVALID_DATA ("Session.unwrap: bad IV length");
            }
            uint8 *pt = null;
            size_t pt_len = 0;
            if (sk_crypto_aes128_cbc_dec (_aes_key, params_, value, value.length, out pt, out pt_len) != 0) {
                throw new IOError.FAILED ("Session.unwrap: AES decrypt failed");
            }
            uint8[] result = new uint8[pt_len];
            Memory.copy (result, pt, pt_len);
            sk_crypto_free (pt);
            return result;
        }
    }
}
