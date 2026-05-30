// master.vala - master passphrase / key state for the keyring.

using GLib;

namespace Singularity.Keyring {

    /**
     * Holds the in-memory master key for the keyring, plus the verifier
     * that proves a given passphrase derives the right key.
     *
     * File layout for ~/.local/share/singularity/keyrings/master.skr:
     *
     *   "SK1\0"                         4 bytes magic
     *   version (uint8)                 1 byte  (currently 1)
     *   salt[16]                        16 bytes, Argon2id salt
     *   verifier_blob                   secretstream(key, "SINGULARITY-KEYRING-OK")
     *
     * On unlock the entered passphrase is run through Argon2id with the
     * stored salt; the resulting 32-byte key is used to decrypt the
     * verifier. If decryption yields the expected magic plaintext the
     * passphrase is correct and the key is cached.
     */
    public class MasterKey : Object {

        public const string  MAGIC          = "SK1\0";
        public const uint8   VERSION        = 1;
        public const string  VERIFIER_PLAIN = "SINGULARITY-KEYRING-OK";

        public uint8[] key       = new uint8[32];
        public uint8[] salt      = new uint8[16];
        public bool    unlocked  = false;
        public bool    has_file  = false;

        private string _path;

        public MasterKey (string base_dir) {
            _path = GLib.Path.build_filename (base_dir, "master.skr");
            has_file = FileUtils.test (_path, FileTest.EXISTS);
        }

        public bool exists_on_disk () { return has_file; }

        /**
         * Wipes the in-memory key. Subsequent secret access requires a new
         * unlock.
         */
        public void purge () {
            for (int i = 0; i < key.length; i++) key[i] = 0;
            unlocked = false;
        }

        /**
         * Create a fresh master file with the given passphrase. Overwrites
         * any existing one. Used the first time the user sets up the
         * keyring.
         */
        public bool create (string passphrase) {
            sk_crypto_random (salt, 16);
            uint8[] derived = new uint8[32];
            if (sk_crypto_argon2id (passphrase, passphrase.length, salt, derived) != 0) {
                warning ("MasterKey.create: Argon2id failed");
                return false;
            }
            for (int i = 0; i < 32; i++) key[i] = derived[i];

            // Build verifier blob.
            uint8[] vp = VERIFIER_PLAIN.data;
            uint8 *blob = null;
            size_t blob_len = 0;
            if (sk_crypto_secretstream_seal (key, vp, vp.length, out blob, out blob_len) != 0) {
                warning ("MasterKey.create: verifier encryption failed");
                return false;
            }

            try {
                var bytes = new ByteArray ();
                bytes.append (MAGIC.data);
                uint8[] vbuf = { VERSION };
                bytes.append (vbuf);
                bytes.append (salt);
                uint8[] blob_arr = new uint8[blob_len];
                Memory.copy (blob_arr, blob, blob_len);
                bytes.append (blob_arr);

                var file = GLib.File.new_for_path (_path);
                var fos  = file.replace (null, false, GLib.FileCreateFlags.PRIVATE);
                fos.write_all (bytes.data, null);
                fos.close ();
            } catch (Error e) {
                warning ("MasterKey.create: write failed: %s", e.message);
                sk_crypto_free (blob);
                return false;
            }
            sk_crypto_free (blob);

            has_file = true;
            unlocked = true;
            return true;
        }

        /**
         * Try to unlock with the given passphrase: derive the key from the
         * stored salt and verify by decrypting the verifier blob.
         */
        public bool try_unlock (string passphrase) {
            if (!has_file) return false;

            uint8[] file_bytes;
            try {
                var file = GLib.File.new_for_path (_path);
                file.load_contents (null, out file_bytes, null);
            } catch (Error e) {
                warning ("MasterKey.try_unlock: read failed: %s", e.message);
                return false;
            }
            if (file_bytes.length < 4 + 1 + 16 + 1) return false;
            if (file_bytes[0] != 'S' || file_bytes[1] != 'K' ||
                file_bytes[2] != '1' || file_bytes[3] != '\0')
                return false;
            if (file_bytes[4] != VERSION) return false;

            for (int i = 0; i < 16; i++) salt[i] = file_bytes[5 + i];

            uint8[] derived = new uint8[32];
            if (sk_crypto_argon2id (passphrase, passphrase.length, salt, derived) != 0)
                return false;

            int blob_off = 5 + 16;
            int blob_len = file_bytes.length - blob_off;
            uint8[] blob = new uint8[blob_len];
            for (int i = 0; i < blob_len; i++) blob[i] = file_bytes[blob_off + i];

            uint8 *pt = null;
            size_t pt_len = 0;
            if (sk_crypto_secretstream_open (derived, blob, blob_len, out pt, out pt_len) != 0)
                return false;

            uint8[] expect = VERIFIER_PLAIN.data;
            bool ok = (pt_len == expect.length);
            if (ok) {
                for (size_t i = 0; i < pt_len; i++) {
                    if (pt[i] != expect[i]) { ok = false; break; }
                }
            }
            sk_crypto_free (pt);
            if (!ok) return false;

            for (int i = 0; i < 32; i++) key[i] = derived[i];
            unlocked = true;
            return true;
        }
    }
}
