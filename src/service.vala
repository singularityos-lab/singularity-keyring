// service.vala - org.freedesktop.Secret.Service DBus object.

using GLib;

namespace Singularity.Keyring {

    [DBus (name = "org.freedesktop.Secret.Service")]
    public class SecretService : Object {

        private DBusConnection _conn;
        private Gtk.Application _gtk_app;
        private Store          _store;
        private UnlockDialog   _dialog;

        private HashTable<string, SecretCollection> _collections;
        private HashTable<string, uint>             _collection_reg_ids;
        private HashTable<string, SecretSession>    _sessions;
        private HashTable<string, uint>             _session_reg_ids;
        private HashTable<string, string>           _aliases;

        // Tracks active prompt object so we don't unregister too early.
        private HashTable<string, SecretPrompt>     _prompts;
        private HashTable<string, uint>             _prompt_reg_ids;

        private uint _session_counter = 0;
        private uint _prompt_counter  = 0;

        public signal void collection_created (GLib.ObjectPath collection);
        public signal void collection_deleted (GLib.ObjectPath collection);
        public signal void collection_changed (GLib.ObjectPath collection);

        public SecretService (DBusConnection conn, Gtk.Application gtk_app) {
            _conn               = conn;
            _gtk_app            = gtk_app;
            _store              = new Store ();
            _dialog             = new UnlockDialog (gtk_app);
            _collections        = new HashTable<string, SecretCollection> (str_hash, str_equal);
            _collection_reg_ids = new HashTable<string, uint>             (str_hash, str_equal);
            _sessions           = new HashTable<string, SecretSession>    (str_hash, str_equal);
            _session_reg_ids    = new HashTable<string, uint>             (str_hash, str_equal);
            _aliases            = new HashTable<string, string>           (str_hash, str_equal);
            _prompts            = new HashTable<string, SecretPrompt>     (str_hash, str_equal);
            _prompt_reg_ids     = new HashTable<string, uint>             (str_hash, str_equal);
        }

        public void init () throws Error {
            sk_crypto_init ();

            // Register every known collection in locked state.
            foreach (var cname in _store.list_collection_names ()) {
                _register_collection_locked (cname);
            }
            // Ensure the default "login" collection exists on disk later;
            // we register a locked placeholder for it now so paths work.
            if (_collections["login"] == null) {
                _register_collection_locked ("login");
            }
            _aliases["default"] = "/org/freedesktop/secrets/collection/login";
        }

        private SecretCollection _register_collection_locked (string name) {
            var coll = new SecretCollection (name, _store, _conn,
                (path) => _sessions[_path_to_session_id (path)]);

            coll.item_created.connect ((p) =>
                collection_changed ((GLib.ObjectPath) coll.get_path ()));
            coll.item_deleted.connect ((p) =>
                collection_changed ((GLib.ObjectPath) coll.get_path ()));
            coll.item_changed.connect ((p) =>
                collection_changed ((GLib.ObjectPath) coll.get_path ()));

            _collections[name] = coll;
            try {
                _collection_reg_ids[name] = _conn.register_object (coll.get_path (), coll);
            } catch (Error e) {
                warning ("Service: register collection '%s': %s", name, e.message);
            }
            return coll;
        }

        private static string _path_to_session_id (string path) {
            int slash = path.last_index_of ("/");
            return (slash >= 0) ? path[slash + 1 :] : path;
        }

        public GLib.ObjectPath[] collections {
            owned get {
                GLib.ObjectPath[] result = {};
                _collections.foreach ((name, coll) => {
                    result += (GLib.ObjectPath) coll.get_path ();
                });
                return result;
            }
        }

        // open_session: supports plain and dh-ietf. For dh-ietf the input
        // is the client's MODP-2048 public key as an ay; output is our
        // public key, same encoding.
        public void open_session (string algorithm,
                                   GLib.Variant input,
                                   out GLib.Variant output,
                                   out GLib.ObjectPath result) throws GLib.Error {

            var sid     = _session_counter.to_string ();
            _session_counter++;
            var path    = "/org/freedesktop/secrets/session/" + sid;
            SecretSession session;

            if (algorithm == "plain") {
                session = new SecretSession.plain (path);
                output  = new GLib.Variant ("s", "");
            } else if (algorithm == "dh-ietf") {
                if (input.get_type_string () != "ay")
                    throw new GLib.DBusError.INVALID_ARGS ("dh-ietf input must be ay");
                var iter = input.iterator ();
                uint8[] client_pub = new uint8[0];
                uint8 b;
                while (iter.next ("y", out b)) client_pub += b;

                uint8 *our_pub_bytes = null;
                size_t our_pub_len   = 0;
                void *priv           = null;
                if (sk_crypto_dh_keypair (out our_pub_bytes, out our_pub_len, out priv) != 0)
                    throw new GLib.DBusError.FAILED ("DH keypair failed");

                uint8 *shared = null;
                size_t shared_len = 0;
                if (sk_crypto_dh_shared (client_pub, client_pub.length, priv, out shared, out shared_len) != 0) {
                    sk_crypto_free (our_pub_bytes);
                    sk_crypto_dh_priv_free (priv);
                    throw new GLib.DBusError.FAILED ("DH shared failed");
                }
                sk_crypto_dh_priv_free (priv);

                uint8[] shared_arr = new uint8[shared_len];
                for (size_t i = 0; i < shared_len; i++) shared_arr[i] = shared[i];
                sk_crypto_free (shared);

                uint8[] aes_key = new uint8[16];
                if (sk_crypto_hkdf_sha256_aes128 (shared_arr, shared_arr.length, aes_key) != 0) {
                    sk_crypto_free (our_pub_bytes);
                    throw new GLib.DBusError.FAILED ("HKDF failed");
                }

                var pub_builder = new GLib.VariantBuilder (new GLib.VariantType ("ay"));
                for (size_t i = 0; i < our_pub_len; i++)
                    pub_builder.add ("y", our_pub_bytes[i]);
                sk_crypto_free (our_pub_bytes);
                output = pub_builder.end ();

                session = new SecretSession.dh_ietf (path, aes_key);
            } else {
                throw new GLib.DBusError.NOT_SUPPORTED (
                    "Algorithm '%s' is not supported; use 'plain' or 'dh-ietf'.".printf (algorithm));
            }

            session.session_closed.connect (() => {
                uint reg_id = _session_reg_ids[sid];
                if (reg_id != 0) {
                    _conn.unregister_object (reg_id);
                    _session_reg_ids.remove (sid);
                }
                _sessions.remove (sid);
            });
            _sessions[sid] = session;
            try {
                _session_reg_ids[sid] = _conn.register_object (path, session);
            } catch (Error e) {
                throw new GLib.DBusError.FAILED ("Register session: " + e.message);
            }
            result = (GLib.ObjectPath) path;
        }

        public void create_collection (HashTable<string, GLib.Variant> properties,
                                        string alias,
                                        out GLib.ObjectPath collection_path,
                                        out GLib.ObjectPath prompt) throws GLib.Error {
            prompt = (GLib.ObjectPath) "/";

            if (alias.length > 0 && _aliases[alias] != null) {
                collection_path = (GLib.ObjectPath) _aliases[alias];
                return;
            }

            string new_label = "New Keyring";
            var    lv        = properties["org.freedesktop.Secret.Collection.Label"];
            if (lv != null) new_label = lv.get_string ();

            string name = new_label.down ()
                                   .replace (" ", "-")
                                   .replace ("/", "")
                                   .replace (".", "");
            if (name.length == 0) name = "keyring";
            var base_name = name;
            int suffix    = 1;
            while (_collections[name] != null) name = "%s-%d".printf (base_name, suffix++);

            // Make sure the master key is unlocked before we can persist.
            if (!_store.master.unlocked) {
                throw new GLib.DBusError.FAILED ("keyring is locked; call Unlock() first");
            }

            var coll = _register_collection_locked (name);
            if (!coll.unlock_collection ())
                throw new GLib.DBusError.FAILED ("Could not initialise collection");
            coll.label = new_label;

            if (alias.length > 0) _aliases[alias] = coll.get_path ();
            collection_path = (GLib.ObjectPath) coll.get_path ();
            collection_created (collection_path);
        }

        public void search_items (HashTable<string, string> attributes,
                                   out GLib.ObjectPath[] unlocked,
                                   out GLib.ObjectPath[] locked) throws GLib.Error {
            GLib.ObjectPath[] u = {};
            GLib.ObjectPath[] l = {};
            _collections.foreach ((name, coll) => {
                try {
                    if (coll.is_locked ()) {
                        // We don't have item paths when locked.
                        l += (GLib.ObjectPath) coll.get_path ();
                    } else {
                        foreach (var p in coll.search_items (attributes)) u += p;
                    }
                } catch {}
            });
            unlocked = u;
            locked   = l;
        }

        public void unlock (GLib.ObjectPath[]   objects,
                             out GLib.ObjectPath[] unlocked,
                             out GLib.ObjectPath   prompt) throws GLib.Error {
            unlocked = {};
            prompt   = (GLib.ObjectPath) "/";

            // Find which referenced collections are currently locked.
            var locked_colls = new GenericArray<SecretCollection> ();
            _collections.foreach ((name, coll) => {
                bool referenced = false;
                foreach (var p in objects) {
                    string ps = (string) p;
                    if (ps == coll.get_path () || ps.has_prefix (coll.get_path () + "/")) {
                        referenced = true;
                        break;
                    }
                }
                if (referenced && coll.is_locked ()) locked_colls.add (coll);
            });

            // Already unlocked subset.
            GLib.ObjectPath[] already = {};
            foreach (var p in objects) {
                string ps = (string) p;
                bool covered = false;
                _collections.foreach ((name, coll) => {
                    if (coll.is_locked ()) return;
                    if (ps == coll.get_path () || ps.has_prefix (coll.get_path () + "/"))
                        covered = true;
                });
                if (covered) already += p;
            }

            // If the master itself is already unlocked we can finish all
            // collections inline without prompting.
            if (_store.master.unlocked) {
                for (uint i = 0; i < locked_colls.length; i++) {
                    locked_colls[i].unlock_collection ();
                }
                foreach (var p in objects) {
                    string ps = (string) p;
                    _collections.foreach ((name, coll) => {
                        if (coll.is_locked ()) return;
                        if (ps == coll.get_path () || ps.has_prefix (coll.get_path () + "/"))
                            already += p;
                    });
                }
                unlocked = already;
                return;
            }

            if (locked_colls.length == 0) {
                unlocked = already;
                return;
            }

            // Need to prompt for the master passphrase.
            var pid  = _prompt_counter.to_string ();
            _prompt_counter++;
            string ppath = "/org/freedesktop/secrets/prompt/" + pid;

            var mode = _store.master.exists_on_disk ()
                       ? UnlockDialog.Mode.UNLOCK
                       : UnlockDialog.Mode.CREATE;

            GLib.ObjectPath[] captured = objects;
            var p = new SecretPrompt (ppath, mode, _dialog,
                (passphrase, out dismissed, out result) => {
                    dismissed = false;
                    bool ok = false;
                    if (mode == UnlockDialog.Mode.CREATE) {
                        ok = _store.master.create (passphrase);
                    } else {
                        ok = _store.master.try_unlock (passphrase);
                    }
                    if (!ok) {
                        dismissed = true;
                        result    = new GLib.Variant ("ao", new GLib.ObjectPath[0]);
                        return;
                    }
                    GLib.ObjectPath[] now_unlocked = {};
                    _collections.foreach ((name, coll) => {
                        if (coll.is_locked ()) coll.unlock_collection ();
                    });
                    foreach (var op in captured) {
                        string ops = (string) op;
                        _collections.foreach ((name, coll) => {
                            if (coll.is_locked ()) return;
                            if (ops == coll.get_path () || ops.has_prefix (coll.get_path () + "/"))
                                now_unlocked += op;
                        });
                    }
                    var b = new GLib.VariantBuilder (new GLib.VariantType ("ao"));
                    foreach (var op in now_unlocked) b.add ("o", op);
                    result = b.end ();
                });

            p.finished.connect (() => {
                uint reg_id = _prompt_reg_ids[pid];
                if (reg_id != 0) {
                    _conn.unregister_object (reg_id);
                    _prompt_reg_ids.remove (pid);
                }
                _prompts.remove (pid);
            });

            _prompts[pid] = p;
            try {
                _prompt_reg_ids[pid] = _conn.register_object (ppath, p);
            } catch (Error e) {
                throw new GLib.DBusError.FAILED ("Register prompt: " + e.message);
            }
            prompt   = (GLib.ObjectPath) ppath;
            unlocked = already;
        }

        public void lock (GLib.ObjectPath[]   objects,
                           out GLib.ObjectPath[] locked,
                           out GLib.ObjectPath   prompt) throws GLib.Error {
            GLib.ObjectPath[] result = {};
            _collections.foreach ((name, coll) => {
                bool referenced = (objects.length == 0);
                foreach (var p in objects) {
                    string ps = (string) p;
                    if (ps == coll.get_path () || ps.has_prefix (coll.get_path () + "/")) {
                        referenced = true;
                        break;
                    }
                }
                if (referenced && !coll.is_locked ()) {
                    coll.lock_collection ();
                    result += (GLib.ObjectPath) coll.get_path ();
                }
            });

            // If user locks every collection, purge the master too.
            bool any_unlocked = false;
            _collections.foreach ((name, coll) => {
                if (!coll.is_locked ()) any_unlocked = true;
            });
            if (!any_unlocked) _store.master.purge ();

            locked = result;
            prompt = (GLib.ObjectPath) "/";
        }

        public HashTable<GLib.ObjectPath, Secret?> get_secrets (
                GLib.ObjectPath[] items,
                GLib.ObjectPath   session) throws GLib.Error {

            var result = new HashTable<GLib.ObjectPath, Secret?> (str_hash, str_equal);
            foreach (var item_path in items) {
                _collections.foreach ((name, coll) => {
                    if (coll.is_locked ()) return;
                    string prefix = coll.get_path () + "/";
                    string path_s = (string) item_path;
                    if (!path_s.has_prefix (prefix)) return;
                    string id   = path_s[prefix.length :];
                    var    item = coll.get_item_by_id (id);
                    if (item == null) return;
                    try { result[item_path] = item.get_secret (session); } catch {}
                });
            }
            return result;
        }

        public GLib.ObjectPath read_alias (string name) throws GLib.Error {
            var target = _aliases[name];
            return (target != null) ? (GLib.ObjectPath) target : (GLib.ObjectPath) "/";
        }

        public void set_alias (string name, GLib.ObjectPath collection_path) throws GLib.Error {
            string cp = (string) collection_path;
            if (cp == "/") { _aliases.remove (name); return; }
            bool found = false;
            _collections.foreach ((cname, coll) => {
                if (coll.get_path () == cp) found = true;
            });
            if (!found)
                throw new GLib.DBusError.FAILED ("No collection at path '%s'".printf (cp));
            _aliases[name] = cp;
        }
    }
}
