// collection.vala - org.freedesktop.Secret.Collection DBus object.

using GLib;

namespace Singularity.Keyring {

    public delegate SecretSession? SessionLookup (string path);

    [DBus (name = "org.freedesktop.Secret.Collection")]
    public class SecretCollection : Object {

        private string          _name;
        private CollectionData? _data;
        private Store           _store;
        private DBusConnection  _conn;
        private SessionLookup   _lookup;

        private bool _locked = true;

        private HashTable<string, SecretItem> _items_map;
        private HashTable<string, uint>       _item_reg_ids;

        public signal void item_created (GLib.ObjectPath item);
        public signal void item_deleted (GLib.ObjectPath item);
        public signal void item_changed  (GLib.ObjectPath item);
        internal signal void deleted ();

        public SecretCollection (string name,
                                  Store  store,
                                  DBusConnection conn,
                                  owned SessionLookup lookup) {
            _name         = name;
            _store        = store;
            _conn         = conn;
            _lookup       = (owned) lookup;
            _items_map    = new HashTable<string, SecretItem> (str_hash, str_equal);
            _item_reg_ids = new HashTable<string, uint>       (str_hash, str_equal);
        }

        public string get_name () { return _name; }
        public string get_path () { return path_for_name (_name); }
        public bool   is_locked () { return _locked; }

        internal static string path_for_name (string name) {
            var component = new StringBuilder ();
            foreach (uint8 b in name.data) {
                if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
                    (b >= '0' && b <= '9'))
                    component.append_c ((char) b);
                else
                    component.append_printf ("_%02x", b);
            }
            if (component.len == 0) component.append_c ('_');
            return "/org/freedesktop/secrets/collection/" + component.str;
        }

        internal SecretSession? lookup_session (string path) {
            return _lookup (path);
        }

        /**
         * Load + register all items from disk. Requires the store master
         * key to be unlocked. Returns true on success, false on failure.
         */
        public bool unlock_collection () {
            if (!_locked) return true;
            try {
                _data = _store.load (_name);
            } catch (Error e) {
                warning ("Collection '%s' load failed: %s", _name, e.message);
                return false;
            }
            if (_data == null) {
                // First-time: create empty data on disk.
                _data = new CollectionData ();
                _data.label = _name;
                try { _store.save (_name, _data); }
                catch (Error e) {
                    warning ("Collection '%s' init failed: %s", _name, e.message);
                    _data = null;
                    return false;
                }
            }
            foreach (var idata in _data.items) _register_item (idata);
            _locked = false;
            return true;
        }

        /**
         * Drop in-memory data + unregister items from the bus.
         */
        public void lock_collection () {
            if (_locked) return;
            _item_reg_ids.foreach ((id, reg_id) => {
                _conn.unregister_object (reg_id);
            });
            _item_reg_ids.remove_all ();
            _items_map.remove_all ();
            _data = null;
            _locked = true;
        }

        internal SecretItem? get_item_by_id (string id) {
            return _items_map[id];
        }

        private void _register_item (ItemData idata) {
            var item = new SecretItem (_name, idata.id, idata);
            item.set_owner (this);

            item.needs_save.connect (() => {
                if (_data == null) return;
                _data.modified = (uint64) (get_real_time () / 1000000);
                _save ();
                item_changed ((GLib.ObjectPath) item.get_path ());
            });

            _items_map[idata.id] = item;
            try {
                _item_reg_ids[idata.id] = _conn.register_object (item.get_path (), item);
            } catch (Error e) {
                warning ("Collection '%s': failed to register item '%s': %s",
                          _name, idata.id, e.message);
            }
        }

        private void _save () {
            if (_data == null) return;
            try { _store.save (_name, _data); }
            catch (Error e) { warning ("Collection '%s': save failed: %s", _name, e.message); }
        }

        internal void save_secret (string id, uint8[] value, string content_type) throws Error {
            var item = _items_map[id];
            if (_locked || _data == null || item == null)
                throw new DBusError.FAILED ("collection is locked or item is missing");
            var data = item.get_data ();
            uint8[] previous_value = data.secret_value;
            string previous_type = data.content_type;
            uint64 previous_modified = data.modified;
            uint64 collection_modified = _data.modified;
            data.secret_value = value;
            data.content_type = content_type;
            data.modified = (uint64) (get_real_time () / 1000000);
            _data.modified = data.modified;
            try {
                _store.save (_name, _data);
            } catch (Error e) {
                data.secret_value = previous_value;
                data.content_type = previous_type;
                data.modified = previous_modified;
                _data.modified = collection_modified;
                throw e;
            }
            item_changed ((GLib.ObjectPath) item.get_path ());
        }

        private static bool _attributes_match (HashTable<string, string> item_attrs,
                                                HashTable<string, string> query) {
            bool match = true;
            query.foreach ((k, v) => { if (item_attrs[k] != v) match = false; });
            return match;
        }

        internal void unregister_all () { lock_collection (); }

        internal void remove_item (string id) throws Error {
            var item = _items_map[id];
            if (_locked || item == null || _data == null)
                throw new DBusError.FAILED ("collection is locked or item is missing");

            ItemData? to_remove = null;
            foreach (var idata in _data.items) {
                if (idata.id == id) { to_remove = idata; break; }
            }
            if (to_remove == null)
                throw new DBusError.FAILED ("Item is missing from collection");
            int position = _data.items.index (to_remove);
            uint64 previous_modified = _data.modified;
            _data.items.remove (to_remove);
            _data.modified = (uint64) (get_real_time () / 1000000);
            try {
                _store.save (_name, _data);
            } catch (Error e) {
                _data.items.insert (to_remove, position);
                _data.modified = previous_modified;
                throw e;
            }
            uint reg_id = _item_reg_ids[id];
            if (reg_id != 0) _conn.unregister_object (reg_id);
            _item_reg_ids.remove (id);
            _items_map.remove (id);
            item_deleted ((GLib.ObjectPath) item.get_path ());
        }

        public GLib.ObjectPath[] items {
            owned get {
                GLib.ObjectPath[] result = {};
                _items_map.foreach ((id, item) => {
                    result += (GLib.ObjectPath) item.get_path ();
                });
                return result;
            }
        }

        public string label {
            get { return (_data != null) ? _data.label : _name; }
            set {
                if (_data == null) return;
                _data.label    = value;
                _data.modified = (uint64) (get_real_time () / 1000000);
                _save ();
            }
        }

        public bool   locked   { get { return _locked; } }
        public uint64 created  { get { return (_data != null) ? _data.created  : 0; } }
        public uint64 modified { get { return (_data != null) ? _data.modified : 0; } }

        public GLib.ObjectPath[] search_items (HashTable<string, string> attributes) throws GLib.Error {
            GLib.ObjectPath[] result = {};
            if (_locked) return result;
            _items_map.foreach ((id, item) => {
                if (_attributes_match (item.get_data ().attributes, attributes)) {
                    result += (GLib.ObjectPath) item.get_path ();
                }
            });
            return result;
        }

        public void create_item (HashTable<string, GLib.Variant> properties,
                                  Secret secret,
                                  bool replace,
                                  out GLib.ObjectPath item_path,
                                  out GLib.ObjectPath prompt) throws GLib.Error {
            prompt = (GLib.ObjectPath) "/";
            if (_locked || _data == null)
                throw new GLib.DBusError.FAILED ("collection is locked");

            string new_label = "";
            string new_type  = "org.freedesktop.Secret.Generic";
            var new_attrs    = new HashTable<string, string> (str_hash, str_equal);

            var lv = properties["org.freedesktop.Secret.Item.Label"];
            if (lv != null) new_label = lv.get_string ();

            var tv = properties["org.freedesktop.Secret.Item.Type"];
            if (tv != null) new_type = tv.get_string ();

            var av = properties["org.freedesktop.Secret.Item.Attributes"];
            if (av != null) {
                var iter = new GLib.VariantIter (av);
                string? k = null;
                string? v = null;
                while (iter.next ("{ss}", out k, out v)) {
                    if (k != null && v != null) new_attrs[k] = v;
                }
            }

            // Decrypt the incoming secret with the session it came on.
            var session = _lookup ((string) secret.session);
            if (session == null)
                throw new GLib.DBusError.NO_REPLY ("Unknown session");
            uint8[] plain = session.unwrap (secret.parameters, secret.value);

            if (replace) {
                SecretItem? found = null;
                _items_map.foreach ((id, item) => {
                    if (found == null &&
                        _attributes_match (item.get_data ().attributes, new_attrs))
                        found = item;
                });
                if (found != null) {
                    found.replace_secret (plain, secret.content_type);
                    item_path = (GLib.ObjectPath) found.get_path ();
                    return;
                }
            }

            string new_id    = GLib.Uuid.string_random ().replace ("-", "");
            var    idata      = new ItemData ();
            idata.id           = new_id;
            idata.label        = new_label;
            idata.item_type    = new_type;
            idata.attributes   = new_attrs;
            idata.secret_value = plain;
            idata.content_type = secret.content_type;

            uint64 previous_modified = _data.modified;
            _data.items.append (idata);
            _data.modified = (uint64) (get_real_time () / 1000000);
            try {
                _store.save (_name, _data);
            } catch (Error e) {
                _data.items.remove (idata);
                _data.modified = previous_modified;
                throw e;
            }
            _register_item (idata);

            item_path = (GLib.ObjectPath) _items_map[new_id].get_path ();
            item_created (item_path);
        }

        public GLib.ObjectPath delete () throws GLib.Error {
            _store.delete_collection (_name);
            unregister_all ();
            deleted ();
            return (GLib.ObjectPath) "/";
        }
    }
}
