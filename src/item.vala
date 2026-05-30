// item.vala - org.freedesktop.Secret.Item DBus object.

using GLib;

namespace Singularity.Keyring {

    [DBus (signature = "(oayays)")]
    public struct Secret {
        public GLib.ObjectPath session;
        public uint8[] parameters;
        public uint8[] value;
        public string content_type;
    }

    [DBus (name = "org.freedesktop.Secret.Item")]
    public class SecretItem : Object {

        private string   _collection_name;
        private string   _id;
        private ItemData _data;
        private weak SecretCollection? _owner = null;

        internal signal void needs_save ();
        internal signal void delete_requested (string item_id);

        public SecretItem (string collection_name, string id, ItemData data) {
            _collection_name = collection_name;
            _id              = id;
            _data            = data;
        }

        internal void set_owner (SecretCollection owner) { _owner = owner; }

        public string get_id   () { return _id; }
        public string get_path () {
            return "/org/freedesktop/secrets/collection/%s/%s"
                    .printf (_collection_name, _id);
        }

        public bool locked { get { return false; } }

        public HashTable<string, string> attributes {
            owned get {
                var copy = new HashTable<string, string> (str_hash, str_equal);
                _data.attributes.foreach ((k, v) => copy[k] = v);
                return copy;
            }
            set {
                _data.attributes = value;
                _data.modified = (uint64) (get_real_time () / 1000000);
                needs_save ();
            }
        }

        public string label {
            get { return _data.label; }
            set {
                _data.label    = value;
                _data.modified = (uint64) (get_real_time () / 1000000);
                needs_save ();
            }
        }

        [DBus (name = "Type")]
        public string item_type {
            get { return _data.item_type; }
            set {
                _data.item_type = value;
                _data.modified  = (uint64) (get_real_time () / 1000000);
                needs_save ();
            }
        }

        public uint64 created  { get { return _data.created; } }
        public uint64 modified { get { return _data.modified; } }

        public GLib.ObjectPath delete () throws GLib.Error {
            delete_requested (_id);
            return (GLib.ObjectPath) "/";
        }

        public Secret get_secret (GLib.ObjectPath session_path) throws GLib.Error {
            if (_owner == null)
                throw new GLib.DBusError.FAILED ("Item has no owner collection");
            var session = _owner.lookup_session ((string) session_path);
            if (session == null)
                throw new GLib.DBusError.NO_REPLY ("Unknown session");

            uint8[] plain = (_data.secret_value != null) ? _data.secret_value : new uint8[0];
            uint8[] @params;
            uint8[] value;
            string  ct;
            session.wrap (plain, _data.content_type, out @params, out value, out ct);

            Secret s = Secret ();
            s.session      = session_path;
            s.parameters   = @params;
            s.value        = value;
            s.content_type = ct;
            return s;
        }

        public void set_secret (Secret secret) throws GLib.Error {
            if (_owner == null)
                throw new GLib.DBusError.FAILED ("Item has no owner collection");
            var session = _owner.lookup_session ((string) secret.session);
            if (session == null)
                throw new GLib.DBusError.NO_REPLY ("Unknown session");

            uint8[] plain = session.unwrap (secret.parameters, secret.value);
            _data.secret_value = plain;
            _data.content_type = secret.content_type;
            _data.modified     = (uint64) (get_real_time () / 1000000);
            needs_save ();
        }

        internal unowned ItemData get_data () { return _data; }

        internal void replace_secret (uint8[] value, string content_type) {
            _data.secret_value = value;
            _data.content_type = content_type;
            _data.modified     = (uint64) (get_real_time () / 1000000);
        }
    }
}
