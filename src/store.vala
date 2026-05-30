// store.vala - encrypted persistence for keyring collections.
//
// File layout for each collection ~/.local/share/singularity/keyrings/<name>.skr:
//
//   "SKC\0"           4 bytes magic
//   version (uint8)   1 byte (currently 1)
//   secretstream blob containing the JSON payload (libsodium XChaCha20-Poly1305)
//
// The JSON payload has the same shape as before but everything (including
// secret values) is inside the encrypted blob.

using GLib;
using Json;

namespace Singularity.Keyring {

    public class ItemData : GLib.Object {
        public string id            { get; set; default = ""; }
        public string label         { get; set; default = ""; }
        public string item_type     { get; set; default = "org.freedesktop.Secret.Generic"; }
        public HashTable<string, string> attributes;
        public uint8[] secret_value;
        public string content_type  { get; set; default = "text/plain; charset=utf8"; }
        public uint64 created       { get; set; }
        public uint64 modified      { get; set; }

        public ItemData () {
            attributes = new HashTable<string, string> (str_hash, str_equal);
            uint64 now = (uint64) (get_real_time () / 1000000);
            created = now;
            modified = now;
            secret_value = new uint8[0];
        }
    }

    public class CollectionData : GLib.Object {
        public string label    { get; set; default = ""; }
        public uint64 created  { get; set; }
        public uint64 modified { get; set; }
        public GLib.List<ItemData> items;

        public CollectionData () {
            items = new GLib.List<ItemData> ();
            uint64 now = (uint64) (get_real_time () / 1000000);
            created = now;
            modified = now;
        }
    }

    public class Store : GLib.Object {

        public const string MAGIC   = "SKC\0";
        public const uint8  VERSION = 1;

        private string     _base_dir;
        private MasterKey  _master;

        public Store () {
            _base_dir = GLib.Path.build_filename (
                Environment.get_user_data_dir (), "singularity", "keyrings");
            DirUtils.create_with_parents (_base_dir, 0700);
            _master = new MasterKey (_base_dir);
        }

        public string base_dir { get { return _base_dir; } }
        public MasterKey master { get { return _master; } }

        private string collection_file (string name) {
            return GLib.Path.build_filename (_base_dir, name + ".skr");
        }

        public string[] list_collection_names () {
            string[] result = {};
            try {
                var dir = Dir.open (_base_dir);
                string? entry;
                while ((entry = dir.read_name ()) != null) {
                    if (entry.has_suffix (".skr") && entry != "master.skr") {
                        result += entry[0 : entry.length - 4];
                    }
                }
            } catch (Error e) {
                warning ("Store: cannot list keyrings dir: %s", e.message);
            }
            return result;
        }

        public bool exists (string name) {
            return FileUtils.test (collection_file (name), FileTest.EXISTS);
        }

        /**
         * Decrypt and parse a collection. Requires the master key to be
         * unlocked. Returns null if missing or undecryptable.
         */
        public CollectionData? load (string name) throws Error {
            if (!_master.unlocked) return null;
            var path = collection_file (name);
            if (!FileUtils.test (path, FileTest.EXISTS)) return null;

            uint8[] raw;
            var file = GLib.File.new_for_path (path);
            file.load_contents (null, out raw, null);
            if (raw.length < 5) return null;
            if (raw[0] != 'S' || raw[1] != 'K' || raw[2] != 'C' || raw[3] != '\0')
                return null;
            if (raw[4] != VERSION) return null;

            int blob_len = raw.length - 5;
            uint8[] blob = new uint8[blob_len];
            for (int i = 0; i < blob_len; i++) blob[i] = raw[5 + i];

            uint8 *pt = null;
            size_t pt_len = 0;
            if (sk_crypto_secretstream_open (_master.key, blob, blob_len, out pt, out pt_len) != 0) {
                warning ("Store.load: decrypt failed for '%s'", name);
                return null;
            }

            uint8[] json_bytes = new uint8[pt_len + 1];
            for (size_t i = 0; i < pt_len; i++) json_bytes[i] = pt[i];
            json_bytes[pt_len] = 0;
            sk_crypto_free (pt);
            string json_str = (string) json_bytes;

            return parse_json (json_str);
        }

        public void save (string name, CollectionData data) throws Error {
            if (!_master.unlocked) {
                throw new IOError.PERMISSION_DENIED ("keyring is locked");
            }

            string json_str = serialize_json (data);
            uint8[] pt = json_str.data;

            uint8 *blob = null;
            size_t blob_len = 0;
            if (sk_crypto_secretstream_seal (_master.key, pt, pt.length, out blob, out blob_len) != 0) {
                throw new IOError.FAILED ("Store.save: encryption failed");
            }

            var bytes = new ByteArray ();
            bytes.append (MAGIC.data);
            uint8[] vbuf = { VERSION };
            bytes.append (vbuf);
            uint8[] blob_arr = new uint8[blob_len];
            Memory.copy (blob_arr, blob, blob_len);
            bytes.append (blob_arr);
            sk_crypto_free (blob);

            var file = GLib.File.new_for_path (collection_file (name));
            var fos  = file.replace (null, false, GLib.FileCreateFlags.PRIVATE);
            fos.write_all (bytes.data, null);
            fos.close ();
        }

        public void delete_collection (string name) {
            try {
                GLib.File.new_for_path (collection_file (name)).delete ();
            } catch (Error e) {
                warning ("Store: could not delete '%s': %s", name, e.message);
            }
        }

        // JSON serialise / parse stay shaped like before.

        private string serialize_json (CollectionData data) {
            var builder = new Json.Builder ();
            builder.begin_object ();

            builder.set_member_name ("label");    builder.add_string_value (data.label);
            builder.set_member_name ("created");  builder.add_int_value ((int64) data.created);
            builder.set_member_name ("modified"); builder.add_int_value ((int64) data.modified);

            builder.set_member_name ("items");
            builder.begin_array ();
            foreach (var item in data.items) {
                builder.begin_object ();
                builder.set_member_name ("id");           builder.add_string_value (item.id);
                builder.set_member_name ("label");        builder.add_string_value (item.label);
                builder.set_member_name ("type");         builder.add_string_value (item.item_type);
                builder.set_member_name ("content_type"); builder.add_string_value (item.content_type);
                builder.set_member_name ("created");      builder.add_int_value ((int64) item.created);
                builder.set_member_name ("modified");     builder.add_int_value ((int64) item.modified);
                builder.set_member_name ("secret_b64");
                builder.add_string_value (
                    (item.secret_value != null && item.secret_value.length > 0)
                    ? Base64.encode (item.secret_value) : "");

                builder.set_member_name ("attributes");
                builder.begin_object ();
                item.attributes.foreach ((k, v) => {
                    builder.set_member_name (k);
                    builder.add_string_value (v);
                });
                builder.end_object ();
                builder.end_object ();
            }
            builder.end_array ();
            builder.end_object ();

            var gen = new Json.Generator ();
            gen.set_root (builder.get_root ());
            size_t len;
            return gen.to_data (out len);
        }

        private CollectionData? parse_json (string json_str) {
            var parser = new Json.Parser ();
            try { parser.load_from_data (json_str, -1); }
            catch (Error e) { warning ("Store: JSON parse failed: %s", e.message); return null; }

            var root = parser.get_root ();
            if (root == null || root.get_node_type () != Json.NodeType.OBJECT) return null;
            var obj  = root.get_object ();
            var data = new CollectionData ();

            if (obj.has_member ("label"))    data.label    = obj.get_string_member ("label");
            if (obj.has_member ("created"))  data.created  = (uint64) obj.get_int_member ("created");
            if (obj.has_member ("modified")) data.modified = (uint64) obj.get_int_member ("modified");

            if (obj.has_member ("items")) {
                obj.get_array_member ("items").foreach_element ((arr, idx, node) => {
                    if (node.get_node_type () != Json.NodeType.OBJECT) return;
                    var io = node.get_object ();

                    var item = new ItemData ();
                    if (io.has_member ("id"))           item.id           = io.get_string_member ("id");
                    if (io.has_member ("label"))        item.label        = io.get_string_member ("label");
                    if (io.has_member ("type"))         item.item_type    = io.get_string_member ("type");
                    if (io.has_member ("content_type")) item.content_type = io.get_string_member ("content_type");
                    if (io.has_member ("created"))      item.created      = (uint64) io.get_int_member ("created");
                    if (io.has_member ("modified"))     item.modified     = (uint64) io.get_int_member ("modified");

                    if (io.has_member ("secret_b64")) {
                        var b64 = io.get_string_member ("secret_b64");
                        item.secret_value = (b64.length > 0) ? Base64.decode (b64) : new uint8[0];
                    }

                    item.attributes = new HashTable<string, string> (str_hash, str_equal);
                    if (io.has_member ("attributes")) {
                        io.get_object_member ("attributes").foreach_member ((ao, key, vnode) => {
                            if (vnode.get_node_type () == Json.NodeType.VALUE)
                                item.attributes[key] = vnode.get_string ();
                        });
                    }
                    data.items.append (item);
                });
            }
            return data;
        }
    }
}
