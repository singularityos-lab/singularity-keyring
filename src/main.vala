// main.vala - entry point.
//
// Hosts a hidden GtkApplication so unlock dialogs have a GUI parent,
// then owns "org.freedesktop.secrets" on the session bus.

using GLib;
using Gtk;

static Singularity.Keyring.SecretService? service_instance = null;

class Singularity.Keyring.Daemon : Gtk.Application {

    public Daemon () {
        Object (application_id: "dev.sinty.keyring",
                flags:          ApplicationFlags.IS_SERVICE);
    }

    protected override void activate () {
        hold ();  // stay alive without windows
    }

    protected override bool dbus_register (DBusConnection conn, string object_path) throws Error {
        if (!base.dbus_register (conn, object_path)) return false;
        var session_bus = Bus.get_sync (BusType.SESSION, null);
        Bus.own_name_on_connection (session_bus,
            "org.freedesktop.secrets",
            BusNameOwnerFlags.NONE,
            (c, name) => {
                try {
                    service_instance = new Singularity.Keyring.SecretService (c, this);
                    c.register_object ("/org/freedesktop/secrets", service_instance);
                    service_instance.init ();
                    message ("singularity-keyring: bus name acquired");
                } catch (Error e) {
                    warning ("singularity-keyring: registration failed: %s", e.message);
                    release ();
                }
            },
            (c, name) => {
                warning ("singularity-keyring: lost bus name '%s'", name);
                release ();
            });
        return true;
    }
}

int main (string[] args) {
    var app = new Singularity.Keyring.Daemon ();
    return app.run (args);
}
