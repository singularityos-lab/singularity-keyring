// main.vala - entry point.
//
// Hosts a hidden application so unlock dialogs have a GUI parent,
// then owns "org.freedesktop.secrets" on the session bus.

using GLib;
using Gtk;

static Singularity.Keyring.SecretService? service_instance = null;

class Singularity.Keyring.Daemon : Singularity.Application {

    public Daemon () {
        base ("dev.sinty.keyring", ApplicationFlags.IS_SERVICE);
    }

    protected override void activate () {
    }

    protected override bool dbus_register (DBusConnection conn, string object_path) throws Error {
        if (!base.dbus_register (conn, object_path)) return false;
        service_instance = new Singularity.Keyring.SecretService (conn, this);
        conn.register_object ("/org/freedesktop/secrets", service_instance);
        service_instance.init ();
        hold ();
        Bus.own_name_on_connection (conn,
            "org.freedesktop.secrets",
            BusNameOwnerFlags.NONE,
            (c, name) => {
                message ("singularity-keyring: bus name acquired");
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
