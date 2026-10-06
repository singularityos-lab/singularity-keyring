// unlock_dialog.vala - tiny GTK4 passphrase dialog.
//
// Two modes:
//   CREATE  - first-time setup, two entries (passphrase + confirm).
//   UNLOCK  - existing keyring, one passphrase entry.

using GLib;
using Gtk;

namespace Singularity.Keyring {

    public delegate void UnlockResult (bool accepted, string passphrase);

    public class UnlockDialog : Object {

        public enum Mode { CREATE, UNLOCK }

        private Gtk.Application _app;

        public UnlockDialog (Gtk.Application app) {
            _app = app;
        }

        public void run (Mode mode, owned UnlockResult cb) {
            var win = new Gtk.Window ();
            win.application   = _app;
            win.modal         = true;
            win.resizable     = false;
            win.deletable     = false;
            win.title         = (mode == Mode.CREATE)
                                ? "Set keyring passphrase"
                                : "Unlock keyring";
            win.default_width = 380;

            var root = new Box (Orientation.VERTICAL, 12);
            root.margin_top    = 18;
            root.margin_bottom = 18;
            root.margin_start  = 22;
            root.margin_end    = 22;

            var title = new Label ((mode == Mode.CREATE)
                ? "Choose a passphrase for your keyring."
                : "An application is trying to read a secret. Enter your passphrase.");
            title.wrap   = true;
            title.xalign = 0;
            root.append (title);

            var entry1 = new PasswordEntry ();
            entry1.show_peek_icon = true;
            entry1.placeholder_text = _("Passphrase");
            entry1.activates_default = true;
            root.append (entry1);

            PasswordEntry? entry2 = null;
            if (mode == Mode.CREATE) {
                entry2 = new PasswordEntry ();
                entry2.placeholder_text = _("Confirm passphrase");
                entry2.activates_default = true;
                root.append (entry2);
            }

            var err_lbl = new Label ("");
            err_lbl.add_css_class ("error");
            err_lbl.xalign = 0;
            err_lbl.visible = false;
            root.append (err_lbl);

            var btnbox = new Box (Orientation.HORIZONTAL, 8);
            btnbox.halign = Align.END;
            var cancel_btn = new Button.with_label (_("Cancel"));
            var ok_btn     = new Button.with_label ((mode == Mode.CREATE) ? "Create" : "Unlock");
            ok_btn.add_css_class ("suggested-action");
            btnbox.append (cancel_btn);
            btnbox.append (ok_btn);
            root.append (btnbox);

            win.set_child (root);
            win.set_default_widget (ok_btn);

            bool finished = false;
            UnlockResult cbref = (owned) cb;

            cancel_btn.clicked.connect (() => {
                if (finished) return;
                finished = true;
                win.close ();
                cbref (false, "");
            });

            var keys = new EventControllerKey ();
            keys.key_pressed.connect ((keyval, keycode, state) => {
                if (keyval != Gdk.Key.Escape) return false;
                cancel_btn.clicked ();
                return true;
            });
            ((Widget) win).add_controller (keys);

            void try_submit () {
                if (finished) return;
                string p1 = entry1.text;
                if (p1.length == 0) {
                    err_lbl.label = _("Passphrase cannot be empty.");
                    err_lbl.visible = true;
                    return;
                }
                if (entry2 != null) {
                    string p2 = entry2.text;
                    if (p1 != p2) {
                        err_lbl.label = _("Passphrases do not match.");
                        err_lbl.visible = true;
                        entry2.text = "";
                        entry2.grab_focus ();
                        return;
                    }
                }
                finished = true;
                win.close ();
                cbref (true, p1);
            }
            ok_btn.clicked.connect (try_submit);
            entry1.activate.connect (try_submit);
            if (entry2 != null) entry2.activate.connect (try_submit);

            win.close_request.connect (() => {
                if (!finished) {
                    finished = true;
                    cbref (false, "");
                }
                return false;
            });

            win.present ();
            entry1.grab_focus ();
        }
    }
}
