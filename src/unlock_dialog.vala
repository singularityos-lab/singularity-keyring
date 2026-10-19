// unlock_dialog.vala - keyring passphrase dialog.
//
// Two modes:
//   CREATE  - first-time setup, two entries (passphrase + confirm).
//   UNLOCK  - existing keyring, one passphrase entry.

using GLib;
using Gtk;

namespace Singularity.Keyring {

    public delegate void UnlockResult (bool accepted, string passphrase);
    public delegate bool UnlockVerify (string passphrase);

    public class UnlockDialog : Object {

        public enum Mode { CREATE, UNLOCK }

        private class Waiter {
            public UnlockResult cb;
            public Waiter (owned UnlockResult cb) { this.cb = (owned) cb; }
        }

        private Gtk.Application _app;
        private Singularity.Widgets.AppDialog? _win = null;
        private GLib.List<Waiter> _waiters = new GLib.List<Waiter> ();
        private UnlockVerify? _verify = null;

        public UnlockDialog (Gtk.Application app) {
            _app = app;
        }

        public void set_verify (owned UnlockVerify verify) {
            _verify = (owned) verify;
        }

        public void run (Mode mode, owned UnlockResult cb) {
            _waiters.append (new Waiter ((owned) cb));
            if (_win != null) {
                _win.present ();
                return;
            }

            var win = new Singularity.Widgets.AppDialog (_app, true, false);
            _win = win;
            win.resizable = false;
            win.set_title (mode == Mode.CREATE ? _("Create Keyring") : _("Unlock Keyring"));
            win.set_default_size (420, -1);

            var header = new Box (Orientation.VERTICAL, 8);
            header.margin_top = 12;
            header.margin_start = 24;
            header.margin_end = 24;

            var icon = new Image.from_icon_name ("dialog-password");
            icon.pixel_size = 64;
            header.append (icon);

            var heading = new Label (mode == Mode.CREATE
                ? _("Protect your saved passwords")
                : _("An app wants to use your saved passwords"));
            heading.add_css_class ("title-3");
            heading.wrap = true;
            heading.justify = Justification.CENTER;
            header.append (heading);

            var body = new Label (mode == Mode.CREATE
                ? _("Apps keep passwords and keys in your keyring. Choose a passphrase to encrypt it; you will need it to unlock the keyring later.")
                : _("Enter your keyring passphrase to unlock it."));
            body.add_css_class ("dim-label");
            body.wrap = true;
            body.justify = Justification.CENTER;
            body.max_width_chars = 44;
            header.append (body);
            win.content_box.append (header);

            var group = new Singularity.Widgets.PreferencesGroup ();
            group.margin_start = 12;
            group.margin_end = 12;
            group.margin_top = 12;

            var pass_row = new Singularity.Widgets.PasswordRow (_("Passphrase"));
            group.add_row (pass_row);

            Singularity.Widgets.PasswordRow? confirm_row = null;
            if (mode == Mode.CREATE) {
                confirm_row = new Singularity.Widgets.PasswordRow (_("Confirm Passphrase"));
                group.add_row (confirm_row);
            }
            win.content_box.append (group);

            var err_lbl = new Label ("");
            err_lbl.add_css_class ("error");
            err_lbl.margin_start = 24;
            err_lbl.margin_end = 24;
            err_lbl.margin_top = 8;
            err_lbl.wrap = true;
            err_lbl.visible = false;
            win.content_box.append (err_lbl);

            var footer = new Box (Orientation.HORIZONTAL, 12);
            footer.margin_start = 24;
            footer.margin_end = 24;
            footer.margin_top = 12;
            footer.margin_bottom = 24;
            footer.halign = Align.END;

            var cancel_btn = new Button.with_label (_("Cancel"));
            cancel_btn.add_css_class ("flat");
            win.set_cancel_button (cancel_btn);

            var ok_btn = new Button.with_label (mode == Mode.CREATE ? _("Create") : _("Unlock"));
            ok_btn.add_css_class ("suggested-action");

            footer.append (cancel_btn);
            footer.append (ok_btn);
            win.content_box.append (footer);
            win.set_default_widget (ok_btn);

            cancel_btn.clicked.connect (() => {
                finish (false, "");
            });

            ok_btn.clicked.connect (() => {
                string p1 = pass_row.text;
                if (p1.length == 0) {
                    err_lbl.label = _("Passphrase cannot be empty.");
                    err_lbl.visible = true;
                    pass_row.grab_focus ();
                    return;
                }
                if (confirm_row != null && p1 != confirm_row.text) {
                    err_lbl.label = _("Passphrases do not match.");
                    err_lbl.visible = true;
                    confirm_row.text = "";
                    confirm_row.grab_focus ();
                    return;
                }
                if (mode == Mode.UNLOCK && _verify != null && !_verify (p1)) {
                    err_lbl.label = _("Wrong passphrase. Try again.");
                    err_lbl.visible = true;
                    pass_row.text = "";
                    pass_row.grab_focus ();
                    return;
                }
                finish (true, p1);
            });
            pass_row.entry_activated.connect (() => {
                if (confirm_row != null && confirm_row.text.length == 0) {
                    confirm_row.grab_focus ();
                    return;
                }
                ok_btn.clicked ();
            });
            if (confirm_row != null) {
                confirm_row.entry_activated.connect (() => ok_btn.clicked ());
            }

            win.close_request.connect (() => {
                finish (false, "");
                return false;
            });

            win.present ();
            pass_row.grab_focus ();
        }

        private void finish (bool accepted, string passphrase) {
            var win = _win;
            if (win == null) return;
            _win = null;
            var waiters = (owned) _waiters;
            _waiters = new GLib.List<Waiter> ();
            win.destroy ();
            foreach (var w in waiters) w.cb (accepted, passphrase);
        }
    }
}
