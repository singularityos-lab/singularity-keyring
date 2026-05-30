// prompt.vala - org.freedesktop.Secret.Prompt DBus object.
//
// Backed by a real GTK passphrase dialog. When prompt() is called the
// dialog is shown; on success the action callback decides whether the
// prompt's completion is dismissed=true or carries a result.

using GLib;

namespace Singularity.Keyring {

    public delegate void PromptAction (string passphrase, out bool dismissed, out GLib.Variant result);

    [DBus (name = "org.freedesktop.Secret.Prompt")]
    public class SecretPrompt : Object {

        private string _path;
        private UnlockDialog.Mode _mode;
        private UnlockDialog _dialog;
        private PromptAction _action;
        private bool _done = false;

        public signal void completed (bool dismissed, GLib.Variant result);
        internal signal void finished ();

        public SecretPrompt (string path,
                             UnlockDialog.Mode mode,
                             UnlockDialog dialog,
                             owned PromptAction action) {
            _path   = path;
            _mode   = mode;
            _dialog = dialog;
            _action = (owned) action;
        }

        public string get_path () { return _path; }

        public void prompt (string window_id) throws GLib.Error {
            if (_done) return;
            _dialog.run (_mode, (accepted, passphrase) => {
                if (_done) return;
                _done = true;
                if (!accepted) {
                    completed (true, new GLib.Variant ("s", ""));
                    finished ();
                    return;
                }
                bool dismissed = false;
                GLib.Variant result = new GLib.Variant ("s", "");
                _action (passphrase, out dismissed, out result);
                completed (dismissed, result);
                finished ();
            });
        }

        public void dismiss () throws GLib.Error {
            if (_done) return;
            _done = true;
            completed (true, new GLib.Variant ("s", ""));
            finished ();
        }
    }
}
