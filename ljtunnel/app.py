"""The listen end's window.

A panel over the server: which dialers are connected, on which port,
and a way to add and remove them. The panel IS the server -- the
sshd, the key list and the port assignment are ljtunnel.listen's,
imported and driven here, not reimplemented.

THE PANEL
---------
One row per dialer:

    name      the port it is on, who it is, whether the port is open

and the buttons to add one, remove one, and stop everything.

WHAT THE PANEL CANNOT DO
------------------------
It cannot open the firewall. That needs an administrator shell, and a
program cannot elevate itself quietly. So the panel SHOWS the command
and says it has to be run in an elevated shell -- which is more use
than an "access denied" with no explanation.
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

try:
    import ljtunnel.listen as L
    from ljtunnel import firewall as FW
    from ljtunnel import paths, sshd
except ImportError:                     # running from a source tree
    _PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _PARENT not in sys.path:
        sys.path.insert(0, _PARENT)
    import ljtunnel.listen as L
    from ljtunnel import firewall as FW
    from ljtunnel import paths, sshd

APP_TITLE = "ljtunnel listen"
POLL_MS = 1000


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("880x600")
        self.minsize(760, 500)

        self.events = queue.Queue()
        self.srv = None
        # The dialers are NOT a list this end keeps.  They are what
        # the sshd's own log and the socket table say is there, and
        # they are read afresh every time the panel is drawn.
        self.listener = L.Listener()

        self._build()
        self.after(120, self._drain)
        self.after(POLL_MS, self._poll)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------ layout

    def _build(self):
        pad = 8
        outer = ttk.Frame(self, padding=pad)
        outer.pack(fill="both", expand=True)

        # -- the server's own state ---------------------------------
        top = ttk.LabelFrame(outer, text="The reachable end", padding=8)
        top.pack(fill="x")

        self.sshd_var = tk.StringVar(value="not running")
        ttk.Label(top, text="sshd").grid(row=0, column=0, sticky="w")
        ttk.Label(top, textvariable=self.sshd_var).grid(
            row=0, column=1, sticky="w", padx=(8, 20))

        self.addr_var = tk.StringVar(value="")
        ttk.Label(top, text="address").grid(row=0, column=2, sticky="w")
        ttk.Label(top, textvariable=self.addr_var).grid(
            row=0, column=3, sticky="w", padx=(8, 20))

        self.fw_var = tk.StringVar(value="")
        ttk.Label(top, text="firewall").grid(row=0, column=4, sticky="w")
        ttk.Label(top, textvariable=self.fw_var).grid(
            row=0, column=5, sticky="w", padx=(8, 0))

        self.btn = ttk.Button(top, text="Start", command=self._toggle)
        self.btn.grid(row=0, column=6, sticky="e", padx=(20, 0))
        top.columnconfigure(5, weight=1)

        # -- the firewall command, when it is needed ----------------
        self.fw_frame = ttk.LabelFrame(
            outer, text="The firewall needs one rule (administrator shell)",
            padding=8)
        self.fw_frame.pack(fill="x", pady=(pad, 0))

        self.fw_text = tk.Text(self.fw_frame, height=3, wrap="none",
                               font=("Consolas", 9))
        self.fw_text.pack(fill="x")
        self.fw_text.insert("1.0", FW.netsh_command())
        self.fw_text.configure(state="disabled")

        ttk.Label(self.fw_frame,
                  text="Run this in a terminal running as administrator. "
                       "Until it is done, the dialers time out with no "
                       "message at all.").pack(anchor="w", pady=(6, 0))

        # -- the dialer, and the key that has to be moved by hand ----
        #
        # There is nothing to ADD.  A dialer arrives, and the panel
        # sees it.  The only thing that has to be moved by hand is the
        # KEY: the dialer's public key goes in this end's key list, or
        # the sshd will not let it in.
        #
        # The name is optional.  A key with no name shows up as its
        # fingerprint, which is enough to tell two dialers apart.
        add = ttk.LabelFrame(outer, text="Let a dialer in", padding=8)
        add.pack(fill="x", pady=(pad, 0))

        ttk.Label(add, text="dialer's public key").grid(
            row=0, column=0, sticky="w")
        self.key_var = tk.StringVar(value="")
        ttk.Entry(add, textvariable=self.key_var).grid(
            row=0, column=1, sticky="w", padx=(4, 12))

        ttk.Label(add, text="name (optional)").grid(row=0, column=2, sticky="w")
        self.name_var = tk.StringVar(value="")
        ttk.Entry(add, textvariable=self.name_var, width=12).grid(
            row=0, column=3, sticky="w", padx=(4, 12))

        ttk.Button(add, text="Let it in", command=self._add).grid(
            row=0, column=4, sticky="e")
        add.columnconfigure(1, weight=1)

        # -- the panel ----------------------------------------------
        mid = ttk.LabelFrame(outer, text="Dialers", padding=6)
        mid.pack(fill="both", expand=True, pady=(pad, 0))

        cols = ("name", "port", "who", "state")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings",
                                  height=10)
        for col, width in (("name", 140), ("port", 80),
                           ("who", 220), ("state", 120)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")
        sb = ttk.Scrollbar(mid, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        row = ttk.Frame(outer)
        row.pack(fill="x", pady=(pad, 0))
        ttk.Button(row, text="Remove", command=self._remove).pack(side="left")
        ttk.Button(row, text="Copy the dialer command",
                   command=self._copy_dialer_cmd).pack(side="left", padx=6)
        ttk.Button(row, text="Copy the access key path",
                   command=self._copy_access_path).pack(side="left")
        ttk.Button(row, text="Open the firewall",
                   command=self._open_firewall).pack(side="left", padx=6)
        ttk.Button(row, text="Copy the firewall command",
                   command=self._copy_fw_cmd).pack(side="left")

        # -- the log ------------------------------------------------
        self.log = tk.Text(outer, wrap="word", height=8, state="disabled",
                           font=("Consolas", 9))
        self.log.pack(fill="x", pady=(pad, 0))

    # ------------------------------------------------------------ events

    def _drain(self):
        """Move whatever the server said onto the screen."""
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "started":
                    self._started(payload)
                elif kind == "error":
                    self._failed(payload)
                elif kind == "log":
                    self._append(payload)
        except queue.Empty:
            pass
        self.after(120, self._drain)

    def _poll(self):
        """Keep the panel current."""
        self._refresh()
        self.after(POLL_MS, self._poll)

    # ------------------------------------------------------------ the server

    def _toggle(self):
        if self.srv and self.srv.poll() is None:
            self._stop()
        else:
            self._start()

    def _start(self):
        self._append("starting ...")
        self._set_button("Stop")
        # The server runs in a thread: the window's after() loop has
        # to stay on the main thread, and tkinter from another thread
        # is the usual way a program crashes at random.
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            paths.ensure_dir(paths.state_dir())
            sshd.ensure_host_key()
            sshd.ensure_client_key()
            sshd.set_authorized_keys(L.read_keys())
            self.srv = self.listener.start()
            time.sleep(1.5)
            if self.srv.poll() is not None:
                why = "the sshd did not start"
                if sshd.port_busy(L.LISTEN_SSHD_PORT):
                    why += f" -- port {L.LISTEN_SSHD_PORT} is held by " \
                           "another process"
                self.events.put(("error", why))
                return
            self.events.put(("started", None))
        except Exception as e:                       # noqa: BLE001
            self.events.put(("error", f"{type(e).__name__}: {e}"))

    def _stop(self):
        self._append("stopping ...")
        if self.srv and self.srv.poll() is None:
            try:
                self.srv.terminate()
                self.srv.wait(timeout=8)
            except Exception:
                pass
        self.srv = None
        sshd.stop()
        self._set_button("Start")
        self.sshd_var.set("not running")
        self._refresh()
        self._append("stopped")

    def _started(self, _payload):
        self._set_button("Stop")
        self.sshd_var.set(f"listening on {L.LISTEN_SSHD_PORT}")
        self.addr_var.set(L.local_ipv4())
        _fw = FW.describe()
        if _fw["installed"]:
            self.fw_var.set(f"the rule is in ({_fw['ports']})")
        else:
            self.fw_var.set("NOT in -- needs an administrator shell")
        self._append(f"the sshd is up on {L.LISTEN_SSHD_PORT}")
        self._append(f"the dialers' ports: "
                     f"{FW.FIRST_FORWARD_PORT}-{FW.LAST_FORWARD_PORT}")
        self._refresh()

    def _failed(self, why):
        self._set_button("Start")
        self.sshd_var.set("not running")
        self._append(f"FAILED: {why}")
        messagebox.showerror(APP_TITLE, why)

    def _set_button(self, text: str, enabled: bool = True) -> None:
        self.btn.configure(text=text)
        self.btn.configure(state="normal" if enabled else "disabled")

    # ------------------------------------------------------------ dialers

    def _add(self):
        """Let a dialer's key in.

        The only thing that has to be done by hand is the KEY: the
        dialer's public key goes in this end's key list, or the sshd
        will not let it in.  Everything else -- which port it gets,
        whether it is there at all -- the listen end works out for
        itself.
        """
        key = self.key_var.get().strip()
        name = self.name_var.get().strip()
        if not key:
            messagebox.showerror(APP_TITLE,
                                 "paste the dialer's public key")
            return
        # a key with a name is one line; a key without one is still
        # one key, and the panel shows its fingerprint
        L.add_key(key, name)
        self._append(f"the key is in the list"
                     + (f", named {name}" if name else ""))
        self.key_var.set("")
        self.name_var.set("")
        self._refresh()

    def _remove(self):
        """Take a dialer's key out of the list.

        The dialer is not stopped by this -- it is a dialer on the
        other machine, and the only thing that stops it is the
        person who runs it.  What this does is stop it being let in
        again, and take its name off the panel.
        """
        sel = self.tree.selection()
        if not sel:
            return
        iid = sel[0]
        fp = self._fingerprints.get(iid, "")
        if fp:
            L.remove_key(fp)
            self._append(f"the key {fp[:24]} is out of the list")
        self._refresh()

    def _refresh(self):
        """Redraw the panel from what the listen end can SEE.

        The dialers are not a list this end keeps: they are read from
        the sshd's log and the socket table, and a dialer that has
        gone leaves its lines in the log and no socket.  So a row is
        here exactly while the port is open.
        """
        want = {}
        self._fingerprints = {}
        for d in self.listener.dialers():
            iid = d.label or d.fingerprint
            # two dialers with the same name would collide in the
            # tree, so the fingerprint is always part of the id
            iid = f"{iid} {d.fingerprint[-6:]}" if d.name else d.fingerprint
            self._fingerprints[iid] = d.fingerprint
            want[iid] = (d.name or d.fingerprint[-12:], str(d.port),
                         d.peer, "open")

        have = {iid: tuple(self.tree.item(iid, "values"))
                for iid in self.tree.get_children()}
        for iid in self.tree.get_children():
            if iid not in want:
                self.tree.delete(iid)
        for iid, values in want.items():
            if iid in have:
                if have[iid] != values:
                    self.tree.item(iid, values=values)
            else:
                self.tree.insert("", "end", iid=iid, values=values)

    def _copy_dialer_cmd(self):
        """The command a NEW dialer runs, copy-pasteable.

        The command does not name a port: the dialer finds a free one
        itself, and if the port it asked for is taken it asks for the
        next.  So one command works for any number of dialers, and
        the same command can be pasted on every box.

        The dialer also needs this end's ACCESS key, in its own key
        list, so the end user can log in.  The access key is public,
        and it goes in the command.
        """
        cmd = L.dialer_command()
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self._append("copied the dialer's command")
        self._append("  " + cmd)
        self._append("")
        self._append("The same command works for every dialer: the port")
        self._append("is found by the dialer, not given to it.")
        self._append("The dialer's own public key has to be in this")
        self._append("end's key list -- paste it in the field above.")
        self._append("  " + sshd.public_key_of(sshd.ensure_client_key()))
        self._append("  (in " + paths.authorized_keys() + ")")

    def _copy_access_path(self):
        """Where the end user's private key is.

        The end user needs the PRIVATE half to log in to a dialer, and
        that file stays on this machine. So the path is what gets
        copied, not the key: the key file is private, and putting it
        on the clipboard would put it wherever the clipboard goes.
        """
        key = sshd.ensure_access_key()
        self.clipboard_clear()
        self.clipboard_append(key)
        self._append("copied the access key's path")
        self._append("  " + key)
        self._append("the end user logs in with:")
        self._append(f"  ssh -i \"{key}\" -p <the dialer's port> "
                     f"<user>@{L.local_ipv4()}")

    def _open_firewall(self):
        """Try to open the ports.

        Adding a firewall rule is an administrator action, and this
        program does not elevate itself. So it tries, and when it
        cannot, it says what to run instead -- which is more use than
        "access denied" and nothing else.
        """
        ok, msg = FW.add_rule()
        self._append("the firewall: " + msg.replace("\n", " "))
        if ok:
            self.fw_var.set(f"the rule is in ({FW.port_spec()})")
        else:
            self.fw_var.set("NOT in -- needs an administrator shell")
            self.clipboard_clear()
            self.clipboard_append(FW.netsh_command())
            messagebox.showinfo(
                APP_TITLE,
                "The firewall rule needs an administrator shell.\n\n"
                "The command has been copied to the clipboard -- paste it "
                "into a terminal running as administrator.\n\n"
                + FW.netsh_command())

    def _copy_fw_cmd(self):
        self.clipboard_clear()
        self.clipboard_append(FW.netsh_command())
        self._append("copied the firewall command")
        self._append("  " + FW.netsh_command())
        self._append("run it in a terminal running as administrator")

    def _append(self, line):
        self.log.configure(state="normal")
        self.log.insert("end", line.rstrip() + "\n")
        self.log.see("end-1c")
        self.log.configure(state="disabled")

    def _on_close(self):
        """The window is closing: take the server down with it.

        The sshd is a child of this process, so it would die with the
        process -- but the window can close while the process lives
        on, and a server left running in that gap keeps the port and
        answers the next launch with the old state.
        """
        if self.srv and self.srv.poll() is None:
            try:
                self.srv.terminate()
                self.srv.wait(timeout=8)
            except Exception:
                pass
        self.srv = None
        sshd.stop()
        self.destroy()


def main(argv=None) -> int:
    """Run the window.

    The dispatcher calls every subcommand's main() with the remaining
    arguments, so this has to accept them even though the window has
    no options.
    """
    if argv:
        print("ljtunnel listen takes no options", file=sys.stderr)
        return 2
    App().mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
