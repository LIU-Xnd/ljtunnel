"""The listen end's window.

A panel over the server: the dialers that are recorded, the ones that
are here, and the command to run on a box.

THE TWO THINGS
--------------
A RECORD is what somebody filled in: this dialer is called box-a, it
is at this address, its key is this, and here is the command to run
on it.  A record is kept whether or not the dialer is up.

A DIALER is what is actually there: a key authenticated and asked for
a port, and that port is open.  The listen end works this out by
itself, from the sshd's log and the socket table.

So a row can be a record with no dialer (the box is not running yet),
a dialer with no record (it was let in before the records existed),
or both.  The panel shows them together, because the two questions
are different: "what did I set up" and "what is up right now".

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
    from ljtunnel import detect, elevate, firewall as FW
    from ljtunnel import paths, records, sshd
except ImportError:                     # running from a source tree
    _PARENT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _PARENT not in sys.path:
        sys.path.insert(0, _PARENT)
    import ljtunnel.listen as L
    from ljtunnel import detect, elevate, firewall as FW
    from ljtunnel import paths, records, sshd

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
        self._closed = False
        self._interrupted = False
        self._records = {}
        # The dialers are NOT a list this end keeps.  They are what
        # the sshd's own log and the socket table say is there, and
        # they are read afresh every time the panel is drawn.
        self.listener = L.Listener()

        self._build()
        self.admin_var.set("administrator" if elevate.is_admin()
                           else "not an administrator")
        self._after_ids = set()
        self._after_ids.add(self.after(120, self._drain))
        self._after_ids.add(self.after(POLL_MS, self._poll))
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        _install_sigint(self)

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

        # Whether the app is an administrator.  It says so, because
        # "the firewall rule is not in" and "this app cannot add it"
        # are different problems and a person needs to know which.
        self.admin_var = tk.StringVar(value="")
        ttk.Label(top, text="rights").grid(row=1, column=0, sticky="w",
                                           pady=(4, 0))
        ttk.Label(top, textvariable=self.admin_var).grid(
            row=1, column=1, sticky="w", padx=(8, 20), pady=(4, 0))

        self.btn = ttk.Button(top, text="Start", command=self._toggle)
        self.btn.grid(row=0, column=6, sticky="e", padx=(20, 0))
        top.columnconfigure(5, weight=1)

        # -- the firewall command, when it is needed ----------------
        self.fw_frame = ttk.LabelFrame(
            outer, text="The firewall needs one rule", padding=8)
        self.fw_frame.pack(fill="x", pady=(pad, 0))

        self.fw_text = tk.Text(self.fw_frame, height=3, wrap="none",
                               font=("Consolas", 9))
        self.fw_text.pack(fill="x")
        self.fw_text.insert("1.0", FW.netsh_command())
        self.fw_text.configure(state="disabled")

        ttk.Label(self.fw_frame,
                  text="Until the rule is in, the dialers time out with no "
                       "message at all.").pack(anchor="w", pady=(6, 0))

        # -- the dialers, and the form that records them -------------
        #
        # The form is for RECORDING a dialer: its name, where it is,
        # who logs in, and its key.  What it does NOT do is decide
        # which port the dialer gets -- the dialer finds a free one
        # itself -- and it does not decide whether the dialer is up.
        # The panel works that out by itself.
        add = ttk.LabelFrame(outer, text="Record a dialer", padding=8)
        add.pack(fill="x", pady=(pad, 0))

        ttk.Label(add, text="name").grid(row=0, column=0, sticky="w")
        self.name_var = tk.StringVar(value="")
        ttk.Entry(add, textvariable=self.name_var, width=14).grid(
            row=0, column=1, sticky="w", padx=(4, 12))

        ttk.Label(add, text="address").grid(row=0, column=2, sticky="w")
        self.host_var = tk.StringVar(value="")
        ttk.Entry(add, textvariable=self.host_var, width=16).grid(
            row=0, column=3, sticky="w", padx=(4, 12))

        ttk.Label(add, text="user here").grid(row=0, column=4, sticky="w")
        self.user_var = tk.StringVar(value="")
        self.user_entry = ttk.Entry(add, textvariable=self.user_var, width=10)
        self.user_entry.grid(row=0, column=5, sticky="w", padx=(4, 12))
        ttk.Label(add, text="(the user on THIS machine -- leave it "
                            "empty for yours)").grid(
            row=1, column=0, columnspan=6, sticky="w", pady=(2, 0))

        ttk.Label(add, text="dialer's public key").grid(
            row=2, column=0, sticky="w", pady=(6, 0))
        self.key_var = tk.StringVar(value="")
        ttk.Entry(add, textvariable=self.key_var).grid(
            row=2, column=1, columnspan=5, sticky="ew", padx=(4, 12),
            pady=(6, 0))

        ttk.Label(add, text="notes").grid(row=3, column=0, sticky="w",
                                          pady=(6, 0))
        self.note_var = tk.StringVar(value="")
        ttk.Entry(add, textvariable=self.note_var).grid(
            row=3, column=1, columnspan=5, sticky="ew", padx=(4, 12),
            pady=(6, 0))

        buttons = ttk.Frame(add)
        buttons.grid(row=4, column=0, columnspan=6, sticky="w", pady=(8, 0))
        ttk.Button(buttons, text="Save", command=self._save).pack(side="left")
        ttk.Button(buttons, text="Show the command",
                   command=self._show_command).pack(side="left", padx=6)
        ttk.Button(buttons, text="Forget",
                   command=self._forget).pack(side="left")
        add.columnconfigure(1, weight=1)
        add.columnconfigure(3, weight=1)

        # -- the panel ----------------------------------------------
        mid = ttk.LabelFrame(outer, text="Dialers", padding=6)
        mid.pack(fill="both", expand=True, pady=(pad, 0))

        cols = ("name", "port", "state", "where", "notes")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings",
                                  height=10)
        for col, width in (("name", 130), ("port", 60),
                           ("state", 90), ("where", 150), ("notes", 180)):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")
        sb = ttk.Scrollbar(mid, orient="vertical",
                            command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        row = ttk.Frame(outer)
        row.pack(fill="x", pady=(pad, 0))
        ttk.Button(row, text="Copy the command",
                   command=self._copy_selected).pack(side="left")
        ttk.Button(row, text="Copy the access key path",
                   command=self._copy_access_path).pack(side="left", padx=6)
        ttk.Button(row, text="Be an administrator",
                   command=self._ask_to_be_admin)
        ttk.Button(row, text="Open the firewall",
                   command=self._open_firewall).pack(side="left")
        ttk.Button(row, text="Copy the firewall command",
                   command=self._copy_fw_cmd).pack(side="left", padx=6)

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
                elif kind == "firewall":
                    self._firewall_done(*payload)
        except queue.Empty:
            pass
        if not self._closed:
            self._after_ids.add(self.after(120, self._drain))

    def _poll(self):
        """Keep the panel current, and notice a Ctrl-C."""
        if self._closed:
            return
        if self._interrupted:
            self._append("Ctrl-C: stopping ...")
            self._on_close()
            return
        self._refresh()
        self._after_ids.add(self.after(POLL_MS, self._poll))

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
                # the port the LISTENER was built with, not the
                # module's constant: the two can differ, and a
                # message about the wrong port sends the reader
                # looking at the wrong thing
                if sshd.port_busy(self.listener.sshd_port):
                    why += f" -- port {self.listener.sshd_port} is held by " \
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

    def _save(self):
        """Record the dialer the form describes.

        The record says what this dialer IS: its name, where it is,
        who logs in, and its key.  It does not say which port it gets
        -- the dialer finds a free one -- and it does not say whether
        it is up: the panel works that out by itself.

        The key, if there is one, goes into this end's key list, so
        the dialer is let in.  A record with no key is still a record:
        it is a box that has not been set up yet, and the command
        that sets it up is what the panel prints.
        """
        name = self.name_var.get().strip()
        host = self.host_var.get().strip()
        user = self.user_var.get().strip()
        key = self.key_var.get().strip()
        note = self.note_var.get().strip()

        if not name and not host and not key:
            messagebox.showerror(APP_TITLE,
                                 "a record needs at least a name")
            return

        rec = records.add(name or key[:24], key, host, user, note)
        if key:
            L.add_key(key, rec["name"])
            self._append(f"the key is in the list, named {rec['name']}")
        self._append(f"recorded {rec['name']}")
        self._append(f"  the command it runs:")
        self._append(f"    {records.command_for(rec)}")
        self._refresh()

    def _forget(self):
        """Forget the selected record, and take its key out of the list.

        The dialer is not stopped by this -- it is a dialer on the
        other machine, and the only thing that stops it is the
        person who runs it.  What this does is stop it being let in
        again, and take it off the panel.
        """
        sel = self.tree.selection()
        if not sel:
            messagebox.showerror(APP_TITLE, "pick a row first")
            return
        iid = sel[0]
        rec = self._records.get(iid)
        if not rec:
            return
        if rec.get("pubkey"):
            L.remove_key(detect._fingerprint_of(rec["pubkey"]))
        records.remove(rec["name"])
        self._append(f"forgotten {rec['name']}")
        self._refresh()

    def _show_command(self):
        """Show the command the recorded dialer runs.

        The command is for the dialer to RUN, on the other machine.
        It is shown in the log, and it is copied to the clipboard, so
        it can be pasted into a terminal over there.
        """
        rec = self._form_record()
        cmd = records.command_for(rec)
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self._append(f"the command for {rec['name']}:")
        self._append(f"  {cmd}")
        self._append("  (copied -- paste it on the dialer machine)")

    def _copy_selected(self):
        """The command for the SELECTED row, copied.

        The clipboard is the point: the command is run on another
        machine, and the fastest way to get it there is to paste it.
        """
        sel = self.tree.selection()
        if not sel:
            messagebox.showerror(APP_TITLE, "pick a row first")
            return
        rec = self._records.get(sel[0])
        if not rec:
            return
        cmd = records.command_for(rec)
        self.clipboard_clear()
        self.clipboard_append(cmd)
        self._append(f"copied the command for {rec['name']}")
        self._append(f"  {cmd}")

    def _form_record(self) -> dict:
        """The record the form describes, with the form's values."""
        name = self.name_var.get().strip()
        return {
            "name": name or "a dialer",
            "host": self.host_var.get().strip(),
            "user": self.user_var.get().strip(),
            "pubkey": self.key_var.get().strip(),
            "note": self.note_var.get().strip(),
        }

    def _refresh(self):
        """Redraw the panel: the records, and the dialers that are up.

        The two are joined by NAME.  A record whose name is on a live
        dialer is that dialer; a record with no live dialer is a box
        that is not running yet; a live dialer with no record is one
        that was let in before the records existed, and it is shown
        under its fingerprint.
        """
        want = {}
        self._records = {}

        # the dialers that are up, by name
        live = {}
        for d in self.listener.dialers():
            live[d.name or d.fingerprint] = d

        # the records first: a record is a row whether or not its
        # dialer is here
        for rec in records.load():
            name = rec.get("name") or rec.get("pubkey", "")[:24]
            d = live.pop(name, None)
            self._records[name] = rec
            want[name] = (
                name,
                str(d.port) if d else "",
                "up" if d else "not up",
                rec.get("host") or (d.peer if d else ""),
                rec.get("note", ""),
            )

        # and then the live dialers with no record
        for key, d in live.items():
            self._records[key] = {"name": key, "pubkey": "",
                                   "host": d.peer, "user": "", "note": ""}
            want[key] = (key, str(d.port), "up", d.peer, "")

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
        """Open the ports.

        If the app is ALREADY an administrator, the rule goes in
        with no prompt at all: the app asked to be an administrator
        when it started, and the person answered that prompt once.

        If it is not -- the person declined the prompt at start-up,
        or the app is running from a source tree -- then THIS step
        asks for it, and the UAC prompt appears here.  So declining
        at the start is not a dead end: the rule is still one click
        and one "Yes" away.

        The window is not blocked while it waits: the prompt is
        MODAL to the elevated process, not to this one, so the person
        can carry on with the window while they decide.
        """
        if elevate.is_admin():
            self._append("the firewall: adding the rule ...")
            self.fw_var.set("adding the rule ...")
        else:
            self._append("the firewall: asking for the UAC prompt ...")
            self.fw_var.set("waiting for the UAC prompt ...")

        def work():
            # Not on the main thread: the elevation starts a process
            # and waits for it to write its answer, and the window
            # has to stay alive while that happens.
            ok, msg = FW.add_rule()
            self.events.put(("firewall", (ok, msg)))

        threading.Thread(target=work, daemon=True).start()

    def _ask_to_be_admin(self):
        """Ask to be an administrator, now.

        The app asks for this when it starts, so the button is for
        the person who declined that prompt and wants it after all.

        THE PROMPT IS ON THE SECURE DESKTOP.  Windows takes the
        screen over for it, and it is gone when the answer is
        given.  So a person who is not watching for it may not see
        it -- and the consent for an administrator is cached for a
        short while, so the second one may not come either.

        The button therefore says what is going on, and the app is
        restarted as an administrator if the answer is yes.
        """
        if elevate.is_admin():
            self._append("this app is already an administrator")
            self.admin_var.set("administrator")
            return

        self._append("asking to be an administrator -- Windows will "
                     "take the screen over for the prompt")
        started, why = elevate.relaunch_elevated()
        if started:
            self._append("  the app is starting as an administrator")
            self._append("  this window will close")
            self._on_close()
            return
        self._append("  no: " + why)
        messagebox.showinfo(
            APP_TITLE,
            "The app could not start as an administrator.\n\n" + why
            + "\n\nThe firewall button will ask for it on its own.")

    def _firewall_done(self, ok, msg):
        """The firewall rule is in, or it is not.

        Either way the window says which, because "nothing happened"
        is not a state a person can act on.
        """
        self._append("the firewall: " + msg.replace("\n", " "))
        if ok:
            self.fw_var.set(f"the rule is in ({FW.port_spec()})")
            return
        self.fw_var.set("NOT in")
        if "declined" in msg:
            # the person said no.  That is an answer, not a failure,
            # so it is not dressed up as one.
            messagebox.showinfo(
                APP_TITLE,
                "The UAC prompt was declined, so the firewall rule is "
                "not in.\n\n"
                "Until it is, the dialers time out with no message at "
                "all.")
            return
        # it did not work, and the reason is not that the person said
        # no: so the command is the way forward
        self.clipboard_clear()
        self.clipboard_append(FW.netsh_command())
        messagebox.showinfo(
            APP_TITLE,
            "The firewall rule did not go in.\n\n"
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

    def _stop_server(self):
        """Stop the sshd.  This does not touch Tk, so it is safe from
        any thread.

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

    def _on_close(self):
        """The window is closing: take the server down with it.

        The shutdown is done ONCE.  The window can be closed by the
        X, by Ctrl-C, or by the program being asked to quit, and two
        of those can happen at the same time: the second one would
        find a half-stopped server and the port would still be held.

        destroy() alone is NOT enough.  A window that is destroyed
        from inside an after() callback leaves the main loop RUNNING:
        the callbacks are all gone, so the loop has nothing to do and
        spins without ever returning.  So the loop is asked to QUIT
        as well.
        """
        if self._closed:
            return
        self._closed = True

        self._stop_server()

        # the after() callbacks are cancelled, so the poll does not
        # carry on against a window that is going away
        for _id in list(self._after_ids):
            try:
                self.after_cancel(_id)
            except Exception:
                pass
        self._after_ids = set()

        try:
            self.quit()
        except Exception:
            pass
        try:
            self.destroy()
        except Exception:
            pass

    def _on_sigint(self, signum, frame):
        """Ctrl-C was pressed.

        The handler does NOTHING but raise a flag.  Tk's own calls
        are not safe from a signal handler: the handler runs between
        two bytecodes, and calling into Tk then can leave the
        toolkit in a state it does not expect.  So the flag is
        noticed by the poll, which runs in the main loop where
        calling Tk is what it is for.

        Without this, Ctrl-C kills the process where it stands: the
        sshd is a child, so it would go too, but the ports it had are
        not released cleanly and the next launch finds a port that is
        busy for no reason anybody can see.
        """
        self._interrupted = True


def _install_sigint(app) -> None:
    """Make Ctrl-C close the window, cleanly.

    There is no console in the Windows launcher, so Ctrl-C is not
    something a person presses there.  But the console launcher is
    the same program, and on Linux the window is not used at all.

    THE SIGNAL HANDLER ITSELF DOES NOTHING BUT SET A FLAG.

    Tk's own calls are not safe from a signal handler: the handler
    runs between two bytecodes of the main thread, and calling into
    the toolkit from there can leave it in a state it does not
    expect.  It is worse than that on Windows, where a Ctrl-C
    arrives as a console event that Python turns into a SIGINT on
    the main thread -- and the main thread is inside the Tk event
    loop, not at a bytecode boundary where a handler is welcome.

    So a THREAD waits for the flag and does the work.  The thread is
    the one thing that can touch the server and the toolkit safely
    enough, and the main loop is left to notice that it is time to
    stop.
    """
    import signal
    import threading

    def _handler(signum, frame):
        # Nothing is called here.  A flag, and nothing else.
        app._interrupted = True

    try:
        signal.signal(signal.SIGINT, _handler)
    except (ValueError, OSError, AttributeError):
        # Not the main thread, or the platform has no SIGINT.
        pass

    # SIGBREAK is the Windows BREAK.  A process in its own process
    # group IGNORES a console Ctrl-C, so the break is the event it
    # actually gets -- and a program that is launched with its own
    # console is in its own group.
    #
    # Python's default handler for it raises KeyboardInterrupt, so
    # without this it would work by accident.  It is handled
    # explicitly because "by accident" is not a decision.
    if hasattr(signal, "SIGBREAK"):
        try:
            signal.signal(signal.SIGBREAK, _handler)
        except (ValueError, OSError, AttributeError):
            pass

    if not hasattr(signal, "SIGINT"):
        return

    def _watch():
        while not app._closed:
            if app._interrupted:
                app._interrupted = False
                try:
                    # The server is stopped HERE, on this thread: it
                    # does not touch Tk, so it is safe.  The window
                    # is closed by the MAIN LOOP, which is the only
                    # thread allowed to touch the toolkit.
                    app._stop_server()
                    app.after(0, app._on_close)
                except Exception:
                    pass
                return
            time.sleep(0.2)

    t = threading.Thread(target=_watch, daemon=True,
                         name="ljtunnel-sigint")
    t.start()


def _record_start(what: str) -> None:
    """Write down how the app started.

    It is a small file in the state directory, and it says one of
    two things: "elevated" -- the app asked to be an administrator
    and the person said yes -- or "plain" -- it did not, or it
    could not.

    WHY IT IS WORTH WRITING DOWN.  The difference between the two is
    invisible from the outside: the window looks the same, and the
    only thing that changes is whether the firewall button needs a
    prompt.  So when the dialers time out and nobody knows why, this
    is the file that says which of the two things happened.

    THE THREE VALUES:
      elevated      the app is an administrator
      plain         it is not, and it is carrying on without
      handing over  it has started an elevated copy and is going away
    """
    try:
        paths.ensure_dir(paths.state_dir())
        with open(paths.start_record(), "w", encoding="utf-8",
                  newline="\n") as fh:
            fh.write(what + "\n")
    except OSError:
        pass


def main(argv=None) -> int:
    """Run the window, as an administrator if it can be.

    THE APP IS AN ADMINISTRATOR, so the firewall rule needs no
    prompt of its own.

    The window needs administrator rights for exactly one thing: the
    firewall rule.  Windows blocks inbound connections to a port it
    has not been told about, and it does it SILENTLY -- the dialer
    times out with no error on either side and nothing says
    "firewall".

    So the app asks to be an administrator ONCE, at the start, rather
    than asking every time the rule is needed.  The UAC prompt
    appears once, the person answers it once, and the firewall
    button does its work with no prompt at all afterwards.

    A person who presses "No" gets the app WITHOUT the elevation,
    and the firewall button then asks for it on its own, for that
    one step.  So declining is not a dead end.
    """
    # THE FLAG SAYS "you are the elevated one".
    #
    # The elevated copy starts the SAME program, and that program
    # asks to be an administrator when it starts.  So the elevated
    # copy is told, in its arguments, that it does not have to ask.
    # Without that, the two copies ask each other to start, forever
    # -- which is not a hypothetical: it happened.
    if argv and elevate.ELEVATED_FLAG in argv:
        argv = [a for a in argv if a != elevate.ELEVATED_FLAG]
        _record_start("elevated")
        return _run_window(argv)

    if sys.platform == "win32" and not elevate.is_admin():
        started, why = elevate.relaunch_elevated(argv)
        if started:
            # The elevated copy is running now.  This one has to go:
            # two windows would be two panels showing the same state,
            # and this one cannot do the work.
            #
            # The record is written by the ELEVATED copy, which is
            # the one that is actually running.  This one writes
            # "handing over" so that a record left behind by a
            # crash is not read as "the app is running".
            _record_start("handing over")
            return 0
        # The person said no, or the elevation did not happen.  Carry
        # on without it: the firewall button asks for it on its own.
        if why == "the UAC prompt was declined":
            print("the UAC prompt was declined -- the firewall rule "
                  "will ask for the elevation by itself", file=sys.stderr)
        else:
            print("could not run as an administrator: " + why,
                  file=sys.stderr)
        _record_start("plain")
    else:
        _record_start("elevated")

    return _run_window(argv)


def _run_window(argv=None) -> int:
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
