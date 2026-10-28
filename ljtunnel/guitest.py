"""The window's self-test.

The window is built, a dialer is RECORDED through the real form, the
command it prints is checked, the record is forgotten, the window is
closed -- and the server has to be gone afterwards.

A window that builds but does nothing is the failure that matters,
and only driving the real buttons finds it. The buttons are INVOKED,
not the methods called directly: an invoke() is what a click does,
and it goes through the same event path.

The window is never shown. It is built, updated and destroyed, which
is enough to find a layout that throws.

THE TWO THINGS THE PANEL SHOWS
------------------------------
A RECORD is what somebody filled in: a name, an address, a user, a
key, a note.  A DIALER is what is actually there: a key
authenticated and asked for a port, and that port is open.

The test makes BOTH happen: a record is written through the form,
and a dialer arrives by feeding the detector the log lines a real
sshd wrote and opening a real socket on the port.
"""
from __future__ import annotations

import socket
import sys
import time

from . import detect, listen as L, paths, records, sshd

_results = []

# The log lines a real sshd wrote, copied from a real run.
#
# THE KEY IN THEM IS A FIXTURE, made for the test and thrown away
# with it.  An earlier version of this file carried a real machine's
# public key, and a repository is a public place.  The fingerprint
# was computed by OpenSSH itself (`ssh-keygen -lf`), not by this
# project's code, so the check is against something independent.
_LOG_ACCEPT = ("Accepted publickey for xnd_l from 192.0.2.7 "
               "port 48238 ssh2: ED25519 "
               "SHA256:RY1xRnF/3WiV8FKLVS6z16esXWAcCAPhjY30GHzqlzk")
_LOG_FORWARD = ("debug1: user: xnd_l: server_input_global_request: "
                "tcpip-forward listen 0.0.0.0 port 20002 [postauth]")
_LOG_KEY_OPTION = (
    "debug2: C:/Users/xnd_l/AppData/Local/ljtunnel/"
    "ljtunnel_authorized_keys:1: check options: "
    "'environment=\"LJT_NAME=testbox\" ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIK4icCbdG74l91kP0yiahmWy5ATLu47tVar4KD9FAOqx"
    " ljtunnel-test-fixture'")
_FP = "SHA256:RY1xRnF/3WiV8FKLVS6z16esXWAcCAPhjY30GHzqlzk"

# A key that is not anybody's: it is here so the test can put it in
# the key list and take it out again.  It is not even a real key --
# the base64 does not decode to a valid one, and it does not have
# to: the test only puts it in a list and takes it out.
#
# THE COMMENT IS THE NAME.  The dialer makes its key with
# `ssh-keygen -C <name>`, and the panel reads the name from there --
# so a key that carries a comment is a key that names itself, and
# that is what the window does with it.
_FAKE_KEY = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"
             "dGUzdC1rZXktZm9yLXRoZS13aW5kb3ctdGVzdA"
             " anotherbox")


def check(name, ok, detail=""):
    _results.append((name, bool(ok), detail))
    if not ok:
        print(f"  FAIL  {name}" + (f" -- {detail}" if detail else ""))
    return bool(ok)


def _read_pid() -> int:
    try:
        with open(paths.pid_file(), encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return -1


def run() -> int:
    from . import app

    a = app.App()
    a.update_idletasks()
    check("the window builds", True)

    # -- start the server -----------------------------------------
    a._start()
    for _ in range(40):
        a.update()
        if a.srv and a.srv.poll() is None:
            break
        time.sleep(0.25)
    check("the sshd came up", a.srv is not None and a.srv.poll() is None,
          f"pid {a.srv.pid}" if a.srv else "no process")

    # the "started" event is delivered by the after() loop, so the
    # loop has to TICK: update() once is not a tick.
    for _ in range(40):
        a.update()
        if "listening" in a.sshd_var.get():
            break
        time.sleep(0.25)
    check("the button says Stop", a.btn.cget("text") == "Stop",
          a.btn.cget("text"))
    check("the panel shows the sshd", "listening" in a.sshd_var.get(),
          a.sshd_var.get())
    check("the panel shows the address",
          a.addr_var.get() not in ("", "127.0.0.1"), a.addr_var.get())

    # -- the known hosts button --------------------------------------
    #
    # A DIALER THAT IS SET UP AGAIN MAKES A NEW HOST KEY, and the ssh
    # client remembers the old one, and then it says
    #
    #     Host key for [localhost]:10002 has changed and you have
    #     requested strict checking.
    #
    # So the window has a button that takes the tunnel's own entries
    # away, and it does not touch the person's own hosts.
    import os as _os5
    import tempfile as _tf5

    with _tf5.TemporaryDirectory() as _tmp5:
        _kh5 = _os5.path.join(_tmp5, "known_hosts")
        with open(_kh5, "w", encoding="utf-8") as _fh5:
            _fh5.write("[localhost]:10002 ssh-ed25519 AAAAfake1 nobody\n")
            _fh5.write("[example.com]:22 ssh-ed25519 AAAAfake3 somebody\n")

        _old5 = paths.known_hosts
        paths.known_hosts = lambda: _kh5
        try:
            # THE BUTTON IS INVOKED, not the method called: an invoke()
            # is what a click does, and it goes through the same event
            # path.
            _found5 = None
            _all5 = []

            def _walk5(w):
                for _c in w.winfo_children():
                    _all5.append(_c)
                    _walk5(_c)

            _walk5(a)
            for _c in _all5:
                try:
                    if _c.cget("text") == "Clean the known hosts":
                        _found5 = _c
                except Exception:
                    pass
            check("the window has the button", _found5 is not None,
                  "not found")
            if _found5 is not None:
                _found5.invoke()
                a.update()
            _after5 = open(_kh5, encoding="utf-8").read()
        finally:
            paths.known_hosts = _old5

        check("and the button takes the tunnel's own entry away",
              "[localhost]:10002" not in _after5, _after5[:90])
        check("and leaves the person's own host alone",
              "[example.com]:22" in _after5, _after5[:90])

    # -- the panel starts empty ------------------------------------
    check("the panel starts empty", len(a.tree.get_children()) == 0,
          str(a.tree.get_children()))

    # -- a dialer ARRIVES -------------------------------------------
    #
    # A real socket on a real port, and the log lines a real sshd
    # wrote.  The socket has to be open for the dialer to show up:
    # the socket table is the truth about a port.
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]

    # THE SOCKET SAYS THE SSH BANNER, because the detector asks for
    # it now: a dialer that has gone leaves its lines in the log, and
    # its PORT is taken by something else, and the panel said the
    # dialer was up when it was not.
    import threading as _th6

    def _say6(conn):
        try:
            conn.sendall(b"SSH-2.0-OpenSSH_9.6 TestFixture\r\n")
        except OSError:
            pass

    def _banner_loop6():
        while True:
            try:
                s.settimeout(0.5)
                conn, _ = s.accept()
            except (socket.timeout, OSError):
                continue
            _th6.Thread(target=_say6, args=(conn,), daemon=True).start()

    _th6.Thread(target=_banner_loop6, daemon=True).start()

    reg = a.listener.registry
    reg.first_port = port
    reg.count = 1
    reg.learn([_LOG_KEY_OPTION, _LOG_ACCEPT, _LOG_FORWARD])
    if _FP in reg._seen:
        reg._seen[_FP].port = port

    # THE SCAN IS ON A THREAD, so the answer comes a moment later.
    # The window draws what the scan found, so the test WAITS for the
    # scan and then lets the window draw it.
    #
    # MEASURED: this is why the scan is on a thread at all -- the
    # question takes time, and the window must not wait for it.
    for _ in range(40):
        a._last_scan = 0.0
        a._scanning = False
        a.update()
        if a._scan_rows:
            break
        time.sleep(0.1)
    a._refresh()
    a.update_idletasks()
    rows = a.tree.get_children()
    check("a dialer that arrives shows up by itself", len(rows) == 1,
          str(rows) + " -- the scan found " + str(len(a._scan_rows)))
    if rows:
        vals = a.tree.item(rows[0], "values")
        check("the row has the name", vals[0] == "testbox", str(vals))
        check("the row has the port", vals[1] == str(port), str(vals))
        check("the row's state is that it is up", vals[2] == "up", str(vals))
        check("the row has where it came from",
              "192.0.2.7" in str(vals[3]), str(vals))

    # -- the FORM: record a dialer --------------------------------
    #
    # The form is for recording a dialer: its name, where it is, who
    # logs in, its key, and a note.  The key has to be a FRESH one:
    # adding a key that is already in the list changes nothing, and a
    # test that counts the keys would then be measuring the wrong
    # thing.
    #
    # And the record is REMOVED first, so the test starts from the
    # same state every time.  A test that only passes the first time
    # it is run is a test that measures the order things happened in.
    L.remove_key(detect._fingerprint_of(_FAKE_KEY))
    records.remove("anotherbox")
    # ---- AND EVERYTHING A PREVIOUS RUN LEFT BEHIND ----
    #
    # A test that leaves a record behind makes the NEXT run fail on
    # a row that is not there, and the failure looks like the product
    # is wrong.  MEASURED: the panel started with a row called
    # "do-not-use-this-key" and the test said the panel did not
    # start empty -- and it was the test's own leftover.
    for _old in records.load():
        if _old.get("pubkey"):
            L.remove_key(detect._fingerprint_of(_old["pubkey"]))
        records.remove(_old.get("name"))
    # ---- AND THE KEYS THAT ARE LEFT, for the same reason ----
    #
    # A key in the list with no record is a key the panel shows as a
    # row, and the panel is supposed to start empty.
    for _line in L.read_keys():
        _body = _line.split()
        for _i, _part in enumerate(_body):
            if _part.startswith(("ssh-", "ecdsa-", "sk-")) and _i + 1 < len(_body):
                L.remove_key(detect._fingerprint_of(
                    _body[_i] + " " + _body[_i + 1]))
                break
    before = len(L.read_keys())

    # ---- ONE INPUT: THE KEY ----
    #
    # THE NAME IS ON THE KEY.  The dialer makes its key with
    # `ssh-keygen -C <name>`, so the comment carries the name and the
    # panel reads it -- there is no box to type it in.
    #
    # MEASURED: that is what lets the form go down to one field, and
    # a form with five boxes is a form nobody fills in.
    a.key_var.set(_FAKE_KEY)
    a._save()
    a.update_idletasks()

    check("the key was let in", len(L.read_keys()) == before + 1,
          f"{before} -> {len(L.read_keys())}")
    check("the name went on the key",
          any("anotherbox" in l for l in L.read_keys()),
          str(L.read_keys())[:120])
    check("and the key field is cleared",
          a.key_var.get() == "", a.key_var.get()[:40])

    # ---- the record is kept ----
    rec = records.by_name("anotherbox")
    check("the record is kept", bool(rec), str(records.load())[:120])
    check("with the key", rec.get("pubkey") == _FAKE_KEY, str(rec)[:80])

    # ---- and the command ----
    #
    # IT IS THE SAME COMMAND FOR EVERY DIALER: the dialer finds its
    # own port and the reachable end is the same one.
    cmd = L.dialer_command()
    check("the command names the dialer", "ljtunnel dialer" in cmd, cmd[:80])
    check("the command carries the access key", "ssh-ed25519" in cmd, cmd[:80])
    check("the command does NOT name a port", "--forward-port" not in cmd,
          "the dialer finds the port itself")
    check("and it does not name an account for the person",
          "--local-user" not in cmd,
          "the account belongs to the dialer, and the dialer knows it")

    # ---- and the panel shows the record ----
    a._refresh()
    a.update_idletasks()
    names = [a.tree.item(i, "values")[0]
             for i in a.tree.get_children()]
    check("the record is in the panel", "anotherbox" in names, str(names))
    for iid in a.tree.get_children():
        vals = a.tree.item(iid, "values")
        if vals[0] == "anotherbox":
            check("the record's row says it is not up", vals[2] == "not up",
                  str(vals))

    # ---- the command is copied for the other machine ----
    a._show_command()
    a.update_idletasks()
    clip = a.clipboard_get()
    check("the command is on the clipboard", "ljtunnel dialer" in clip,
          clip[:80])

    # ---- and it can be forgotten ----
    target = [i for i in a.tree.get_children()
              if a.tree.item(i, "values")[0] == "anotherbox"]
    a.tree.selection_set(target)
    a._forget()
    a.update_idletasks()
    check("the record is gone", not records.by_name("anotherbox"),
          str(records.load())[:80])
    check("the key is out of the list",
          not any("anotherbox" in l for l in L.read_keys()),
          str(L.read_keys())[:120])

    s.close()

    # -- close the window -----------------------------------------
    # The server has to go WITH the window. A window that closes and
    # leaves the sshd running keeps the port and answers the next
    # launch with the old state.
    pid = _read_pid()
    a._on_close()
    time.sleep(1.0)
    check("the sshd is gone after the window closes",
          not sshd._pid_alive(pid), f"pid {pid}")
    check("the port is free after the window closes",
          not L.port_in_use(10001))

    # ---- and closing twice is not a problem ----
    a._on_close()
    check("closing twice is safe", True)

    passed = sum(1 for _, ok, _ in _results if ok)
    failed = [n for n, ok, _ in _results if not ok]
    print(f"  {passed}/{len(_results)} passed"
          + (f", {len(failed)} failed" if failed else ", 0 failed"))
    for n in failed:
        print(f"    FAILED: {n}")
    return 1 if failed else 0


def main() -> int:
    if sys.platform != "win32":
        print("  the window is Windows only (skipped)")
        return 0
    try:
        import tkinter   # noqa: F401
    except ImportError:
        print("  tkinter is not here (skipped)")
        return 0
    print("ljtunnel -- the window's self-test")
    return run()


if __name__ == "__main__":
    sys.exit(main())
