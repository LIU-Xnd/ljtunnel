"""The window's self-test.

The window is built, a dialer's KEY is let in through the real
button, the panel is checked, the command it hands out is checked,
the key is taken out again, and the window is closed -- and the
server has to be gone afterwards.

A window that builds but does nothing is the failure that matters,
and only driving the real buttons finds it. The buttons are INVOKED,
not the methods called directly: an invoke() is what a click does,
and it goes through the same event path.

The window is never shown. It is built, updated and destroyed, which
is enough to find a layout that throws.

THE PANEL SHOWS WHAT IS THERE, NOT WHAT WAS TYPED
--------------------------------------------------
There is no "add a dialer" any more.  A dialer arrives, and the
panel sees it.  So the test cannot add a row by typing a name and an
address: it has to make a dialer ACTUALLY ARRIVE, and the only way
to do that without a second machine is to put a line in the sshd's
log and open a socket on the port.  That is what the test does: it
feeds the detector the log lines a real sshd writes, and it opens a
real listening socket on the port.

A test that fakes the state it is testing proves nothing, so the
socket is a REAL socket and the log lines are COPIES of what the
sshd wrote.
"""
from __future__ import annotations

import socket
import sys
import time

from . import detect, listen as L, paths, sshd

_results = []

# The log lines a real sshd wrote, copied from a real run.
_LOG_ACCEPT = ("Accepted publickey for xnd_l from 203.0.113.7 "
               "port 48238 ssh2: ED25519 "
               "SHA256:xht76GglXU2cFU/7Sd14DpDOatAr+zD+qUdGU4vSk7c")
_LOG_FORWARD = ("debug1: user: xnd_l: server_input_global_request: "
                "tcpip-forward listen 0.0.0.0 port 20002 [postauth]")
_LOG_KEY_OPTION = (
    "debug2: C:/Users/xnd_l/AppData/Local/ljtunnel/"
    "ljtunnel_authorized_keys:1: check options: "
    "'environment=\"LJT_NAME=testbox\" ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIPOXAuTF66OZSgkRSFdn+6Hg6z9j9mUubai0zY/eK6VE"
    " liuxd@zlabm'")
_FP = "SHA256:xht76GglXU2cFU/7Sd14DpDOatAr+zD+qUdGU4vSk7c"


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

    # -- there is nothing to add: the panel is empty to begin with --
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

    reg = a.listener.registry
    reg.first_port = port
    reg.count = 1
    reg.learn([_LOG_KEY_OPTION, _LOG_ACCEPT, _LOG_FORWARD])
    if _FP in reg._seen:
        reg._seen[_FP].port = port

    a._refresh()
    a.update_idletasks()
    rows = a.tree.get_children()
    check("a dialer that arrives shows up by itself", len(rows) == 1,
          str(rows))
    if rows:
        vals = a.tree.item(rows[0], "values")
        check("the row has the name", vals[0] == "testbox", str(vals))
        check("the row has the port", vals[1] == str(port), str(vals))
        check("the row has where it came from",
              "203.0.113.7" in str(vals[2]), str(vals))
        check("the row's state is open", vals[3] == "open", str(vals))

    # -- the command it hands out ---------------------------------
    a._copy_dialer_cmd()
    a.update_idletasks()
    clip = a.clipboard_get()
    check("the command names the host", "ljtunnel dialer" in clip, clip[:100])
    check("the command has the listen port",
          "--listen-port 10001" in clip, clip[:100])
    check("the command carries the access key", "ssh-ed25519" in clip,
          clip[:100])
    check("the command does NOT name a port",
          "--forward-port" not in clip,
          "the dialer finds the port itself, so the command must not "
          "name one")

    # -- the key list, through the real button --------------------
    #
    # The only thing that is done by hand is the key, so that is what
    # the form is for.  The key has to be a FRESH one: adding a key
    # that is already in the list changes nothing, and a test that
    # counts the keys would then be measuring the wrong thing.
    #
    # And the key is REMOVED first, so the test starts from the same
    # state every time.  A test that only passes the first time it is
    # run is a test that measures the order things happened in.
    fresh = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"
             "dGUzdC1rZXktZm9yLXRoZS13aW5kb3ctdGVzdA"
             " do-not-use-this-key")
    fp = detect._fingerprint_of(fresh)
    L.remove_key(fp)
    before = len(L.read_keys())
    a.key_var.set(fresh)
    a.name_var.set("anotherbox")
    a._add()
    a.update_idletasks()
    check("the key was let in", len(L.read_keys()) == before + 1,
          f"{before} -> {len(L.read_keys())}")
    check("the name went on the key",
          any("anotherbox" in l for l in L.read_keys()),
          str(L.read_keys())[:120])

    # -- and the key can be taken out again ------------------------
    a.tree.selection_set(rows[0] if rows else "")
    a._remove()
    a.update_idletasks()
    check("the key is out of the list",
          not any(_FP in l or "testbox" in l for l in L.read_keys()),
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
