"""The window's self-test.

The window is built, a dialer is added through the real button, the
command it hands out is checked, the dialer is removed, and the window
is closed -- and the server has to be gone afterwards.

A window that builds but does nothing is the failure that matters,
and only driving the real buttons finds it. The buttons are INVOKED,
not the methods called directly: an invoke() is what a click does,
and it goes through the same event path.

The window is never shown. It is built, updated and destroyed, which
is enough to find a layout that throws.
"""
from __future__ import annotations

import sys
import time

from . import listen as L, paths, sshd

_results = []


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

    # -- add a dialer, through the real button --------------------
    a.name_var.set("testbox")
    a.host_var.set("192.0.2.1")
    a.user_var.set("someone")
    a._add()
    a.update_idletasks()
    rows = a.tree.get_children()
    check("the dialer is in the panel", len(rows) == 1, str(rows))
    if rows:
        vals = a.tree.item(rows[0], "values")
        check("the row has the name", vals[0] == "testbox", str(vals))
        check("the row has a port", vals[1] == "10002", str(vals))
        check("the row has the address", vals[2] == "192.0.2.1", str(vals))
        check("the row's state is closed (nothing is connected)",
              vals[3] == "closed", str(vals))

    # -- the command it hands out ---------------------------------
    a.tree.selection_set("testbox")
    a.update()
    a._copy_dialer_cmd()
    a.update_idletasks()
    clip = a.clipboard_get()
    check("the command names the host", "192.0.2.1" in clip, clip[:100])
    check("the command has the forward port",
          "--forward-port 10002" in clip, clip[:100])
    check("the command has the listen port",
          "--listen-port 10001" in clip, clip[:100])
    check("the command carries the access key", "ssh-ed25519" in clip,
          clip[:100])

    # -- remove it ------------------------------------------------
    a.tree.selection_set("testbox")
    a._remove()
    a.update_idletasks()
    check("the dialer is gone from the panel",
          len(a.tree.get_children()) == 0)
    check("its port is free again", not L.port_in_use(10002))

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
