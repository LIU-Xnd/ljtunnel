"""Does the program shut down cleanly when it is interrupted?

What matters is the PROGRAM's side: it gets a signal, it stops the
sshd, it releases the port, and it exits.

HOW THE SIGNAL IS DELIVERED
----------------------------
On Linux it is SIGINT, sent with a signal.

On Windows it is a console event.  And the Windows documentation is
explicit about which one:

    "This function ignores CTRL_C_EVENT for a process that is in a
     process group that was created with CREATE_NEW_PROCESS_GROUP.
     However, CTRL_BREAK_EVENT is not ignored."

So a program in its own process group -- which is what a program
launched with its own console is -- gets the BREAK, not the Ctrl-C.
Python turns a console break into SIGBREAK, and its default handler
raises KeyboardInterrupt, exactly like SIGINT.

The test sends the break, and checks what the program DOES with it.

THE MEASUREMENT
---------------
The port is checked before and after.  That is the thing that
matters: a program that is killed with the port still held leaves
the next launch to find a port that is busy for no reason anybody
can see.

AND THE LEFTOVERS
-----------------
The count of the processes that are left is on the process NAME, not
on the command line: a command line filter matches the PowerShell
that is doing the filtering, because the filter text is in its own
command line.  That is a test that measures itself.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

from ljtunnel import paths, sshd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The port the test uses.  It is the real one, because the point is
# that the REAL server releases the REAL port.
LISTEN_PORT = 10001

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))
    return ok


def listening(port):
    """How many things are listening on this port."""
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         f"(Get-NetTCPConnection -State Listen -LocalPort {port} "
         "-ErrorAction SilentlyContinue | Measure-Object).Count"],
        capture_output=True, text=True, errors="replace", timeout=60)
    try:
        return int((r.stdout or "0").strip())
    except ValueError:
        return 0


def ljt_processes():
    """How many ljtunnel sshd sessions are left.

    The filter is on the process NAME, not on the command line: a
    command line filter matches the PowerShell that is doing the
    filtering, because the filter text is in its own command line.
    That is a test that measures itself.

    And the SYSTEM sshd is not ljtunnel's, so it is not counted: it
    is there before the test starts and it is there after it, and it
    is not an sshd-session.
    """
    import re

    config = os.path.basename(paths.sshd_config())
    # `-match`, NOT `-like`.
    #
    # IN THIS POWERSHELL THE WILDCARD OPERATOR DOES NOT WORK:
    #
    #     'abc.exe' -like 'abc%'   ->   False
    #
    # MEASURED: that is what it says.  `-eq` and `-match` both work.
    # So a filter written with `-like` matches NOTHING, the count is
    # zero, and the test passes while the sessions are still there.
    #
    # The name filter is in the WQL, not in the PowerShell, and WQL's
    # LIKE is a different thing that does work.
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         "(Get-CimInstance Win32_Process -Filter "
         "\"Name LIKE 'sshd-session%'\" -ErrorAction SilentlyContinue | "
         "Where-Object { $_.CommandLine -match "
         f"'{re.escape(config)}' }} | Measure-Object).Count"],
        capture_output=True, text=True, errors="replace", timeout=60)
    return (r.stdout or "").strip()


def send_break(proc):
    """The console break, to the process's own group."""
    if sys.platform == "win32":
        import ctypes
        # CTRL_BREAK_EVENT: the one a process group does NOT ignore
        return bool(ctypes.windll.kernel32.GenerateConsoleCtrlEvent(
            1, proc.pid))
    proc.send_signal(signal.SIGINT)
    return True


CONSOLE_SCRIPT = '''\
import sys, time
sys.path.insert(0, r"{root}")
from ljtunnel import listen
sys.argv = ["ljtunnel", "listen"]
try:
    listen.main([])
except SystemExit:
    pass
print("EXITED", flush=True)
'''

WINDOW_SCRIPT = '''\
import sys, time
sys.path.insert(0, r"{root}")
from ljtunnel import app

a = app.App()
a._start()
for _ in range(60):
    a.update()
    if a.srv and a.srv.poll() is None:
        break
    time.sleep(0.25)
print("READY", flush=True)
a.mainloop()
print("EXITED", flush=True)
'''


def _write(name, body):
    path = os.path.join(os.environ["LOCALAPPDATA"], "Temp", name)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body.replace("{root}", ROOT))
    return path


def _start(script_path, with_stdin):
    """The child, in its own process group.

    Its own group is what a program launched with its own console
    gets, and it is what makes the break reach it: a group created
    with CREATE_NEW_PROCESS_GROUP ignores a console Ctrl-C, and
    receives the break instead.
    """
    kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                  text=True, errors="replace", bufsize=1,
                  creationflags=0x00000200)
    if with_stdin:
        kwargs["stdin"] = subprocess.PIPE
    return subprocess.Popen([sys.executable, script_path], **kwargs)


def _wait_ready(proc, marker, seconds=60):
    out = ""
    deadline = time.time() + seconds
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        out += line
        if marker in line:
            break
    return out


def _wait_gone(proc, seconds=25):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if proc.poll() is not None:
            return True
        time.sleep(0.5)
    return False


def _no_sessions_left(who: str) -> bool:
    """No session of this project's sshd is left.

    THE SESSION IS A CHILD AND IT IS SLOW TO GO.  On Windows the
    per-connection child is `sshd-session.exe`, and it holds the
    FORWARDED port open.  It is a child of the listener, so when the
    listener dies the session is told to go -- but "told to go" is
    not "gone": it can take a moment, and the port it holds is
    still held in the meantime.

    So the check WAITS for it, and if it does not go on its own it
    is stopped.  Then the check is that nothing is left.

    The count is of THIS PROJECT's sessions, by the config in their
    command line.  The SYSTEM sshd's sessions are named the same way
    and are not ours.
    """
    deadline = time.time() + 15
    left = ljt_processes()
    while left != "0" and time.time() < deadline:
        time.sleep(1)
        left = ljt_processes()

    if left != "0":
        # it did not go on its own, so it goes now
        sshd.stop_sessions()
        time.sleep(2)
        left = ljt_processes()

    return check(f"no session of {who} is left", left == "0",
                 f"{left} left")


def run() -> int:
    """The test.  Returns 0 when everything passed."""
    print("=== the console version, interrupted ===")
    path2 = _write("ljt_int_console.py", CONSOLE_SCRIPT)
    proc2 = _start(path2, with_stdin=True)
    time.sleep(8)
    check("the console version is listening", listening(LISTEN_PORT) > 0,
          str(listening(LISTEN_PORT)))

    sent = send_break(proc2)
    check("the interrupt was delivered", sent, str(sent))

    exited2 = _wait_gone(proc2)
    check("the console version exited", exited2,
          f"exit {proc2.poll()}" if exited2 else "it is still running")
    if not exited2:
        proc2.kill()
        proc2.wait(timeout=10)

    time.sleep(2)
    check("the console version released the port",
          listening(LISTEN_PORT) == 0, str(listening(LISTEN_PORT)))
    _no_sessions_left("the console version")

    # ===================================================== the window
    print()
    print("=== the window, interrupted ===")
    path = _write("ljt_int_window.py", WINDOW_SCRIPT)
    proc = _start(path, with_stdin=False)
    ready = _wait_ready(proc, "READY")
    check("the window came up", "READY" in ready, ready.strip()[:60])
    time.sleep(2)
    check("the listen port is open", listening(LISTEN_PORT) > 0,
          str(listening(LISTEN_PORT)))

    sent = send_break(proc)
    check("the interrupt was delivered", sent, str(sent))

    exited = _wait_gone(proc)
    check("the window exited", exited,
          f"exit {proc.poll()}" if exited else "it is still running")
    if not exited:
        proc.kill()
        proc.wait(timeout=10)

    time.sleep(2)
    check("the window released the port", listening(LISTEN_PORT) == 0,
          str(listening(LISTEN_PORT)))
    # and the FORWARDED ports too: on Windows a per-connection
    # session holds those, and the listener going away does not take
    # it with it.  A forwarded port that is still held is a port the
    # next launch finds busy for no reason anybody can see.
    _no_sessions_left("the window")
    check("no ljtunnel sshd is left", ljt_processes() == "0",
          ljt_processes())

    # ===================================================== the summary
    print()
    print("=== the summary ===")
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"  {passed}/{len(results)} passed")

    for f in (path, path2):
        try:
            os.remove(f)
        except OSError:
            pass
    return 0 if passed == len(results) else 1


def main() -> int:
    if sys.platform != "win32":
        print("  the interrupt test is Windows only (skipped)")
        return 0
    return run()


if __name__ == "__main__":
    sys.exit(main())
