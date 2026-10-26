"""Running as an administrator.

The listen end needs administrator rights for exactly one thing: the
firewall rule.  Windows blocks inbound connections to a port it has
not been told about, and it does it SILENTLY -- the dialer times out
with no error on either side and nothing says "firewall".

Adding a firewall rule needs administrator rights, and the way to
get them is the UAC prompt: Windows asks, the person answers, and
the program runs with administrator rights.

THE WHOLE APP, OR JUST THE RULE
--------------------------------
The app could ask for the elevation every time it needs the rule.
Or it could ask ONCE, at the start, and be an administrator for as
long as it is open.

Asking once is better, and it is what this does:

  - the window opens, and if it is not already an administrator, it
    starts ITSELF again as one -- the UAC prompt appears once, and
    the person answers it once
  - after that the firewall button does its work with no prompt at
    all

A person who does not want to run the whole app as an administrator
can decline the prompt, and the app carries on WITHOUT it.  Then the
firewall button asks for the elevation on its own, for that one
step.

THE PROMPT IS VISIBLE ON PURPOSE
--------------------------------
The UAC prompt names the PROGRAM it is about to run.  For the
installed app that is ljtunnel.exe, which is a name a person can
recognise.  It is not hidden: a prompt a person cannot read is a
prompt a person should not be answering.

A person who presses "No" gets ERROR_CANCELLED (1223), and that is
the answer to give: "the prompt was declined", which is a thing
that happened and not a failure.
"""
from __future__ import annotations

import os
import sys

# ERROR_CANCELLED: the person pressed "No" on the UAC prompt.
ERROR_CANCELLED = 1223

# The Windows PowerShell that does the work when something needs
# administrator rights but the app itself does not have them.  The
# FULL path, because the UAC prompt shows the path of the program it
# is about to run.
POWERSHELL = (r"C:\Windows\System32\WindowsPowerShell\v1.0"
              r"\powershell.exe")


def is_admin() -> bool:
    """Is this process elevated?"""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def shell_execute_runas(program: str, arguments: str = "") -> int:
    """Start a program as an administrator, with the UAC prompt.

    Returns 0 when the process was STARTED.  That is all it can
    report: the elevated process is not a child, so its exit code is
    not ours, and the call returns before the program has run.

    THE PROGRAM AND ITS ARGUMENTS ARE SEPARATE.  lpFile is the
    PROGRAM and lpParameters are the ARGUMENTS, and putting the
    whole command line into lpFile makes Windows look for a FILE
    with that name:

        Windows cannot find the file 'powershell.exe -NoProfile ...'

    which is what happens when they are not separated.
    """
    if sys.platform != "win32":
        return 0

    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", wintypes.ULONG),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", wintypes.LPVOID),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIconOrMonitor", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    SW_SHOWNORMAL = 1
    SEE_MASK_NOCLOSEPROCESS = 0x00000040

    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    info.fMask = SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = program
    info.lpParameters = arguments or None
    info.nShow = SW_SHOWNORMAL

    ok = ctypes.windll.shell32.ShellExecuteExW(ctypes.byref(info))
    if not ok:
        err = ctypes.get_last_error()
        if err == ERROR_CANCELLED:
            return ERROR_CANCELLED
        return err or 1

    # The process was started.  The handle has to be closed, or the
    # process object leaks.
    if info.hProcess:
        ctypes.windll.kernel32.CloseHandle(info.hProcess)
    return 0


def _installed_launcher() -> str:
    """The installed app's own launcher, or "".

    The launcher is what the Start Menu shortcut runs, and it is the
    thing the UAC prompt should name: "ljtunnel" is a name a person
    can recognise, and "pythonw.exe" is not.

    TWO PLACES ARE LOOKED AT.  The install puts the launcher two
    directories above the bundled interpreter, because the
    interpreter is in a subdirectory of the install:

        LOCALAPPDATA/Programs/ljtunnel/ljtunnel.exe
        LOCALAPPDATA/Programs/ljtunnel/python/python.exe

    And when the app is run from a SOURCE TREE, the install is still
    there and is still the better thing to name: the prompt says
    "ljtunnel" rather than naming a Python that is not the program.
    So the install is looked for as well.
    """
    import pathlib

    exe = pathlib.Path(sys.executable)
    candidates = [exe.parent.parent / "ljtunnel.exe"]
    # the install, when the app is running from a source tree
    local = os.environ.get("LOCALAPPDATA")
    if local:
        candidates.append(pathlib.Path(local) / "Programs" / "ljtunnel"
                          / "ljtunnel.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return ""


def _pythonw() -> str:
    """The interpreter without a console, beside this one."""
    import pathlib

    exe = pathlib.Path(sys.executable)
    if exe.name.lower() == "pythonw.exe":
        return str(exe)
    candidate = exe.with_name("pythonw.exe")
    if candidate.is_file():
        return str(candidate)
    return ""


# The argument that says "you are already the elevated one".
#
# IT IS NOT OPTIONAL.  The elevated copy starts the SAME program, and
# that program asks to be an administrator when it starts -- so
# without this the elevated copy asks again, and the copy it starts
# asks again, and the two ask each other to start, forever.
#
# That is not a hypothetical: it happened, and the UAC prompt came
# up again and again until the person stopped it.
#
# So the elevated copy is told, in its arguments, that it is the one
# that has already been elevated.  It does not ask again.
ELEVATED_FLAG = "--elevated"


def is_elevated_run(argv=None) -> bool:
    """Was this process started as the elevated one?"""
    args = list(sys.argv[1:] if argv is None else argv)
    return ELEVATED_FLAG in args


def relaunch_elevated(argv=None) -> tuple:
    """Start this program again as an administrator.

    Returns (started, message).

    The person sees the UAC prompt and answers it.  The program that
    was started is a NEW process, and this one is expected to exit:
    two windows would be two panels showing the same state, and the
    un-elevated one could not do the work.

    THE NEW PROCESS IS TOLD IT IS THE ELEVATED ONE.  It carries the
    flag, and it does not ask again.  Without it the two copies ask
    each other to start, forever.
    """
    if sys.platform != "win32":
        return False, "not Windows: nothing to elevate"
    if is_admin():
        return False, "already an administrator"

    # THE SAME APP, NOT ANOTHER COPY OF IT.
    #
    # The interpreter beside this one is the one that is running now,
    # so it is the one that is started again.  The installed launcher
    # is a DIFFERENT program: it is whatever version happens to be
    # installed, and an installed copy that ALSO asks to be an
    # administrator would ask again -- and the two would ask each
    # other to start, forever.
    #
    # So the interpreter wins, and the launcher is the fallback for
    # the case where there is no interpreter to speak of.
    pythonw = _pythonw()
    if pythonw:
        args = list(sys.argv[1:] if argv is None else argv)
        if not args:
            args = ["listen"]
        # The flag is added HERE, so the copy that starts is the one
        # that is already elevated and does not ask again.
        if ELEVATED_FLAG not in args:
            args = [ELEVATED_FLAG] + args
        # The module is named, not a script path, so the copy that
        # starts is the copy that is running now.
        arguments = "-m ljtunnel " + " ".join(
            f'"{a}"' if " " in a else a for a in args)
        code = shell_execute_runas(pythonw, arguments)
        if code == 0:
            return True, "the app is starting as an administrator"
        if code == ERROR_CANCELLED:
            return False, "the UAC prompt was declined"
        return False, f"the elevation did not happen (error {code})"

    launcher = _installed_launcher()
    if launcher:
        code = shell_execute_runas(launcher)
        if code == 0:
            return True, "the app is starting as an administrator"
        if code == ERROR_CANCELLED:
            return False, "the UAC prompt was declined"
        return False, f"the elevation did not happen (error {code})"

    return False, ("there is no pythonw.exe beside this interpreter, "
                   "so the app cannot start itself again")
