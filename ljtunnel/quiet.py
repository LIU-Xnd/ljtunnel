"""THE SUBPROCESSES MUST NOT OPEN A WINDOW.

**THE WINDOWS LAUNCHER IS BUILT ON pythonw.exe**, which has no
console of its own.  A child process started from it INHERITS no
console either -- and a console program started with no console to
join makes a NEW one, in a window, on the screen.

So the panel's poll, which asks PowerShell for the socket table once
a second, put a PowerShell window on the screen once a second.  The
window flashed and flashed and flashed.

**THE FIX IS ONE FLAG.**  `CREATE_NO_WINDOW` tells Windows to run
the child without a console and without making one.

AND IT IS ONLY RIGHT ON WINDOWS.  The flag does not exist on Linux,
and a child there does not make a window anyway -- so the flag is
added only when it is needed.
"""
from __future__ import annotations

import os
import subprocess
import sys


def no_window_flags() -> dict:
    """The flags for a child that must not open a window."""
    if sys.platform != "win32":
        return {}
    return {"creationflags": subprocess.CREATE_NO_WINDOW}


def run_hidden(args, **kwargs) -> subprocess.CompletedProcess:
    """`subprocess.run`, and the child does not open a window."""
    kwargs.update(no_window_flags())
    return subprocess.run(args, **kwargs)


def popen_hidden(args, **kwargs) -> subprocess.Popen:
    """`subprocess.Popen`, and the child does not open a window."""
    kwargs.update(no_window_flags())
    return subprocess.Popen(args, **kwargs)
