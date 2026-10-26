"""The command line: the dispatcher and the commands it dispatches to.

THIS IS ITS OWN MODULE, and that is not tidiness.

`python -m ljtunnel` runs `ljtunnel/__main__.py`, and the frozen
Linux binary runs a script that imports `main` from the package.  If
the dispatcher lived in `__main__.py`, importing the package would
import `__main__.py`, and Python would then warn about it:

    RuntimeWarning: 'ljtunnel.__main__' found in sys.modules after
    import of package 'ljtunnel', but prior to execution of
    'ljtunnel.__main__'

So the dispatcher lives here, and `__main__.py` is a thin shell over
it.  Both ways of running it get the same behaviour, and neither of
them warns.
"""
from __future__ import annotations

import sys


USAGE = """\
ljtunnel {version} -- an ssh reverse-forward tunnel

usage: ljtunnel <command> [options]

commands:
  listen     the reachable end: an sshd, and a panel of dialers
  dialer     the unreachable end: an sshd, forwarded back through the
             reachable end
  key        print this end's public key, for the other end's key list

run 'ljtunnel <command> --help' for a command's own options.
"""


def _run_listen(argv):
    """The window on Windows, the console version elsewhere.

    The window is the product on Windows -- it is the panel, and it
    is what gets installed. The console version is the same server
    without a window, and it is what a person uses over a pipe.
    """
    if sys.platform == "win32":
        from .app import main as run
    else:
        from .listen import main as run
    return run(argv)


def _run_key(argv):
    """Print this end's public key.

    The other end's key list is the handshake: the dialer may log in,
    and nobody else may. So the key has to be moved by hand, and
    there is one command that shows it.
    """
    from . import paths, sshd
    if argv and argv[0] in ("-h", "--help"):
        print("usage: ljtunnel key\n\n"
              "  print this end's public key, for the other end's key list")
        return 0
    paths.ensure_dir(paths.state_dir())
    key = sshd.ensure_host_key()
    print(sshd.public_key_of(key))
    return 0


def has_console() -> bool:
    """Is there a console to print to?

    The Windows launcher is built on pythonw.exe, which has no console.
    Output written there goes nowhere: the process appears to do
    nothing at all. That matters most for the Start Menu shortcut,
    which runs the launcher with no arguments.
    """
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # GetConsoleProcessList fills the buffer with the pids attached
        # to this process's console and returns how many there were.
        # Zero means there is no console -- which is the case for the
        # Windows launcher, because it runs on pythonw.exe.
        #
        # AttachConsole is the wrong signal here and is tempting to
        # reach for: it succeeds precisely when the process has NO
        # console of its own and can attach to the parent's.
        buffer = (ctypes.c_ulong * 8)()
        count = kernel32.GetConsoleProcessList(buffer, len(buffer))
        return count > 0
    except Exception:
        # If the check itself fails, assume there is a console:
        # printing is the safer default where output matters.
        return True


def report_crash() -> None:
    """Show a traceback where the user can actually see it.

    With a console it goes to stderr. Without one -- the Windows
    launcher runs on pythonw.exe -- stderr is nowhere, so a message
    box is the only thing that will show the user what went wrong.
    """
    import traceback

    text = "".join(traceback.format_exception(*sys.exc_info()))
    if has_console():
        print(text, file=sys.stderr)
        return
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            None, text, "ljtunnel -- something went wrong", 0x10)
    except Exception:
        pass


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    from . import __version__

    if not argv or argv[0] in ("-h", "--help", "help"):
        # With no console there is nowhere to print to, so the user
        # would see nothing happen. Open the window instead: that is
        # what the Start Menu shortcut runs.
        if not argv and not has_console():
            from .app import main as run
            return run([])
        print(USAGE.format(version=__version__), end="")
        return 0
    if argv[0] in ("-V", "--version"):
        print(__version__)
        return 0

    # THE FLAG THE ELEVATED COPY CARRIES.
    #
    # The app asks to be an administrator when it starts, so the
    # elevated copy has to be told it does not have to ask.  It is
    # told in its arguments, and the flag comes FIRST.
    #
    # It is taken off here and put back on the subcommand's own
    # arguments, because the subcommand is the one that understands
    # it.  Without this the elevated copy is told "unknown command"
    # and exits, and the window never appears.
    elevated = False
    if argv and argv[0] == "--elevated":
        elevated = True
        argv = argv[1:]
        if not argv:
            argv = ["listen"]

    command, rest = argv[0], argv[1:]
    if elevated:
        rest = ["--elevated"] + rest

    if command == "listen":
        run = _run_listen
    elif command == "dialer":
        from .dialer import main as run
    elif command == "key":
        run = _run_key
    else:
        print(f"ljtunnel: unknown command {command!r}\n", file=sys.stderr)
        print(USAGE.format(version=__version__), end="", file=sys.stderr)
        return 2

    try:
        return run(rest)
    except Exception:
        # A failure here would otherwise be invisible: the Windows
        # launcher is pythonw-based, so a traceback printed to stderr
        # goes nowhere and the process just disappears. Show it.
        report_crash()
        raise


if __name__ == "__main__":
    sys.exit(main())
