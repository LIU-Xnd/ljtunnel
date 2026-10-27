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
  forget     remove this end's configuration: the keys, the records,
             the config and the log

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
    """Print this end's MACHINE key, for the other end's key list.

    IT IS THE MACHINE KEY, NOT THE HOST KEY, and the two are not
    interchangeable.

    The HOST KEY is this end's identity to a CLIENT: it is what a
    client checks to be sure it is talking to the right machine, and
    it is what the forwarded port's banner is built on.

    The MACHINE KEY is this end's identity to the OTHER END: it is
    what the dialer logs in to the listen end with, and it is what
    the listen end's key list has to name for the dialer to be let
    in.

    So the key that goes into the other end's key list is the machine
    key.  Printing the host key there produced a key the other end
    does not know, and the dialer was refused with:

        the reachable end did not accept this end's key

    which is a correct refusal of the wrong key.
    """
    from . import paths, sshd
    if argv and argv[0] in ("-h", "--help"):
        print("usage: ljtunnel key\n\n"
              "  print this end's machine key, for the other end's key\n"
              "  list -- the listen end's key list, if this is the\n"
              "  dialer end")
        return 0
    paths.ensure_dir(paths.state_dir())
    key = sshd.ensure_client_key()
    print(sshd.public_key_of(key))
    return 0


def _started_as_gui() -> bool:
    """Was this program started as a GUI program?

    **THE LAUNCHER SAYS SO.**  pyappdist's GUI launcher runs the
    program with the CONSOLE python -- `python.exe -I -c ...` -- so
    the interpreter has a console of its own, and the console test
    says there is one.  But that console belongs to a GUI program:
    it is not on the screen and nobody is looking at it.

    MEASURED: the launcher printed the usage into that console and
    exited, and the window never came up.  The user said the
    shortcut "would not run".

    So the launcher is named in the environment it hands over, and
    the program reads it.
    """
    import os

    return bool(os.environ.get("LJT_GUI_LAUNCHER"))


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
        # A GUI LAUNCHER ALWAYS OPENS THE WINDOW.
        #
        # The console test was WRONG, and it cost the whole product:
        # pyappdist's GUI launcher runs the script with the CONSOLE
        # python -- `python.exe -I -c ...` -- so the interpreter HAS
        # a console, and `GetConsoleProcessList` said so.  But that
        # console belongs to the LAUNCHER, which is a GUI program:
        # nobody is looking at it, and the usage text went into it
        # and vanished.
        #
        # MEASURED: the launcher printed the usage and exited, and
        # the window never came up.
        #
        # So the question is not "is there a console" but "was this
        # program started as a GUI program".  The GUI launcher says
        # so itself.
        if not argv and _started_as_gui():
            from .app import main as run
            return run([])
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
    elif command == "forget":
        from .forget import main as run
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
