"""THE GUI ENTRY POINT: the one the launcher on the Start Menu uses.

**THE LAUNCHER IS A GUI PROGRAM, AND THE CONSOLE IT MAKES IS NOT
THE USER'S.**  pyappdist's GUI launcher runs the entry point with
the CONSOLE python -- `python.exe -I -c ...` -- so the interpreter
has a console, and the usual "is there a console" test says yes.

But that console belongs to a GUI program.  It is not on the screen,
nobody is looking at it, and anything printed into it vanishes.

MEASURED: the dispatcher printed the usage into that console and
exited, and the window never came up.  The user said the shortcut
"would not run".

So this entry point SAYS that it is the GUI one, and the dispatcher
believes it.
"""
from __future__ import annotations

import os
import sys


def main(argv=None) -> int:
    """Open the window."""
    os.environ["LJT_GUI_LAUNCHER"] = "1"

    from .cli import main as run

    return run(argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
