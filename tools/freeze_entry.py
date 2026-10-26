"""Entry point for the frozen Linux binary.

PyInstaller needs a script, not a module path.  This calls the same
dispatcher the console script does, so the frozen binary behaves
exactly like `ljtunnel`.

THE DIALER IS THE REASON THIS EXISTS.  The machine that cannot be
reached is the one that has nothing installed -- no Python, no conda,
no pip -- and it is the side that has to dial out.  So the binary
that matters is the one that runs the far side, and it has to carry
its own interpreter.

AND IT IS THE WHOLE DISPATCHER, NOT ONE SUBCOMMAND.  Freezing
`ljtunnel.dialer:main` gives a binary that can only be a dialer, and
then `ljtunnel key` and `ljtunnel listen` do not exist in it -- and
the key command is how the two ends are set up.  So the dispatcher is
frozen, and every subcommand comes with it.

THE WINDOW IS EXCLUDED.  tkinter is not part of the far side, and
excluding it keeps the binary smaller and pulls in no X11 libraries.
"""
import sys

from ljtunnel import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
