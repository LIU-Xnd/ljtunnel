"""ljtunnel -- an ssh reverse-forward tunnel with two ends.

A machine that cannot be reached offers its own sshd to a machine that
can, with no inbound port on the unreachable side.

    ljtunnel listen      the reachable end: an sshd, and a panel that
                         records the dialers and prints their commands
    ljtunnel dialer      the unreachable end: an sshd, forwarded back

The traffic is ssh's own. ljtunnel does not implement a tunnel; it sets
up the ssh one that does.
"""

__version__ = "0.6.8"

# THE DISPATCHER IS EXPORTED, so a frozen binary can call it.
#
# PyInstaller wants a SCRIPT, not a module path, so the frozen
# binary's entry point is a small script that imports `main` from
# here.  And the whole dispatcher is frozen, not one subcommand:
# freezing `ljtunnel.dialer:main` gives a binary that can only be a
# dialer, and then `ljtunnel key` -- which is how the two ends are
# set up -- does not exist in it.
from .cli import main  # noqa: E402

__all__ = ["__version__", "main"]
