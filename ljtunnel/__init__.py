"""ljtunnel -- an ssh reverse-forward tunnel with two ends.

A machine that cannot be reached offers its own sshd to a machine that
can, with no inbound port on the unreachable side.

    ljtunnel listen      the reachable end: an sshd and a panel of dialers
    ljtunnel dialer      the unreachable end: an sshd, forwarded back

The traffic is ssh's own. ljtunnel does not implement a tunnel; it sets
up the ssh one that does.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
