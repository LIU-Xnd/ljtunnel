"""The module entry point: `python -m ljtunnel`.

THE DISPATCHER IS IN `ljtunnel.cli`, not here.  If it were here,
importing the package would import this module, and Python would
warn about it being in sys.modules before it is executed.  So this
is a shell over the real thing.
"""
from __future__ import annotations

import sys

from .cli import has_console, main, report_crash

__all__ = ["main", "has_console", "report_crash"]

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
