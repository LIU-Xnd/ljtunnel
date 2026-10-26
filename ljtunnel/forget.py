"""Taking this end's configuration away.

THE CONFIGURATION IS IN ONE DIRECTORY.  The sshd config, the two
key pairs, the key list, the records, the pid and the log are all in
the state directory, and nothing else is written anywhere.  So
"forget everything this end knew" is one directory, removed.

WHAT IT REMOVES: the state directory, and nothing else.  It never
touches the user's own ~/.ssh, the SYSTEM sshd on port 22, the
firewall rule, or anything the tunnel did not create.

WHAT IT DOES NOT DO: it does not remove the firewall rule.  That is
a machine-wide thing that the tunnel asked for, and the person who
asked for it may want it to stay.  The rule is removed by the
window's own button, which asks for the administrator rights the
rule needs.

AND IT STOPS THE TUNNEL FIRST.  Removing the config out from under a
running sshd leaves a process holding a port and a pid file that
names nothing.
"""
from __future__ import annotations

import os
import shutil
import sys


def _running_pids() -> list:
    """The pids of this project's sshd, if any."""
    from . import paths, sshd
    out = []
    pidfile = paths.pid_file()
    try:
        with open(pidfile, encoding="utf-8", errors="replace") as fh:
            out.append(fh.read().strip())
    except OSError:
        pass
    return [p for p in out if p.isdigit()]


def forget(assume_yes: bool = False) -> int:
    """Remove this end's configuration.  Returns 0 when it is gone."""
    from . import paths, sshd

    directory = paths.state_dir()

    if not os.path.isdir(directory):
        print(f"there is nothing to remove: {directory}")
        return 0

    # ---- the files in it, so the person can see what goes ----
    names = []
    try:
        for name in sorted(os.listdir(directory)):
            full = os.path.join(directory, name)
            try:
                size = os.path.getsize(full)
            except OSError:
                size = 0
            names.append((name, size))
    except OSError:
        pass

    print(f"this end's configuration is in {directory}:")
    for name, size in names:
        print(f"  {name}  ({size:,} bytes)")
    print()

    if not assume_yes:
        # A person who cannot see the question cannot answer it, so
        # the answer has to be on the keyboard.  And the answer is
        # asked for by DEFAULT: this removes private keys.
        try:
            answer = input("remove all of it? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer not in ("y", "yes"):
            print("nothing was removed")
            return 1

    # ---- the tunnel goes first ----
    #
    # Removing the config out from under a running sshd leaves a
    # process holding a port and a pid file that names nothing.
    pids = _running_pids()
    try:
        sshd.stop()
    except Exception:
        pass
    try:
        sshd.stop_sessions()
    except Exception:
        pass
    if pids:
        print(f"  the sshd was stopped (pid {', '.join(pids)})")

    # ---- and the directory goes ----
    try:
        shutil.rmtree(directory)
    except OSError as e:
        print(f"the configuration could not be removed: {e}",
              file=sys.stderr)
        return 1

    print(f"  it is gone: {directory}")
    print()
    print("the firewall rule is still there.  The window's firewall")
    print("button removes it.")
    return 0


def main(argv=None) -> int:
    """`ljtunnel forget`"""
    argv = list(sys.argv[1:] if argv is None else argv)

    if argv and argv[0] in ("-h", "--help"):
        print("usage: ljtunnel forget [--yes]\n"
              "\n"
              "  remove this end's configuration: the sshd config, the\n"
              "  key pairs, the key list, the records and the log.\n"
              "\n"
              "  the firewall rule is NOT removed: that is a machine-wide\n"
              "  thing, and the window's firewall button removes it.")
        return 0

    assume_yes = False
    for a in argv:
        if a in ("-y", "--yes"):
            assume_yes = True
        elif a.startswith("-"):
            print(f"ljtunnel forget: unknown option {a!r}", file=sys.stderr)
            return 2

    return forget(assume_yes)
