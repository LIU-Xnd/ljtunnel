"""The table of the addresses that have been let in.

WHAT IT IS FOR
--------------
The http server asks for a token.  A person who has the token gets
in, and the server REMEMBERS the address they came from -- and the
next time that address comes, it does not have to ask.

    ~/.local/state/ljtunnel/ljt_ip_token_table

So a person who has been once does not have to paste a secret into
every URL, and a program that has been let in does not have to send
the token on every request.

THE RULES
---------
**AN ADDRESS IS IN THE TABLE AFTER IT HAS PROVED ITSELF ONCE.**  It
is put there when a request with the RIGHT token comes from it, and
not before -- so an address cannot get in by being written down by
somebody else.

**AND AN ADDRESS IN THE TABLE NEEDS NO TOKEN.**  That is the point.

**AND THE TOKEN IS STILL THE GATE FOR EVERY ADDRESS THAT IS NOT IN
THE TABLE.**  So a new address -- a laptop, a colleague, something
that has never been here -- still has to have the token.

**AND THE TABLE IS PRIVATE.**  It says which addresses do not need a
secret, and that is not for the people who reach the server.

THE FILE
---------
One address per line, and the line is:

    <the address> <the time it was let in> <the name it gave>

The name is what the request said, and it is not a secret -- a
person may send any name at all.  It is here so that a person
reading the table knows who is in it.

**AND A COMMENT IS A COMMENT**, and a blank line is a blank line.

THE WRITING
------------
**AND IT IS WRITTEN ATOMICALLY.**  A table that is half written is a
table that does not say who is in it, and a server that reads it
while somebody is writing it must not see a half a line.  So the new
table is written to a file next to it and then put in place.

**AND THE FILE IS PRIVATE TOO** -- 0600 on the machines that have
such a thing -- because a table of who does not need a token is worth
keeping to the person who owns the machine.
"""
from __future__ import annotations

import os
import tempfile
import time

from . import paths


def table_path() -> str:
    """Where the table is."""
    return paths.ip_token_table()


def _read() -> dict:
    """The addresses in the table, and when each was let in."""
    out = {}
    path = table_path()
    if not os.path.isfile(path):
        return out
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                parts = s.split()
                if not parts:
                    continue
                addr = parts[0]
                when = 0.0
                name = ""
                if len(parts) > 1:
                    try:
                        when = float(parts[1])
                    except ValueError:
                        when = 0.0
                if len(parts) > 2:
                    name = " ".join(parts[2:])
                out[addr] = (when, name)
    except OSError:
        return {}
    return out


def _write(entries: dict) -> None:
    """Put the table down, atomically.

    **AND IT IS WRITTEN TO A FILE NEXT TO IT AND THEN PUT IN PLACE.**
    A table that is half written is a table that does not say who is
    in it -- and a server that reads it while somebody is writing it
    must not see half a line.
    """
    path = table_path()
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)

    lines = [
        "# the addresses that have been let in without a token.",
        "# one per line: <the address> <the time> <the name>",
        "",
    ]
    for addr in sorted(entries):
        when, name = entries[addr]
        lines.append(f"{addr} {int(when)} {name}".rstrip())
    text = "\n".join(lines) + "\n"

    fd, tmp = tempfile.mkstemp(prefix=".ipt-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        _make_private(tmp)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _make_private(path: str) -> None:
    """Make the file readable by its owner only, where that means
    something.

    **AND IT IS NOT AN ERROR IF IT CANNOT BE DONE.**  On a machine
    without POSIX permissions -- Windows -- there is nothing to do,
    and the file lives in a directory that is the user's own.
    """
    try:
        os.chmod(path, 0o600)
    except (OSError, NotImplementedError):
        pass


def is_known(address: str) -> bool:
    """Whether this address is in the table.

    **AND AN EMPTY ADDRESS IS NOT IN THE TABLE.**  There is no
    address to remember, and a request without one is a request that
    has to carry the token.
    """
    if not address:
        return False
    return address in _read()


def remember(address: str, name: str = "") -> bool:
    """Put this address in the table.  True if it worked.

    **AND IT IS NOT WRITTEN TWICE.**  A request that comes with the
    token every time -- a program that sends it -- would otherwise
    rewrite the table on every request, and the table is on the disk.
    """
    if not address:
        return False
    entries = _read()
    when = time.time()
    if address in entries:
        # AND THE NAME IS UPDATED, because a person may say who they
        # are the second time and not the first.
        old_when, old_name = entries[address]
        if name and name != old_name:
            entries[address] = (old_when, name)
            try:
                _write(entries)
            except OSError:
                return False
        return True
    entries[address] = (when, name or "")
    try:
        _write(entries)
    except OSError:
        return False
    return True


def forget(address: str = "") -> int:
    """Take an address out of the table, or all of them.  How many.

    **AND IT IS THE WAY TO STOP TRUSTING SOMEBODY.**  The table says
    who does not need a token, and a person who does not want that
    any more asks for it to be taken out.
    """
    entries = _read()
    if not address:
        count = len(entries)
        if count:
            try:
                _write({})
            except OSError:
                return 0
        return count
    if address in entries:
        del entries[address]
        try:
            _write(entries)
        except OSError:
            return 0
        return 1
    return 0


def entries() -> list:
    """The table, as a list of (address, when, name).

    **AND IT IS SORTED BY THE TIME**, and the newest first, because
    the question a person asks is "who was here lately".
    """
    out = []
    for addr, (when, name) in _read().items():
        out.append((addr, when, name))
    out.sort(key=lambda r: -r[1])
    return out
