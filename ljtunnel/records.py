"""What the listen end has been told, and what it has seen.

There are two things, and they are not the same thing:

  a RECORD is what somebody filled in: this dialer is called box-a,
  its key is this, and here is the command to run on it.

  a DIALER is what is actually there right now: a key authenticated
  and asked for a port, and that port is open.

A record without a live dialer is a dialer that has not started yet,
or one that has gone.  A live dialer without a record is a dialer
whose key was in the list before the records existed -- and the
records are what make the panel able to PRINT a command for a box
that is not running yet.

So both are kept, and the panel shows one row for each, with the two
pieces of information side by side.

THE FILE
---------
One JSON file in the state directory.  JSON because it is a list of
records with names in them, and a hand-edited file that the program
also writes is a file that ends up broken.  The file is rewritten
whole, and written through a temporary file and renamed, so a crash
in the middle does not leave a half-written file behind.
"""
from __future__ import annotations

import json
import os
import tempfile
import time

from . import paths

RECORDS_FILE = "ljtunnel_records.json"


def records_path() -> str:
    """Where the records live."""
    return os.path.join(paths.state_dir(), RECORDS_FILE)


def load() -> list:
    """The records, as a list of dicts.

    A file that cannot be read is a file with no records in it, not
    a crash: the records are a convenience, and the program works
    without them.
    """
    path = records_path()
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    return [r for r in data if isinstance(r, dict)]


def save(records: list) -> None:
    """Write the records out.

    The file is written to a TEMPORARY one and renamed over the
    real one, because a rename is atomic and a write is not: a
    program that dies halfway through writing leaves a file that
    cannot be parsed, and the records are gone.
    """
    paths.ensure_dir(paths.state_dir())
    path = records_path()
    fd, tmp = tempfile.mkstemp(dir=paths.state_dir(), prefix=".records-",
                                suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(records, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def add(name: str, pubkey: str = "", host: str = "", user: str = "",
        note: str = "", local_user: str = "") -> dict:
    """Record a dialer, and return the record.

    A record with the same NAME is REPLACED, not duplicated: the
    form is filled in again when something about the dialer changes,
    and two records with one name is a form that was filled in twice
    by accident.
    """
    name = (name or "").strip()
    records = load()
    rec = {
        "name": name,
        # THE ACCOUNT ON THE DIALER, for the person who connects
        # through the forwarded port.  It is a different account from
        # "user", which is the account on the reachable end.
        "local_user": (local_user or "").strip(),
        "pubkey": (pubkey or "").strip(),
        "host": (host or "").strip(),
        "user": (user or "").strip(),
        "note": (note or "").strip(),
        "added": time.time(),
    }
    out = []
    replaced = False
    for r in records:
        if r.get("name") and r.get("name") == name and name:
            out.append(rec)
            replaced = True
        else:
            out.append(r)
    if not replaced:
        out.append(rec)
    save(out)
    return rec


def remove(name: str) -> bool:
    """Forget a record.  Returns whether there was one."""
    records = load()
    out = [r for r in records if r.get("name") != name]
    if len(out) == len(records):
        return False
    save(out)
    return True


def by_name(name: str) -> dict:
    """The record with that name, or an empty dict."""
    for r in load():
        if r.get("name") == name:
            return r
    return {}


def names() -> list:
    """The names, in the order they were added."""
    return [r.get("name", "") for r in load() if r.get("name")]


def command_for(record: dict) -> str:
    """The command a dialer runs, from its record.

    THE COMMAND IS THE SAME FOR EVERY DIALER.  The dialer finds its
    own port, the reachable end is the same one, and the name and the
    account are the DIALER's own business -- it knows both.

    So the command carries only what the reachable end knows: where
    it is, on which port, and the key that lets a person in.

    The record may name a host and a user -- the ones the form was
    filled in with.  When it does not, the reachable end's own
    address and the user running it are used, because that is what
    the command needs.

    THE USER IS THE REACHABLE END'S USER.  The dialer opens an ssh
    session to the reachable end, and the reachable end's sshd
    refuses a user that does not exist on it -- so the name in the
    command is a user of the machine the command is going to reach,
    not a user of the machine the command is run on.  The two are
    different machines and they have different users.

    The command does NOT name a port: the dialer finds a free one
    itself, and if the port it asked for is taken it asks for the
    next.  So the same command works on every box.
    """
    from . import listen

    host = (record.get("host") or "").strip() or listen.local_ipv4()
    user = (record.get("user") or "").strip() or listen.current_user()
    return (f"ljtunnel dialer --listen-host {host} "
            f"--listen-port {listen.LISTEN_SSHD_PORT} "
            f"--user {user} "
            f"--access-key \"{listen.access_public_key()}\"")


