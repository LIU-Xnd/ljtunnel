"""Finding the dialers WITHOUT the sshd's log.

THE LOG IS NOT AVAILABLE ON WINDOWS, and that is worth stating
plainly because the whole first design depended on it.

**THE LISTENER'S LOG GOES DOWN THE PIPE, BUT THE SESSIONS' LOG DOES
NOT.**  On Windows the per-CONNECTION child is `sshd-session.exe`,
and its stderr does not reach the parent's pipe.  MEASURED: with a
dialer connected and forwarding, the pipe held eleven lines -- the
listener's start-up -- and not one of them mentioned the connection.

**AND `-E <file>` DOES NOT HELP.**  It holds the file EXCLUSIVELY:
it cannot be read by python, by `cmd /c type`, or by `copy`.  A log
nobody can read is no log.

**AND THE EVENT LOG DOES NOT HAVE IT EITHER.**  `OpenSSH/Operational`
carries the failures -- "banner exchange: invalid format", the
disconnects -- but a session that authenticated and asked for a
forward leaves NOTHING there.  MEASURED: the newest event was from
half an hour before the test.

**AND `-d` IS NOT THE ANSWER.**  With `-d` the listener does not
fork, so it handles ONE connection and every log line comes down
the pipe.  MEASURED: the first dialer worked and the second was
refused with "Connection refused".

SO THE IDENTITY IS FOUND A DIFFERENT WAY, and it is better anyway.

THE HOST KEY IS THE IDENTITY
----------------------------
Behind every forwarded port there is the DIALER's own sshd.  So the
host key that answers there is the dialer's identity, and it cannot
be faked: it is what the key exchange is built on, and the far end
has to prove it holds the private half.

The listen end already knows what it should be.  The dialer's
public key is in the listen end's key list -- that is how the dialer
was let in -- and the dialer's HOST key is a public key too.  So:

    the fingerprint behind the forwarded port
        is looked up in the key list
        and the name on the key it matches is the dialer's name

**THE MACHINE KEY AND THE HOST KEY ARE DIFFERENT KEYS**, and that is
fine: the key list holds the machine key, and the fingerprint behind
the port is the host key.  So the lookup is by the host key's
fingerprint, and the host key has to be in the list as well.

**SO THE DIALER PUTS ITS HOST KEY IN THE LIST TOO.**  The command
the panel prints carries both: the machine key, which is how the
dialer logs in, and the host key, which is how it is identified.

**AND THE NAME IS ON THE KEY, AS AN OPTION**, so a dialer cannot
call itself something it is not:

    environment="LJT_NAME=box-a" ssh-ed25519 AAAA...

**AND IF THE FINGERPRINT IS NOT IN THE LIST**, the port is still
shown -- the port is open, and something is there -- but it is shown
by its fingerprint and not by a name.  A dialer whose key was added
before the records existed looks like that.
"""
from __future__ import annotations

import os
import re
import sys

from .detect import Dialer, _fingerprint_of, _listening, host_key_fingerprint

# The name, as it is written on the key.
NAME_RE = re.compile(r'environment="LJT_NAME=([^"]+)"')


def _keys_with_names() -> dict:
    """The key list, as fingerprint -> name.

    The list is this end's OWN authorized_keys file: the keys of the
    dialers that are allowed to log in.  A key that is not in it
    cannot be a dialer, and the names are on the keys as options, so
    a dialer cannot call itself something it is not.
    """
    from . import paths

    out = {}
    try:
        with open(paths.authorized_keys(), "r", encoding="utf-8",
                  errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                name = ""
                m = NAME_RE.search(line)
                if m:
                    name = m.group(1)
                # THE KEY ITSELF: the type and the base64 body, which
                # is what the fingerprint is computed over.
                #
                # The line is:
                #
                #     environment="LJT_NAME=box-a" ssh-ed25519 AAAA... comment
                #
                # so the type and the body are the two fields after
                # the option.  Taking only the type gives a
                # fingerprint of nothing, and the lookup finds
                # nothing, and the panel shows no names -- which
                # looks exactly like a dialer that did not arrive.
                parts = line.split()
                key_text = ""
                for n, part in enumerate(parts):
                    if part.startswith("ssh-") and len(part) > 4:
                        if n + 1 < len(parts):
                            key_text = part + " " + parts[n + 1]
                        break
                if not key_text:
                    continue
                fp = _fingerprint_of(key_text)
                if fp:
                    out[fp] = name
    except OSError:
        pass
    return out


def scan(first_port: int, count: int, timeout: float = 12.0) -> list:
    """The dialers that are there right now.

    Returns a list of dicts: port, name, fingerprint, and whether
    the name was recognised.

    THE SOCKET TABLE SAYS WHICH PORTS ARE OPEN.  It is the truth and
    it needs no log.

    AND THE HOST KEY BEHIND EACH PORT SAYS WHO IS THERE.  The
    fingerprint is looked up in the key list, and the name on the
    key that matches is the dialer's name.
    """
    last = first_port + count - 1
    listening = _listening(first_port, last)
    if not listening:
        return []

    names = _keys_with_names()
    out = []
    for port in sorted(listening):
        fp = host_key_fingerprint(port, "127.0.0.1", timeout=timeout)
        name = names.get(fp, "") if fp else ""
        out.append(Dialer(
            fingerprint=fp,
            name=name,
            port=port,
            alive=True,
        ))
    return out


def scan_fast(first_port: int, count: int, timeout: float = 12.0) -> list:
    """The same, but the fingerprints are looked up in PARALLEL.

    THE KEYSCAN IS SLOW.  It does a whole handshake for each port,
    and a keyscan that takes three seconds per port makes a panel
    that refreshes every second take three seconds.  So the ports
    are scanned at the same time, and the panel waits for the
    slowest one instead of for the sum.

    **AND A FINGERPRINT THAT IS ALREADY KNOWN IS NOT LOOKED FOR
    AGAIN.**  The host key behind a port does not change while the
    dialer is there -- it is the dialer's own host key, and the
    dialer is the one holding the connection.  So a port that was
    seen before is remembered, and the cache is what makes the panel
    cheap.

    MEASURED: the keyscan takes ten seconds on a port that is not
    answering -- `ssh-keyscan -T 10` waits for the timeout -- and the
    panel asked for it every second.

    AND THE CACHE IS BY THE PORT AND THE OWNER, so a port that
    changes hands is looked at again: the pid is in the key, because
    a different process on the same port is a different machine.
    """
    from concurrent.futures import ThreadPoolExecutor

    last = first_port + count - 1
    listening = _listening(first_port, last)
    if not listening:
        _cache.clear()
        return []

    names = _keys_with_names()
    ports = sorted(listening)

    # ---- the ones that are already known ----
    todo = []
    fps = {}
    for port in ports:
        pid = listening[port]
        key = (port, pid)
        if key in _cache:
            fps[port] = _cache[key]
        else:
            todo.append(port)

    if todo:
        with ThreadPoolExecutor(max_workers=min(8, len(todo))) as pool:
            found = list(pool.map(
                lambda p: host_key_fingerprint(p, "127.0.0.1", timeout=timeout),
                todo))
        for port, fp in zip(todo, found):
            fps[port] = fp
            _cache[(port, listening[port])] = fp

    # ---- and the ones that are gone are forgotten ----
    live_keys = {(p, listening[p]) for p in ports}
    for key in [k for k in _cache if k not in live_keys]:
        del _cache[key]

    out = []
    for port in ports:
        fp = fps.get(port, "")
        name = names.get(fp, "") if fp else ""
        out.append(Dialer(
            fingerprint=fp,
            name=name,
            port=port,
            alive=True,
        ))
    return out


# The fingerprints that are already known: (port, pid) -> fingerprint.
#
# IT IS A MODULE LEVEL THING on purpose: the panel asks again every
# second, and the thing that makes the ask cheap is that the answer
# is remembered.
_cache: dict = {}
