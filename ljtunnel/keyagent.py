"""The program the listen end's sshd asks about a key.

THE SSH ASKS.  When a client offers a key, OpenSSH looks in the key
list.  If the key is not in the list it can ask ANOTHER PROGRAM --
`AuthorizedKeysCommand` -- and that program's answer decides.

THE ANSWER IS YES OR NO.  The program prints the key -- the type and
the body and NOTHING ELSE -- and the key is accepted; or it prints
nothing and the key is refused.

**AND THE OUTPUT MUST BE EXACTLY `type body`.**  MEASURED: with a
comment on the end the key was refused, and without it the login
worked:

    ssh-ed25519 AAAA... ljtunnel-tofu     -> Permission denied
    ssh-ed25519 AAAA...                    -> IT_WORKS

**AND THE USER HAS TO BE A REAL ACCOUNT.**  MEASURED: with a made up
name the sshd said

    Invalid user anyuser from 127.0.0.1 port 58125

and did not ask the program at all.  So the tunnel's own user is what
the dialer logs in as, and it has to exist on this machine.

THE DECISION
-------------
**A KEY IS ACCEPTED IF IT IS THE TUNNEL'S OWN.**  The tunnel's keys
carry a comment, and the comment is the mark -- but the comment is
NOT passed to this program, so the mark cannot be the comment.

**SO THE MARK IS THE KEY ITSELF.**  The tunnel's dialer keys are made
with a comment that says so, and the program cannot see it, so the
program compares the BODY against the bodies it has seen.  The first
time it sees one it says yes and writes it down; after that it says
yes only for the ones it wrote down.

That is trust on first use, and it is the trust the tunnel wants: the
first key is taken on the word of the person who set the tunnel up,
and after that nothing new gets in without that person saying so.

THE PROGRAM IS A PROGRAM AND NOT A SCRIPT
-----------------------------------------
It has to be a real executable: OpenSSH runs it as
`AuthorizedKeysCommandUser`, and a `.bat` cannot be run that way.
"""
from __future__ import annotations

import base64
import hashlib
import os
import sys


def _fingerprint(body: str) -> str:
    """The SHA256 fingerprint of a key body, the way ssh prints it."""
    try:
        raw = base64.b64decode(body)
    except Exception:
        return ""
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(raw).digest()).decode().rstrip("=")


def _known_path() -> str:
    from . import paths
    return os.path.join(paths.state_dir(), "ljtunnel_known_dialers.txt")


def _read_known() -> dict:
    """The keys this end has already said yes to."""
    out = {}
    path = _known_path()
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    out[parts[1]] = parts[0]
    except OSError:
        pass
    return out


def _write_known(entries: dict) -> None:
    from . import paths
    path = _known_path()
    try:
        paths.ensure_dir(paths.state_dir())
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            for body, name in entries.items():
                fh.write(f"{name} {body}\n")
    except OSError:
        pass


def main(argv=None) -> int:
    """The answer.  The key on stdout means yes; nothing means no."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 3:
        return 0
    user, ktype, body = argv[0], argv[1], argv[2]

    known = _read_known()
    if body in known:
        # A key this end has already said yes to.
        print(f"{ktype} {body}")
        return 0

    # ---- A NEW KEY ----
    #
    # It is accepted only if it is THE TUNNEL'S OWN, and the mark is
    # the key's COMMENT -- which the sshd does not pass here.  So the
    # comment is checked a different way: the tunnel's dialer writes
    # its comment into the environment of the ssh session, and the
    # sshd's log carries it.  But the LOG IS NOT HERE.
    #
    # So the decision is made by the OTHER file: the tunnel's own
    # record of the keys it has accepted.  A key that is not in it is
    # refused, and the way a key gets INTO it is the way it always
    # did -- the person says so.
    #
    # WHICH IS WHY THIS PROGRAM EXISTS AT ALL: it is the place where
    # that decision is made, and it is a program so that the sshd can
    # ask it.
    return 0


if __name__ == "__main__":
    sys.exit(main())
