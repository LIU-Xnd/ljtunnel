"""The tokens for the http server, and who owns which file.

WHY A TABLE AND NOT ONE TOKEN
-----------------------------
One token is one person, and one person cannot share a machine with
anybody else without giving them everything.  So there is a TABLE of
tokens, and each token is a separate key to the same door.

    ~/.local/state/ljtunnel-http-token/token-filetable

**AND THE FILE IS NOT VISIBLE TO OTHER PEOPLE.**  It holds the keys
to the door, so its permissions are the owner's alone -- 0600 on the
file and 0700 on the directory.

WHAT THE TABLE IS
-----------------
It is a TEXT file, one token per line, and a line that starts with a
`#` is a comment.  So a person can read it, and a person can add a
line to it, and the program can read it without a parser.

    # the ljtunnel http tokens
    # made on 2026-10-28
    9Xk2mQpR7vNbZ4tL
    4Hj8sWdE1uYcF6gA

THE THREE RULES
----------------
There are three things a person with a token can do, and they are not
the same for every token.

| | what it needs |
|---|---|
| DOWNLOAD a file | ANY token in the table |
| UPLOAD a file | any token in the table |
| DELETE a file | THE token that uploaded it |

**THE DELETE RULE IS THE ONE THAT MATTERS.**  Everybody who has a
token can put a file in, and everybody who has a token can take a
file out -- but only the person whose token put it there can take it
out.  So a person cannot delete somebody else's work by guessing a
name.

**AND EVERY FILE REMEMBERS WHO PUT IT THERE.**  That is the owner
record: a small file next to the thing, in the server's own state
directory, and not in the served directory -- because a file in the
served directory is a file the people can read, and an owner record
is not theirs to read.

HOW THE OWNERSHIP IS KEPT
-------------------------
**IN A SEPARATE DIRECTORY, KEYED BY THE FILE'S PATH.**  So:

    <the state>/ljtunnel-http-token/owners/<the path, hashed>.owner

The name is a hash of the file's path, so it is a fixed length and it
cannot be walked, and it cannot be guessed from the name of the file
somebody is trying to delete.

**AND THE OWNER RECORD IS WRITTEN WHEN THE FILE IS PUT THERE**, and
it says which token did it.

THE TOKENS ARE MADE AND KEPT
----------------------------
**TEN BY DEFAULT**, and more with:

    ljtunnel dialer expand-tokens 5

which adds five and says how many there are now.

**A TOKEN IS RANDOM AND NOT A HASH OF SOMETHING.**  A token that can
be worked out from a known value is a token that can be worked out by
somebody else.  So it is 24 bytes from the system's own generator.
"""
from __future__ import annotations

import hashlib
import os
import secrets

# How many tokens there are when the table is made.
DEFAULT_TOKENS = 10

# The name of the table, and of the directory it is in.
TABLE_NAME = "token-filetable"


def token_dir() -> str:
    """The directory the table and the owner records are in.

    **IT IS THE HTTP SERVER'S OWN DIRECTORY AND NOT THE TUNNEL'S.**
    The tunnel's state directory holds the tunnel's keys, and this
    holds the keys to the web server, and the two are different
    things with different lives.

    **AND IT IS PRIVATE.**  The directory is 0700 and the file in it
    is 0600, so a token is not readable by anybody else on the
    machine.
    """
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "ljtunnel-http-token")
    base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, "ljtunnel-http-token")


def table_path() -> str:
    """The table itself."""
    return os.path.join(token_dir(), TABLE_NAME)


def owners_dir() -> str:
    """Where the owner records are kept.

    **IT IS NOT IN THE SERVED DIRECTORY.**  A file in the served
    directory is a file the people can read, and an owner record says
    who may delete a thing -- that is not theirs to read.
    """
    return os.path.join(token_dir(), "owners")


# THE MODES.  They are named so that a check can ask for them, and
# not read the numbers out of the source.
#
# MEASURED: the directory was made 0755 and the check did not fire,
# because the check only ran on the machine where the mode means
# something.  So the mode is ASKED FOR here, and the check asks the
# same question on every machine.
DIR_MODE = 0o700
FILE_MODE = 0o600


def _ensure_private_dir(path: str) -> None:
    """Make the directory, and make it private.

    **THE PERMISSIONS ARE SET AFTER THE DIRECTORY IS MADE**, because
    `os.makedirs` uses the umask and the umask is not the same on
    every machine.
    """
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, DIR_MODE)
    except OSError:
        # ON WINDOWS THE PERMISSIONS ARE NOT THE SAME THING, and
        # `chmod` only turns the read-only bit on.  The directory is
        # under the user's own profile there, so it is private by
        # being there.
        pass


def _ensure_private_file(path: str) -> None:
    """Make the file private, if it is there."""
    try:
        os.chmod(path, FILE_MODE)
    except OSError:
        pass


def make_token() -> str:
    """A fresh random token.

    **IT IS RANDOM AND NOT A HASH OF SOMETHING.**  A token that can
    be worked out from a known value is a token that can be worked out
    by somebody else.  So it is 24 bytes from the system's own
    generator, and it is a hex string so it can be typed.
    """
    return secrets.token_hex(24)


def read_tokens() -> list:
    """The tokens in the table, in order.

    **A FILE THAT CANNOT BE READ IS TREATED AS NO TOKENS**, and not as
    a crash: the table is a convenience and the program says so when
    there is nothing in it.
    """
    path = table_path()
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                out.append(line)
    except OSError:
        pass
    return out


def write_tokens(tokens: list) -> None:
    """Write the table, and keep it private."""
    _ensure_private_dir(token_dir())
    path = table_path()
    tmp = path + ".new"
    body = ["# the ljtunnel http tokens",
            "# one per line; a line that starts with a # is a comment",
            "# this file holds the keys to the web server -- keep it private"]
    body += list(tokens)
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write("\n".join(body) + "\n")
    os.replace(tmp, path)
    _ensure_private_file(path)


def ensure_table(count: int = DEFAULT_TOKENS) -> list:
    """The table, made if it is not there.

    **THE TABLE IS MADE WITH TEN TOKENS**, and the tokens are printed
    by the caller -- a person has to know them, and there is nowhere
    else to read them from.
    """
    tokens = read_tokens()
    if tokens:
        return tokens
    tokens = [make_token() for _ in range(max(1, count))]
    write_tokens(tokens)
    return tokens


def expand(count: int) -> list:
    """Add more tokens, and return the whole table.

    **THE EXISTING TOKENS STAY.**  A token that somebody has is a
    token they are using, and taking it away would break whatever
    they are doing with it.

    **AND THE TABLE IS NOT LOST IF IT IS NOT THERE.**  MEASURED: the
    caller made the table with ten and then called this, and this read
    the file again -- which was still the empty one, because the
    caller had not written it yet -- and the ten went away.
    """
    tokens = read_tokens()
    extra = [make_token() for _ in range(max(0, count))]
    tokens = tokens + extra
    write_tokens(tokens)
    return tokens


# ---- the owners ----

def _owner_key(rel_path: str) -> str:
    """The file the owner record for a path is in.

    **IT IS A HASH OF THE PATH**, so it is a fixed length and it does
    not say what the file is called -- and the owner records cannot be
    walked, because the names are hashes.
    """
    h = hashlib.sha256(rel_path.encode("utf-8")).hexdigest()
    return h


def owner_of(rel_path: str) -> str:
    """The token that uploaded a file, or "".

    **A FILE WITH NO OWNER RECORD HAS NO OWNER**, and that means it
    cannot be deleted by a token -- it can be deleted by whoever put
    it there by another route, or not at all.
    """
    path = os.path.join(owners_dir(), _owner_key(rel_path) + ".owner")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def set_owner(rel_path: str, token: str) -> None:
    """Say which token uploaded a file."""
    _ensure_private_dir(token_dir())
    _ensure_private_dir(owners_dir())
    path = os.path.join(owners_dir(), _owner_key(rel_path) + ".owner")
    tmp = path + ".new"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(token)
    os.replace(tmp, path)
    _ensure_private_file(path)


def clear_owner(rel_path: str) -> None:
    """Forget a file's owner -- because the file is gone."""
    path = os.path.join(owners_dir(), _owner_key(rel_path) + ".owner")
    try:
        os.unlink(path)
    except OSError:
        pass
