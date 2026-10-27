"""Sync the tree to the far side, and run a command there.

THE FAR SIDE IS A MACHINE WITH NOTHING ON IT, and this is how the
tree gets there: one connection, one walk, one put per file.

THE ADDRESS AND THE PASSWORD COME FROM THE ENVIRONMENT, so nothing
is written down in the tree:

    LJT_SERVER, LJT_PORT, LJT_USER, LJT_PASSWORD

AND THE COMMAND IS AN ARGUMENT, so the script is not tied to one
particular thing to run.
"""
from __future__ import annotations

import os
import posixpath
import sys

import paramiko

# Where the tree lives on the far side.  It is in the environment
# too, because it is a fact about the machine and not about the
# software.
REMOTE = os.environ.get("LJT_REMOTE", "")

# The directories that are not part of the source.
SKIP = {"__pycache__", ".git", ".appdist-build", "appdist", "build",
        "dist", ".wix", ".pytest_cache", "ljtunnel.egg-info"}


def files(local_root):
    """Every file in the tree, as (relative posix path, full path)."""
    out = []
    for base, dirs, names in os.walk(local_root):
        dirs[:] = [d for d in dirs if d not in SKIP]
        for name in names:
            if name.endswith((".pyc", ".pyo")):
                continue
            full = os.path.join(base, name)
            rel = os.path.relpath(full, local_root).replace("\\", "/")
            out.append((rel, full))
    return out


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    local = os.environ.get("LJT_LOCAL", "")
    if not local:
        local = str(__import__("pathlib").Path(__file__).resolve().parents[1])

    # THE ADDRESS COMES FROM THE ENVIRONMENT, and there is no
    # default for it: the address of a machine is not a fact about
    # the software, and it is wrong the moment the machine is on a
    # different network.
    host = os.environ.get("LJT_SERVER", "")
    port = int(os.environ.get("LJT_PORT", "22"))
    user = os.environ.get("LJT_USER", "")
    password = os.environ.get("LJT_PASSWORD", "")

    if not (host and user and password):
        print("  LJT_SERVER, LJT_USER and LJT_PASSWORD are needed")
        return 2

    if not REMOTE:
        print("  LJT_REMOTE is needed")
        return 2

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=port, username=user, password=password, timeout=40,
              allow_agent=False, look_for_keys=False)
    sftp = c.open_sftp()

    # ---- the directories first ----
    made = set()
    for rel, _ in files(local):
        parts = rel.split("/")[:-1]
        for i in range(len(parts)):
            d = posixpath.join(REMOTE, *parts[:i + 1])
            if d in made:
                continue
            made.add(d)
            try:
                sftp.stat(d)
            except OSError:
                try:
                    sftp.mkdir(d)
                except OSError:
                    pass

    # ---- and then the files ----
    n = 0
    for rel, full in files(local):
        sftp.put(full, posixpath.join(REMOTE, rel))
        n += 1
    print(f"  copied {n} file(s) to {REMOTE}")

    if argv:
        si, so, se = c.exec_command(" ".join(argv), timeout=900)
        out = so.read().decode("utf-8", errors="replace")
        err = se.read().decode("utf-8", errors="replace")
        code = so.channel.recv_exit_status()
        if out:
            print(out)
        if err.strip():
            print("--- stderr ---")
            print(err)
        print(f"--- the exit: {code} ---")

    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
