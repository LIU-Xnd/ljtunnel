"""ljtunnel dialer -- the unreachable end.

This side cannot be reached, so it dials OUT. It runs its own sshd on
a local port, and asks the listen end to forward a port back to it:

    ssh -N -R 0.0.0.0:<listen_port>:127.0.0.1:<local_port> \
        -p <listen_sshd_port> <user>@<listen_host>

After that, connecting to <listen_host>:<listen_port> lands on this
machine's own sshd -- a shell on a box that has no inbound port at
all.

THE TWO PORTS
-------------
Both are on the LISTEN end's machine, and that is the part that is
easy to get wrong:

    the listen end's sshd port   (10001)  -- where the DIALER connects
    the forwarded port           (10002)  -- where OTHER PEOPLE connect,
                                           to reach the dialer

So the dialer needs to know TWO ports on the listen end, and only one
of them is its own sshd. The local port is this end's own sshd, and
it never changes.

THE TWO KEYS
------------
    id_rsa_ljtunnel          this end's own identity. Its PUBLIC half
                             goes in the listen end's key list, so the
                             listen end's sshd lets this dialer in.

    the access key           the end USER's identity. Its PUBLIC half
                             goes in THIS end's key list, so this
                             end's sshd lets the person in. The
                             private half stays with the person.

Two relationships, two identities, two key lists. Neither end's sshd
is trusting its own key.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from . import paths, sshd


def log(msg: str = "") -> None:
    print(msg, flush=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ljtunnel dialer",
        description="the unreachable end: run an sshd here and forward a "
                    "port on the reachable end back to it")
    p.add_argument("--listen-host", required=True, metavar="HOST",
                   help="the reachable end -- the machine that holds the port")
    p.add_argument("--listen-port", type=int, default=10001, metavar="N",
                   help="the reachable end's sshd port (default: 10001)")
    p.add_argument("--forward-port", type=int, default=10002, metavar="N",
                   help="the port to ask the reachable end to forward "
                        "(default: 10002)")
    p.add_argument("--local-port", type=int, default=10001, metavar="N",
                   help="this end's own sshd port (default: 10001)")
    p.add_argument("--user", default=None, metavar="NAME",
                   help="the user on the reachable end (default: this one)")
    p.add_argument("--access-key", default=None, metavar="PUBKEY",
                   help="the end user's public key, for this end's key list")
    p.add_argument("--print-only", action="store_true",
                   help="print what this would do and exit")
    return p


def current_user() -> str:
    return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    user = args.user or current_user()
    if not user:
        log("cannot tell who the user is; pass --user")
        return 2

    log("")
    log("  ljtunnel dialer -- the unreachable end")
    log(f"    the reachable end : {args.listen_host}:{args.listen_port}")
    log(f"    asking it to forward {args.forward_port} -> "
        f"127.0.0.1:{args.local_port}")
    log(f"    this end's sshd   : 127.0.0.1:{args.local_port}")
    log("")

    paths.ensure_dir(paths.state_dir())

    # The end user's key goes into this end's key list, so the person
    # can log in here. It is added, not replaced: the list may already
    # hold the user's own key, and taking that away would be rude.
    if args.access_key:
        add_key(args.access_key)

    # The machine key: this end's identity to the listen end.
    key = sshd.ensure_client_key()
    pub = sshd.public_key_of(key)
    log("  this end's key for the reachable end:")
    log(f"    {pub}")
    log("    (put this in the reachable end's key list)")
    log("")

    # The key list this end's sshd accepts: the end user's key.
    n_keys = len(read_keys())
    log(f"  the keys allowed into this end's sshd: {n_keys}")
    if n_keys == 0:
        log("    (none yet -- until there is one, nobody can log in here)")
    log("")

    if args.print_only:
        return 0

    # 1. this end's sshd, on its own port
    log("  starting this end's sshd ...")
    srv = sshd.start(args.local_port, listen="127.0.0.1",
                     gateway_ports=False, allow_forwarding=False)
    time.sleep(1.5)
    if srv.poll() is not None:
        log("  the sshd did not start.")
        if sshd.port_busy(args.local_port, "127.0.0.1"):
            log(f"  port {args.local_port} is held by another process.")
        _dump(paths.log_file())
        return 1
    log(f"  the sshd is up (pid {srv.pid})")

    # 2. the forwarding connection
    cmd = [
        sshd.ssh_path(), "-N",
        "-p", str(args.listen_port),
        "-i", key,
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "UserKnownHostsFile=" + os.path.join(paths.state_dir(),
                                                    "known_hosts"),
        "-o", "BatchMode=yes",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
        "-R", f"0.0.0.0:{args.forward_port}:127.0.0.1:{args.local_port}",
        f"{user}@{args.listen_host}",
    ]
    log("")
    log("  the forwarding command:")
    log("    " + " ".join(cmd))
    log("")

    fwd = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                           stderr=subprocess.PIPE, text=True,
                           errors="replace")

    try:
        while True:
            rc = fwd.poll()
            if rc is not None:
                log("")
                log(f"  the forwarding connection ended (exit {rc})")
                if rc != 0:
                    err = fwd.stderr.read() if fwd.stderr else ""
                    if err.strip():
                        log("  " + err.strip())
                break
            time.sleep(1.0)
    except KeyboardInterrupt:
        log("")
        log("  stopping")
    finally:
        _kill(fwd)
        _kill(srv)
        sshd.stop()

    log("  stopped")
    return 0


def add_key(pubkey: str) -> None:
    """Let a key log in to this end's sshd.

    The list is this tunnel's own, not the user's ~/.ssh, so the
    tunnel's access is exactly the access that was handed to it.
    """
    path = paths.authorized_keys()
    lines = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            lines = [l.rstrip() for l in fh if l.strip()]
    key = pubkey.strip()
    if key and key not in lines:
        lines.append(key)
    sshd.set_authorized_keys(lines)


def read_keys() -> list:
    path = paths.authorized_keys()
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [l.strip() for l in fh if l.strip()]


def _kill(proc) -> None:
    if not proc:
        return
    try:
        proc.terminate()
        proc.wait(timeout=8)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _dump(path: str, lines: int = 20) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            tail = fh.readlines()[-lines:]
        for line in tail:
            log("    " + line.rstrip())
    except OSError:
        log("    (no log)")


if __name__ == "__main__":
    sys.exit(main())
