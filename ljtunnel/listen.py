"""ljtunnel listen -- the reachable end.

This side holds the port. It runs its own sshd, so the dialers can log
in, and it hands each dialer a port of its own to be reached on.

    machine A (here)                    machine B (unreachable)
      sshd on 10001          <---         ssh -R 10002 -> local 10001
      10002 -> dialer 1
      10003 -> dialer 2
      ...

A person on the network connects to A:10002 and lands on B's own sshd.
Nothing inbound ever touched B.

WHO INITIATES
-------------
The DIALER initiates. `ssh -R` is run by the dialer, connecting out to
this end's sshd. This end never dials out -- it cannot, because the
dialer is by definition the machine that cannot be reached.

So this end's jobs are:
  - run its own sshd
  - keep the list of allowed public keys
  - ASSIGN a port per dialer, and tell the dialer which one
  - show what is up

HOW A DIALER GETS ITS PORT
--------------------------
The panel shows the dialer a one-line command with the port already
in it. The dialer's public key is in this end's key list. The dialer
runs the command, and the forwarded port opens here.

The port is then THIS end's property: it was assigned here, and it is
released here when the dialer is removed. A port that is open here
but belongs to no dialer is a port that something else got into.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

from . import paths, sshd

# The port this end's own sshd listens on. The dialers log in here.
LISTEN_SSHD_PORT = 10001

# Where the forwarded ports start. Each dialer takes one.
FIRST_FORWARD_PORT = 10002

# How many forwarded ports there are. The range is what the firewall
# rule has to open.
FORWARD_PORT_COUNT = 20

LAST_FORWARD_PORT = FIRST_FORWARD_PORT + FORWARD_PORT_COUNT - 1


def log(msg: str = "") -> None:
    print(msg, flush=True)


def local_ipv4() -> str:
    """This machine's address, as the other end should reach it.

    Not 127.0.0.1: the dialer is on another machine, and 127.0.0.1
    there is the dialer. And not hardcoded: the address changes when
    the machine moves to another network, and a hardcoded one is
    wrong exactly when it matters.

    A UDP socket that sends nothing is the portable way to ask the
    routing table "which local address would I use to reach the
    internet". No packet is sent.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))     # TEST-NET-1: never routed
            addr = s.getsockname()[0]
            if addr and not addr.startswith("127."):
                return addr
        finally:
            s.close()
    except OSError:
        pass
    return "127.0.0.1"


def port_in_use(port: int) -> bool:
    """Is something already listening on that port here?

    The check is a BIND and a LISTEN, not a connect. A connect asks
    "is somebody there" and a closed port refuses, which is the same
    answer as a filtered one -- useless. A bind asks "can I take this
    port", which is the question that matters: the port is either
    taken or it is not.

    SO_REUSEADDR is ON, so a port in TIME_WAIT counts as free. That
    is right: TIME_WAIT is a leftover from a connection that has
    already ended, and a new listener can take the port.

    SO_EXCLUSIVEADDRUSE is what makes the answer true rather than
    optimistic. Without it, Windows lets two processes bind the same
    port, and the second one silently never receives anything.
    """
    s = socket.socket()
    try:
        if sys.platform == "win32":
            # On Windows SO_EXCLUSIVEADDRUSE and SO_REUSEADDR are
            # MUTUALLY EXCLUSIVE -- setting both gives WSAEINVAL.
            # The exclusive one is the one that matters here: it is
            # what stops a second process binding a port that is
            # already being listened on, which without it silently
            # never receives anything.
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        else:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        return False
    except OSError:
        return True
    finally:
        s.close()


class PortAllocator:
    """Hands out the forwarded ports, and takes them back.

    A port belongs to a dialer until the dialer is removed. The
    allocator does not look at the network to decide -- a port that is
    open but unassigned means something else got in, and the panel
    should show that, not paper over it.
    """

    def __init__(self, first: int = FIRST_FORWARD_PORT,
                 count: int = FORWARD_PORT_COUNT):
        self.first = first
        self.count = count
        self.taken = {}          # port -> name

    def assign(self, name: str) -> int:
        """Give a name a port. Raises ValueError when there is none left.

        A name that already has a port keeps it: asking again is a
        re-assertion, not a second port. A released port is handed
        out again, so removing a dialer and adding another does not
        quietly eat the range.
        """
        for p, n in self.taken.items():
            if n == name:
                return p
        for p in range(self.first, self.first + self.count):
            if p not in self.taken:
                self.taken[p] = name
                return p
        raise ValueError(
            f"all {self.count} forwarded ports are taken "
            f"({self.first}-{self.first + self.count - 1})")

    def release(self, name: str) -> None:
        for p, n in list(self.taken.items()):
            if n == name:
                del self.taken[p]

    def free_ports(self) -> list:
        return [p for p in range(self.first, self.first + self.count)
                if p not in self.taken]


def access_public_key() -> str:
    """The key the end USER logs in with.

    The private half lives here, on the reachable machine, and the
    public half is what each dialer puts in its key list. So the
    person reaches the dialer with one key, and the dialer's own
    machine key is not in that person's hands.
    """
    return sshd.public_key_of(sshd.ensure_access_key())


def add_key(pubkey: str) -> None:
    """Let a key log in to this end's sshd.

    The key list is this tunnel's own, not the user's ~/.ssh, so the
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


def start_sshd() -> subprocess.Popen:
    """This end's sshd, with remote forwarding allowed.

    GatewayPorts clientspecified is the setting that makes the whole
    thing reachable: without it the forwarded port binds to loopback
    and nobody off this machine can connect to it.
    """
    return sshd.start(LISTEN_SSHD_PORT, listen="0.0.0.0",
                      gateway_ports=True, allow_forwarding=True)


def dialer_command(port: int, user: str = "", host: str = "") -> str:
    """The one line the dialer runs.

    Copy-pasteable on purpose: the dialer should be one paste, not a
    paragraph of instructions.

    The access key is IN the command. That is what makes the setup
    one step instead of three: the dialer takes the key, puts it in
    its own key list, and the end user can log in. Without it the
    person would have to be handed a key and told what to do with it.

    The key is PUBLIC. The private half never leaves the listen end.
    """
    host = host or local_ipv4()
    user = user or current_user()
    return (f"ljtunnel dialer --listen-host {host} "
            f"--listen-port {LISTEN_SSHD_PORT} "
            f"--forward-port {port} --user {user} "
            f"--access-key \"{access_public_key()}\"")


def current_user() -> str:
    return os.environ.get("USERNAME") or os.environ.get("USER") or ""


def main(argv=None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="ljtunnel listen",
        description="the reachable end: an sshd, and a panel of dialers")
    p.add_argument("--print-only", action="store_true",
                   help="print what this would do and exit")
    args = p.parse_args(argv)

    log("")
    log("  ljtunnel listen -- the reachable end")
    log(f"    this end's sshd : {LISTEN_SSHD_PORT}")
    log(f"    forwarded ports : {FIRST_FORWARD_PORT}-{LAST_FORWARD_PORT}")
    log(f"    this end       : {local_ipv4()}")
    log("")

    if args.print_only:
        return 0

    paths.ensure_dir(paths.state_dir())
    sshd.ensure_host_key()
    sshd.ensure_client_key()
    sshd.set_authorized_keys(read_keys())

    srv = start_sshd()
    time.sleep(1.5)
    if srv.poll() is not None:
        log("  the sshd did not start.")
        if sshd.port_busy(LISTEN_SSHD_PORT):
            log(f"  port {LISTEN_SSHD_PORT} is held by another process.")
        _dump(paths.log_file())
        return 1
    log(f"  the sshd is up (pid {srv.pid})")
    log("")

    alloc = PortAllocator()
    try:
        _loop(alloc)
    except KeyboardInterrupt:
        log("")
        log("  stopping")
    finally:
        try:
            srv.terminate()
            srv.wait(timeout=8)
        except Exception:
            pass
        sshd.stop()
    log("  stopped")
    return 0


def _loop(alloc: PortAllocator) -> None:
    """A line-based control, so a terminal can drive it too.

    The desktop app is a view over the same state; this is what a
    person gets when they run it from a shell.
    """
    log("  commands: add <name> <host> [user] | remove <name> | "
        "list | quit")
    log("")
    while True:
        line = sys.stdin.readline()
        if not line:
            break
        parts = line.split()
        if not parts:
            continue
        cmd = parts[0].lower()

        if cmd in ("quit", "exit", "q"):
            break

        if cmd == "add" and len(parts) >= 3:
            name, host = parts[1], parts[2]
            user = parts[3] if len(parts) > 3 else current_user()
            try:
                port = alloc.assign(name)
            except ValueError as e:
                log(f"  {e}")
                continue
            log(f"  {name} is on port {port}")
            log(f"  the dialer runs:")
            log(f"    {dialer_command(port, user, host)}")

        elif cmd == "remove" and len(parts) >= 2:
            alloc.release(parts[1])
            log(f"  {parts[1]} is released")

        elif cmd == "list":
            if not alloc.taken:
                log("  (no dialers)")
            for port, name in sorted(alloc.taken.items()):
                log(f"  {name:16} port {port}")

        else:
            log("  ?")


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
