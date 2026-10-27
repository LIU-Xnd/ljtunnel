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

PICKING THE PORT
----------------
The dialer asks for a port, and if the port is taken it asks for the
next one.  Nobody tells the dialer which port to use.

It cannot ask for port 0 and let the listen end's sshd choose,
because `PermitListen` refuses port 0 -- the range and the
auto-pick cannot be combined, and without a range the sshd picks a
random high port that no firewall rule can name.

AND THE CLIENT'S "SUCCESS" IS NOT ENOUGH
-----------------------------------------
A dialer that asks for a port which is ALREADY TAKEN is told

    remote forward success for: listen 0.0.0.0:10002

and gets NO socket.  The client is told "success" and the forward is
not there.

So the dialer does not believe the client: after the forwarding
connection is up, it checks that the port is really listening, and
if it is not, it moves on to the next port.  The check is on the
LISTEN END, because that is where the socket would be, so it is the
listen end's socket table that is asked -- over the ssh connection
itself, so no extra protocol is needed.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time

from . import detect, listen, paths, sshd
from . import quiet


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
    p.add_argument("--forward-port", type=int, default=None, metavar="N",
                   help="the port to ask the reachable end to forward "
                        "(default: the first free one in the range)")
    p.add_argument("--forward-range", type=int, default=20, metavar="N",
                   help="how many ports to try, from the first one "
                        "(default: 20)")
    p.add_argument("--local-port", type=int, default=10001, metavar="N",
                   help="this end's own sshd port (default: 10001)")
    p.add_argument("--user", default=None, metavar="NAME",
                   help="the user on the reachable end (default: this one)")
    p.add_argument("--local-user", default=None, metavar="NAME",
                   help="the account on THIS machine that a person logs in as "
                        "through the forwarded port")
    p.add_argument("--access-key", default=None, metavar="PUBKEY",
                   help="the end user's public key, for this end's key list")
    p.add_argument("--accept-new-host-key", action="store_true",
                   help="accept the reachable end's host key even if it "
                        "is not the one this end remembers -- use it "
                        "after the reachable end has been reinstalled")
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

    # The ports to try are worked out FIRST, because the log below
    # says what is going to be asked for, and "forward None" is not
    # something anybody can act on.
    ports = _ports_to_try(args)

    log("")
    log("  ljtunnel dialer -- the unreachable end")
    log(f"    the reachable end : {args.listen_host}:{args.listen_port}")
    log(f"    asking it to forward {ports[0]}"
        + (f"-{ports[-1]}" if len(ports) > 1 else "")
        + f" -> 127.0.0.1:{args.local_port}")
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
    # THE ACCOUNT ON THIS END.  The person who connects through the
    # forwarded port has to give a name that exists HERE, and this
    # end's accounts are not the reachable end's accounts.
    #
    # MEASURED: "Permission denied (publickey,keyboard-interactive)"
    # with a key that was perfectly good, because the name was the
    # reachable end's and not this end's.
    if args.local_user:
        log(f"  a person connects through the forwarded port as: "
            f"{args.local_user}")
    else:
        log("  a person connects through the forwarded port as this end's "
            "own account")
        log("    (--local-user says which one, if it is not the default)")
    log("")

    if args.print_only:
        return 0

    # 1. this end's sshd, on its own port
    log("  starting this end's sshd ...")
    # THIS END'S SSHD PRESENTS THE MACHINE KEY AS ITS HOST KEY.
    #
    # The listen end finds its dialers by asking the forwarded port
    # who is there, and the answer is the host key behind it.  So
    # the key behind a forwarded port has to be a key the listen end
    # KNOWS, and the only one it knows is the one the dialer logged
    # in with.  So the two are the same key.
    #
    # One key, two jobs, and it is still one key on disk.
    srv = sshd.start(args.local_port, listen="127.0.0.1",
                     gateway_ports=False, allow_forwarding=False,
                     host_key=key, allowed_users=args.local_user or "")
    time.sleep(1.5)
    if srv.poll() is not None:
        log("  the sshd did not start.")
        if sshd.port_busy(args.local_port, "127.0.0.1"):
            log(f"  port {args.local_port} is held by another process.")
        _dump(paths.log_file())
        return 1
    log(f"  the sshd is up (pid {srv.pid})")

    # 2. the forwarding connection
    #
    # The port is found by TRYING.  The listen end's sshd refuses a
    # port that is already taken, and says so, so the dialer asks for
    # the next one and tries again.
    #
    # And the client cannot be believed: a dialer that asks for a
    # taken port is told "forward success" and gets NO socket.  So
    # the port is CHECKED before the dialer says it is up -- the
    # check is on the listen end, over the same ssh connection, so it
    # needs no protocol of our own.
    log(f"  the ports to try: {ports[0]}-{ports[-1]}")

    # ---- THE REACHABLE END'S HOST KEY, CHECKED FIRST ----
    #
    # BEFORE a single port is tried.  A changed host key makes EVERY
    # attempt fail, and the failure looks like a banner problem, so
    # the dialer would try twenty ports and say nothing about the
    # real cause.
    #
    # The check is the fingerprint of the key the reachable end
    # presents, compared with the one this end remembers.  The
    # remembered one is in the state directory's known_hosts, and it
    # is written there by ssh itself.
    #
    # AND A CHANGED KEY IS NOT ACCEPTED.  It is reported, and the
    # dialer stops.  Accepting it would mean that anybody who could
    # take the reachable end's address could take the tunnel with it,
    # and the host key is the one thing in this protocol that cannot
    # be faked.
    known = _known_host_key(args.listen_host, args.listen_port)
    now = detect.host_key_fingerprint(args.listen_port, args.listen_host,
                                      timeout=15)
    if now and known and now != known:
        if not getattr(args, "accept_new_host_key", False):
            log("")
            log(f"  THE REACHABLE END'S HOST KEY CHANGED.")
            log(f"    it was:  {known}")
            log(f"    it is:   {now}")
            log("")
            log("  That is not a tunnel problem: the reachable end is")
            log("  presenting a different key than this end remembers.")
            log("  It happens when the reachable end's configuration was")
            log("  cleared and the keys were made again.")
            log("")
            log("  If you know the reachable end was reinstalled, say so")
            log("  and this end will take the new key:")
            log("")
            log("    ljtunnel dialer ... --accept-new-host-key")
            log("")
            log("  Otherwise this end's memory of it stays where it is,")
            log("  because the host key is the one thing in this")
            log("  protocol that cannot be faked.")
            _kill(srv)
            sshd.stop()
            return 1

        # ---- AND THE PERSON SAID SO ----
        #
        # The old key is TAKEN AWAY, not just ignored: the next run
        # has to find one key and not two, or the comparison is
        # against whichever the file lists first.
        log("")
        log("  the reachable end's host key CHANGED, and you said to")
        log("  accept it.")
        log(f"    it was:  {known}")
        log(f"    it is:   {now}")
        log("")
        log("  This end's memory of the old key is taken away, so the")
        log("  next run compares against the new one.")
        _forget_known_host(args.listen_host, args.listen_port)

    fwd = None
    got = 0
    for port in ports:
        cmd = _forward_command(args, key, port, user)
        log("")
        log(f"  asking for port {port} ...")
        fwd = quiet.popen_hidden(cmd, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, text=True,
                               errors="replace")
        time.sleep(2.0)
        if fwd.poll() is not None:
            # the connection itself failed: the port was refused, or
            # the sshd would not have it
            err = fwd.stderr.read() if fwd.stderr else ""
            reason = _refusal_reason(err)
            log(f"  no: {reason}")
            _kill(fwd)
            fwd = None
            continue

        # the client says it worked.  Check.
        if _port_is_ours(args, port):
            got = port
            log(f"  yes: port {port} is forwarding to this end")
            break

        log(f"  the client said yes but port {port} is not ours. "
            f"Trying the next one.")
        _kill(fwd)
        fwd = None

    if not got:
        log("")
        log(f"  no port in {ports[0]}-{ports[-1]} could be taken.")
        log("  The reachable end may already have that many dialers.")
        _kill(srv)
        sshd.stop()
        return 1

    log("")
    log(f"  the forwarding command:")
    log("    " + " ".join(_forward_command(args, key, got, user)))
    log("")

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


def _ports_to_try(args) -> list:
    """The ports to try, in order.

    A port that was given is tried first, and the range starts there:
    a person who was told "use 10007" gets 10007, and the ones after
    it are the fallback.
    """
    first = args.forward_port
    if first is None:
        first = listen.FIRST_FORWARD_PORT
    return list(range(first, first + max(1, args.forward_range)))


def _forward_command(args, key: str, port: int, user: str) -> list:
    """The ssh command that asks the reachable end for that port."""
    return [
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
        "-R", f"0.0.0.0:{port}:127.0.0.1:{args.local_port}",
        f"{user}@{args.listen_host}",
    ]


def _known_host_key(host: str, port: int) -> str:
    """The fingerprint this end remembers for the reachable end, or "".

    IT IS READ FROM THE STATE DIRECTORY'S known_hosts, which is the
    file ssh itself writes and the file the dialer points ssh at
    with `UserKnownHostsFile`.  So it is the same memory ssh uses,
    and there is no second copy to get out of step.

    The file is in the hashed form, so the line is found by asking
    ssh for it -- `ssh-keygen -F` knows the hash -- rather than by
    reading the file and looking for the address.
    """
    import subprocess

    kf = os.path.join(paths.state_dir(), "known_hosts")
    if not os.path.isfile(kf):
        return ""

    # the file is in the hashed form, so ssh-keygen -F finds it
    try:
        r = quiet.run_hidden(["ssh-keygen", "-F", f"[{host}]:{port}",
                            "-f", kf],
                           capture_output=True, text=True,
                           errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""

    for line in (r.stdout or "").splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        # THE HOST MAY BE IN THE HASHED FORM, and then the line is
        #
        #     |1|salt|hash ssh-ed25519 AAAA...
        #
        # so the KEY is the SECOND field and not the first.  Looking
        # at the first field finds nothing, and the check then never
        # fires.
        parts = s.split()
        for i, part in enumerate(parts):
            if part.startswith(("ssh-", "ecdsa-", "sk-")) and i + 1 < len(parts):
                return detect._fingerprint_of(" ".join(parts[i:]))
    return ""


def _forget_known_host(host: str, port: int) -> bool:
    """Take this end's memory of the reachable end's host key away.

    THE FILE IS IN THE HASHED FORM, so the line is found by asking
    ssh for it -- `ssh-keygen -F` knows the hash -- and then it is
    removed by asking ssh to do it, because ssh wrote it and ssh
    knows how to take it out again.
    """
    import subprocess

    kf = os.path.join(paths.state_dir(), "known_hosts")
    if not os.path.isfile(kf):
        return False

    for args in (["-R", f"[{host}]:{port}", "-f", kf],
                 ["-R", host, "-f", kf]):
        try:
            r = quiet.run_hidden(["ssh-keygen"] + args, capture_output=True,
                               text=True, errors="replace", timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0:
            return True
    return False


def _refusal_reason(stderr: str) -> str:
    """Why the ssh connection did not stay up, in words."""
    text = (stderr or "").lower()
    # ---- THE HOST KEY CHANGED ----
    #
    # This one matters more than the others, because it is the only
    # one that says something is WRONG rather than that something
    # was refused.
    #
    # OpenSSH closes the connection before it says anything useful,
    # and the dialer reads it as a row of @ signs -- which looks like
    # a banner problem and is not.  MEASURED: the reachable end's
    # host key had been regenerated (its configuration was cleared),
    # the far side's known_hosts still had the old one, and the
    # dialer's whole output was twenty lines of "@@@@@@".
    #
    # And the sshd's side of it says only:
    #
    #     user: (null): Connection closed by 192.0.2.7 [preauth]
    #
    # so there is nothing to match on either side.
    if "host key" in text and ("changed" in text or "mismatch" in text
                                or "verification failed" in text):
        return ("the reachable end's host key CHANGED -- the key it "
                "presents is not the one this end remembers")
    if "remote host identification has changed" in text:
        return ("the reachable end's host key CHANGED -- the key it "
                "presents is not the one this end remembers")
    if "remote port forwarding failed" in text:
        return "the reachable end refused that port"
    if "permission denied" in text:
        return "the reachable end did not accept this end's key"
    if "could not resolve" in text or "name or service not known" in text:
        return "the reachable end could not be found"
    if "connection refused" in text:
        return "nothing is listening on the reachable end"
    if "connection timed out" in text or "timed out" in text:
        return "the reachable end did not answer (the firewall?)"
    for line in (stderr or "").splitlines():
        if line.strip():
            return line.strip()[:100]
    return "the connection failed"


def _port_is_ours(args, port: int) -> bool:
    """Is the port on the reachable end really forwarding to US?

    The client cannot be believed.  A dialer that asks for a port
    which is already taken is told

        remote forward success for: listen 0.0.0.0:20002

    and gets NO socket -- and on Windows the second dialer even takes
    the port away from the first one, so the first dialer's forward
    silently stops working.

    So the port is checked by reading the HOST KEY behind it.  The
    dialer knows its own host key, and the port that carries it is
    the port that is really forwarding to this machine.  A port with
    somebody else's key, or with no key at all, is not this one.

    The host key is the only thing here that cannot be faked: it is
    what the ssh KEY EXCHANGE is built on, and the other end has to
    prove it holds the private half.

    The check is made from the DIALER's side, at the reachable end's
    address, so it works wherever the tunnel is going to be used
    from.  A dialer behind a NAT can reach the reachable end (it
    dialled out to it), so it can check the port the same way.
    """
    mine = _own_host_key_fingerprint()
    if not mine:
        # No host key of our own, so there is nothing to compare
        # against.  The dialer's sshd is what has one, and it is
        # started before this point, so this is not the normal case.
        return False

    theirs = detect.host_key_fingerprint(port, args.listen_host, timeout=20)
    return bool(theirs) and theirs == mine


def _own_host_key_fingerprint() -> str:
    """The fingerprint of THIS end's own host key, or "".

    It is the key the sshd on this machine presents, and it is what
    somebody on the other end of a forward sees.  So it is the thing
    that says "this port is mine".

    IT IS THE MACHINE KEY, because this end's sshd presents the
    machine key as its host key.  The machine key is what the
    reachable end knows -- it is the key this end logs in with -- so
    the key behind a forwarded port is the key the reachable end can
    look up in its list, and that is how the reachable end NAMES the
    dialer without the sshd's log.

    So it is the same key on both sides of the check, and it is
    checked against the machine key's file rather than the host
    key's -- which is a different file and a different key, and
    comparing against it says "this port is not mine" about a port
    that IS.
    """
    key = paths.client_key()
    if not os.path.isfile(key + ".pub"):
        return ""
    try:
        r = quiet.run_hidden([sshd.ssh_keygen_path(), "-lf", key + ".pub"],
                           capture_output=True, text=True,
                           errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    parts = (r.stdout or "").strip().split()
    return parts[1] if len(parts) >= 2 else ""



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
