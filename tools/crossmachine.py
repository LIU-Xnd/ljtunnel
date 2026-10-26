"""The cross-machine test, with the dialers FOUND rather than given.

This is the product's real proof: the listen end on one machine, the
dialer end on another, and a connection to the listen end's forwarded
port landing on the DIALER's sshd -- with nobody adding a dialer to
the panel and nobody giving a dialer a port.

It needs two machines and a port the firewall lets through, so it is
not part of the self-test -- the self-test runs on one machine with no
network and no administrator shell.

THE PORTS
---------
The production ports are 10001 and 10002+. Those are not open on
Windows unless a firewall rule is in, and adding one needs an
administrator shell.

So the test can be pointed at other ports. The rule that ships with
OpenSSH for Windows allows 22, 10000 and 20000, and it is scoped to
the sshd.exe binary -- which is the same binary the user-level sshd
runs. So 10000 and 20000+ exercise the whole mechanism with no
administrator rights at all.

The PORT NUMBERS do not matter to the mechanism. What matters is that
a forwarded port on the listen end answers with the DIALER's sshd,
and that the listen end worked out who is on it by itself.

THE USERS ARE NOT THE SAME
--------------------------
The two ends are on two machines, and the account on one is not an
account on the other. The listen end authenticates the WINDOWS
account; the dialer end authenticates the LINUX one. Getting this
wrong shows up as "Invalid user" in the dialer's log, and nothing at
all on the listen end.

Usage:
    python tools/crossmachine.py --listen-host <ip> --user <name> \\
        --linux-user <name> [--sshd-port 10000] \\
        [--first-forward-port 20000] [--forward-count 20]
"""
from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ljtunnel import detect, listen, paths, sshd   # noqa: E402

_results = []


def check(name, ok, detail=""):
    _results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))
    return bool(ok)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen-host", required=True)
    ap.add_argument("--user", required=True,
                    help="the user on the listen end")
    ap.add_argument("--linux-user", required=True,
                    help="the user on the DIALER end -- a different "
                         "machine, so usually a different account")
    ap.add_argument("--sshd-port", type=int, default=10000,
                    help="the listen end's sshd port (default: 10000)")
    ap.add_argument("--first-forward-port", type=int, default=20000,
                    help="the first forwarded port (default: 20000)")
    ap.add_argument("--forward-count", type=int, default=20,
                    help="how many forwarded ports there are (default: 20)")
    ap.add_argument("--dialer-command", default=None,
                    help="the command that starts the dialer end")
    args = ap.parse_args()

    first = args.first_forward_port
    count = args.forward_count

    print("=== 1. the listen end's sshd, here ===")
    paths.ensure_dir(paths.state_dir())
    sshd.ensure_host_key()
    sshd.ensure_client_key()

    L = listen.Listener(sshd_port=args.sshd_port, first_port=first,
                        count=count)

    # The dialer's key, and the name that goes with it.  This is the
    # ONLY thing that is done by hand: the key has to be in this end's
    # key list, or the sshd will not let that machine in.
    dialer_pub = os.environ.get("LJT_DIALER_PUBKEY", "").strip()
    dialer_name = os.environ.get("LJT_DIALER_NAME", "").strip()
    if dialer_pub:
        listen.add_key(dialer_pub, dialer_name)
        check("the listen end's key list has the dialer's key",
              os.path.getsize(paths.authorized_keys()) > 0)
    else:
        print("  (no LJT_DIALER_PUBKEY: the key list is left as it is)")

    L.start()
    time.sleep(3)
    check("the listen end's sshd is running", L.proc.poll() is None,
          f"pid {L.proc.pid}")
    if L.proc.poll() is not None:
        print("  the sshd did not start. Its log:")
        try:
            for line in open(paths.log_file(), encoding="utf-8",
                             errors="replace").readlines()[-15:]:
                print("   ", line.rstrip())
        except OSError:
            print("    (no log)")
        return 1

    print()
    print("=== 2. the dialer end, on the other machine ===")
    if args.dialer_command:
        print(f"  {args.dialer_command}")
        subprocess.run(args.dialer_command, shell=True, timeout=180)
        time.sleep(15)
    else:
        print("  (no --dialer-command: start it yourself)")

    print()
    print("=== 3. WHAT THE LISTEN END SEES, with nobody adding anything ===")
    dialers = L.dialers()
    for d in dialers:
        print(f"    port {d.port}  name {d.name!r}  key {d.fingerprint[:24]}")
    check("the listen end found a dialer by itself", len(dialers) >= 1,
          f"{len(dialers)} found")
    check("it is on a port in the range",
          any(first <= d.port < first + count for d in dialers),
          str([d.port for d in dialers]))
    if dialer_name:
        check("it knows the dialer's name",
              any(d.name == dialer_name for d in dialers),
              str([d.name for d in dialers]))

    if not dialers:
        print("  (no dialer, so there is nothing to connect to)")
        L.stop()
        return 1

    port = dialers[0].port

    print()
    print("=== 4. THE TEST: connect to the forwarded port ===")
    banner = b""
    for target in (args.listen_host, "127.0.0.1"):
        s = socket.socket()
        s.settimeout(12)
        try:
            s.connect((target, port))
            s.settimeout(12)
            banner = s.recv(64)
            print(f"  {target}:{port} -> {banner[:50]!r}")
            if b"OpenSSH" in banner:
                break
        except Exception as e:
            print(f"  {target}:{port} -> {type(e).__name__}: {e}")
        finally:
            s.close()
    check("an ssh answered on the forwarded port", b"OpenSSH" in banner,
          banner[:40].decode("ascii", "replace"))

    print()
    print("=== 5. the HOST KEY behind the port says who is there ===")
    fp = detect.host_key_fingerprint(port, args.listen_host, timeout=25)
    check("the host key behind the port can be read", bool(fp), fp or "(none)")

    print()
    print("=== 6. log in THROUGH the tunnel ===")
    r = subprocess.run(
        [sshd.ssh_path(), "-p", str(port),
         "-i", paths.access_key(),
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=NUL",
         "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=12",
         f"{args.linux_user}@{args.listen_host}",
         "echo THROUGH-TUNNEL; hostname; uname -s"],
        capture_output=True, text=True, errors="replace", timeout=60)
    print("  exit:", r.returncode)
    print("  stdout:", r.stdout.strip()[:300])
    if r.stderr.strip():
        print("  stderr:", r.stderr.strip()[-300:])
    check("a command ran through the tunnel", "THROUGH-TUNNEL" in r.stdout)

    here = subprocess.run(["hostname"], capture_output=True, text=True,
                          errors="replace").stdout.strip().lower()
    there = ""
    for line in r.stdout.splitlines():
        if line.strip() and line.strip() != "THROUGH-TUNNEL":
            there = line.strip()
            break
    check("it ran somewhere else, not on this machine",
          there and there.lower() != here,
          f"this machine is {here!r}, the tunnel landed on {there!r}")
    check("the far end is a Linux box", "linux" in r.stdout.lower(),
          r.stdout.strip()[-120:])

    print()
    print("=== 7. cleaning up ===")
    L.stop()

    passed = sum(1 for _, ok, _ in _results if ok)
    print()
    for name, ok, detail in _results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"  {passed}/{len(_results)} passed")
    return 0 if passed == len(_results) else 1


if __name__ == "__main__":
    sys.exit(main())
