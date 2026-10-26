"""The cross-machine test.

This is the product's real proof: the listen end on one machine, the
dialer end on another, and a connection to the listen end's forwarded
port landing on the DIALER's sshd.

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
runs. So 10000 and 20000 exercise the whole mechanism with no
administrator rights at all.

The PORT NUMBERS do not matter to the mechanism. What matters is that
a forwarded port on the listen end answers with the dialer's sshd.

Usage:
    python tools/crossmachine.py --listen-host <ip> --user <name> \
        [--sshd-port 10000] [--forward-port 20000]
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

from ljtunnel import paths, sshd   # noqa: E402

_results = []


def check(name, ok, detail=""):
    _results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))
    return bool(ok)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen-host", required=True)
    ap.add_argument("--user", required=True, help="the user on the listen end")
    ap.add_argument("--sshd-port", type=int, default=10000,
                    help="the listen end's sshd port (default: 10000)")
    ap.add_argument("--forward-port", type=int, default=20000,
                    help="the forwarded port (default: 20000)")
    ap.add_argument("--dialer-command", default=None,
                    help="the command that starts the dialer end")
    args = ap.parse_args()

    print("=== 1. the listen end's sshd, here ===")
    paths.ensure_dir(paths.state_dir())
    sshd.ensure_host_key()
    sshd.ensure_client_key()

    # the dialer's key, and the access key
    dialer_pub = os.environ.get("LJT_DIALER_PUBKEY", "").strip()
    if dialer_pub:
        sshd.set_authorized_keys([dialer_pub])
        check("the listen end's key list has the dialer's key",
              os.path.getsize(paths.authorized_keys()) > 0)
    else:
        print("  (no LJT_DIALER_PUBKEY: the key list is left as it is)")

    sshd.stop()
    cfg = sshd.write_config(args.sshd_port, "0.0.0.0",
                            gateway_ports=True, allow_forwarding=True)
    srv = subprocess.Popen(
        [sshd.sshd_path(), "-f", cfg, "-D"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    check("the listen end's sshd is running", srv.poll() is None,
          f"pid {srv.pid}")
    if srv.poll() is not None:
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
        subprocess.run(args.dialer_command, shell=True, timeout=120)
        time.sleep(8)
    else:
        print("  (no --dialer-command: start it yourself)")

    print()
    print("=== 3. is the forwarded port open here? ===")
    n = _listeners(args.forward_port)
    check(f"port {args.forward_port} is listening on the listen end",
          n > 0, f"{n} listener(s)")

    print()
    print("=== 4. THE TEST: connect to the forwarded port ===")
    banner = b""
    for target in (args.listen_host, "127.0.0.1"):
        s = socket.socket()
        s.settimeout(12)
        try:
            s.connect((target, args.forward_port))
            s.settimeout(12)
            banner = s.recv(64)
            print(f"  {target}:{args.forward_port} -> {banner[:50]!r}")
            if b"OpenSSH" in banner:
                break
        except Exception as e:
            print(f"  {target}:{args.forward_port} -> {type(e).__name__}: {e}")
        finally:
            s.close()
    check("an ssh answered on the forwarded port", b"OpenSSH" in banner,
          banner[:40].decode("ascii", "replace"))

    print()
    print("=== 5. log in THROUGH the tunnel ===")
    r = subprocess.run(
        [sshd.ssh_path(), "-p", str(args.forward_port),
         "-i", paths.access_key(),
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=NUL",
         "-o", "BatchMode=yes",
         "-o", "ConnectTimeout=12",
         f"{args.user}@{args.listen_host}",
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
    print("=== 6. cleaning up ===")
    srv.kill()

    passed = sum(1 for _, ok, _ in _results if ok)
    print()
    for name, ok, detail in _results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    print(f"  {passed}/{len(_results)} passed")
    return 0 if passed == len(_results) else 1


def _listeners(port: int) -> int:
    if sys.platform == "win32":
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f"(Get-NetTCPConnection -LocalPort {port} -State Listen "
             f"-ErrorAction SilentlyContinue | Measure-Object).Count"],
            capture_output=True, text=True, errors="replace", timeout=60)
        try:
            return int((r.stdout or "0").strip())
        except ValueError:
            return 0
    r = subprocess.run(["ss", "-tln"], capture_output=True, text=True,
                       errors="replace", timeout=30)
    return sum(1 for line in (r.stdout or "").splitlines()
               if f":{port} " in line)


if __name__ == "__main__":
    sys.exit(main())
