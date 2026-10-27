"""THE CROSS-MACHINE TEST, WITH THE FAR SIDE BEING THE FROZEN BINARY.

The point of the frozen binary is that the machine that cannot be
reached has nothing installed -- no Python, no conda, no pip.  So
the far side here is the BINARY, run with an empty environment, and
everything it needs it carries with it.

**AND THE VERSION IS NOT WRITTEN DOWN HERE.**  The first version of
this checked for a hard-coded "0.5.0", and then the release moved
on and the test failed for a reason that had nothing to do with the
product.  The version comes from the environment now, and the
environment says which one is expected.

WHAT IS READ FROM THE ENVIRONMENT:

    LJT_FAR_HOST, LJT_FAR_PORT, LJT_FAR_USER, LJT_FAR_PASSWORD
        the unreachable machine
    LJT_FAR_BIN
        the frozen binary on it
    LJT_EXPECT_VERSION
        the version it should say

THE THREE THINGS THAT HAD TO BE RIGHT, and each one cost a run:

  - THE DIALER CONNECTS TO THIS MACHINE.  The far machine's address
    is where the connection comes FROM, not where it goes TO.

  - THE KEY IS THE MACHINE KEY.  `ljtunnel key` prints the machine
    key, and the host key is a different key that the other end
    does not know.

  - THE DETECTION IS READ FROM THE LISTENER.  On Windows the sshd's
    sessions do not log to the listener's pipe, so the log cannot
    say who connected: the detection is the SCAN, and the scan asks
    the forwarded port who is there and looks the answer up in the
    key list.
"""
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import paramiko

WIN = r"D:\AgentWorkspace\projects\LjtunnelDev"
PY = r"C:\Users\xnd_l\miniforge3\envs\lj-dev\python.exe"

FAR_HOST = os.environ.get("LJT_FAR_HOST", "")
FAR_PORT = int(os.environ.get("LJT_FAR_PORT", "22"))
FAR_USER = os.environ.get("LJT_FAR_USER", "")
FAR_PASSWORD = os.environ.get("LJT_FAR_PASSWORD", "")
FAR_BIN = os.environ.get("LJT_FAR_BIN", "/home/liuxd/LjtunnelDev/dist/linux/ljtunnel")
EXPECT_VERSION = os.environ.get("LJT_EXPECT_VERSION", "")

LISTEN_PORT = 10000
FWD_PORT = 20000
WINDOWS_USER = os.environ.get("USERNAME", "xnd_l")

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))
    return ok


def frun(c, cmd, timeout=300):
    si, so, se = c.exec_command(cmd, timeout=timeout)
    out = ""
    while True:
        if so.channel.recv_ready():
            out += so.channel.recv(65536).decode("utf-8", errors="replace")
        elif so.channel.exit_status_ready():
            while so.channel.recv_ready():
                out += so.channel.recv(65536).decode("utf-8", errors="replace")
            break
        else:
            time.sleep(0.3)
    out += se.read().decode("utf-8", errors="replace")
    return out


if not (FAR_HOST and FAR_USER and FAR_PASSWORD):
    print("  LJT_FAR_HOST, LJT_FAR_USER and LJT_FAR_PASSWORD are needed")
    raise SystemExit(2)

print("=== this machine's address ===")
LISTEN_ADDR = None
for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
    if not a[4][0].startswith("127."):
        LISTEN_ADDR = a[4][0]
        break
print("  the reachable end is at:", LISTEN_ADDR)

print()
print("=== the far machine ===")
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(FAR_HOST, port=FAR_PORT, username=FAR_USER,
          password=FAR_PASSWORD, timeout=30)

out = frun(c, f"ls -la {FAR_BIN} 2>&1 | tail -1")
check("the frozen binary is there", "ljtunnel" in out, out.strip()[:80])

out = frun(c, f"env -i PATH=/usr/bin:/bin {FAR_BIN} --version 2>&1 | head -1")
say = out.strip()
if EXPECT_VERSION:
    check("and it is the version that is expected",
          EXPECT_VERSION in say, say[:60])
else:
    check("and it runs with an empty environment", say != "", say[:60])
print("  it says:", say)

print()
print("=== the far side's machine key ===")
out = frun(c, f"env -i PATH=/usr/bin:/bin HOME=/home/liuxd {FAR_BIN} key "
              f"2>&1 | tail -1")
machine_key = out.strip()
check("the binary printed its machine key",
      machine_key.startswith("ssh-ed25519"), machine_key[:60])

print()
print("=== the reachable end ===")
LISTENER = """
import sys, time
sys.path.insert(0, r"{win}")
for m in list(sys.modules):
    if m.startswith("ljtunnel"):
        del sys.modules[m]
sys.path = [p for p in sys.path if "site-packages" not in p]
sys.path.insert(0, r"{win}")
from ljtunnel import listen as L, sshd

sshd.stop()
sshd.stop_sessions()

listener = L.Listener(sshd_port={lp}, first_port={fp}, count=2)
srv = listener.start()
time.sleep(3)
print("READY", srv.pid, flush=True)

# THE DETECTION IS PRINTED AS IT HAPPENS.  On Windows this is the
# SCAN, not the log: the sshd's sessions do not log to the
# listener's pipe, so the log cannot say who connected.  The scan
# asks the forwarded port who is there and looks the answer up in
# the key list.
deadline = time.time() + 240
while time.time() < deadline:
    rows = listener.dialers()
    for row in rows:
        print("ROW", row.port, row.name, row.alive, flush=True)
    if rows:
        break
    time.sleep(3)
else:
    print("ROW none", flush=True)

time.sleep(30)
""".format(win=WIN, lp=LISTEN_PORT, fp=FWD_PORT)

# THE LISTENER SCRIPT GOES IN A TEMPORARY DIRECTORY.
#
# It was written to a fixed path in a scratch directory, and it
# stayed there afterwards -- and the next run found the OLD one and
# a test that was measuring the wrong thing would look like a
# passing test.
tmpdir = tempfile.mkdtemp(prefix="ljt-listen-")
p = pathlib.Path(tmpdir) / "listen.py"
p.write_text(LISTENER, encoding="utf-8", newline="\n")

proc = subprocess.Popen([PY, str(p)], stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True,
                        errors="replace")
ready = False
deadline = time.time() + 90
while time.time() < deadline:
    line = proc.stdout.readline()
    if not line:
        break
    if "READY" in line:
        ready = True
        break
check("the listener came up", ready, "READY" if ready else "no READY")

# ---- the far side's key goes into the reachable end's key list ----
code2 = """
import sys
sys.path.insert(0, r"{win}")
for m in list(sys.modules):
    if m.startswith("ljtunnel"):
        del sys.modules[m]
sys.path = [p for p in sys.path if "site-packages" not in p]
sys.path.insert(0, r"{win}")
from ljtunnel import listen as L, sshd
L.add_key({key!r}, "thefrozenbox")
sshd.set_authorized_keys(L.read_keys())
print("  the key is in the list")
""".format(win=WIN, key=machine_key)
r2 = subprocess.run([PY, "-c", code2], capture_output=True, text=True,
                    errors="replace", timeout=180)
check("the far side's key is in the list",
      "the key is in the list" in (r2.stdout or ""),
      (r2.stdout or r2.stderr or "").strip()[:80])

print()
print("=== the far side runs the FROZEN BINARY as the dialer ===")
# THE NEW HOST KEY IS ACCEPTED, BECAUSE THE REACHABLE END WAS
# REINSTALLED, and its configuration -- and so its host key -- was
# made again.
#
# WITHOUT IT the dialer stops with "THE REACHABLE END'S HOST KEY
# CHANGED", which is the right thing for a person and the wrong
# thing for a test that reinstalls the listen end on purpose.
dialer = (
    f"env -i PATH=/usr/bin:/bin HOME=/home/liuxd {FAR_BIN} dialer "
    f"--listen-host {LISTEN_ADDR} --listen-port {LISTEN_PORT} "
    f"--forward-port {FWD_PORT} --user {WINDOWS_USER} "
    f"--accept-new-host-key "
    f"> /tmp/ljt_dialer.log 2>&1 &"
)
frun(c, dialer, timeout=120)
time.sleep(20)
out = frun(c, "cat /tmp/ljt_dialer.log 2>&1 | tail -8")
print("  the dialer said:")
for line in out.splitlines()[:8]:
    print("   ", line[:110])

# ---- the forwarded port answers ----
banner = ""
try:
    s = socket.create_connection(("127.0.0.1", FWD_PORT), timeout=25)
    banner = s.recv(200).decode("utf-8", errors="replace").strip()
    s.close()
except Exception as e:
    banner = f"FAILED: {e}"
print("  the banner on the forwarded port:", banner)
check("the forwarded port speaks ssh", banner.startswith("SSH-"), banner[:60])
check("and it is the far machine's sshd",
      "OpenSSH" in banner and "8.2" in banner, banner[:70])

print()
print("=== and the reachable end SEES it, by itself ===")
rows = []
deadline = time.time() + 60
while time.time() < deadline:
    line = proc.stdout.readline()
    if not line:
        break
    if line.startswith("ROW"):
        rows.append(line.strip())
        if len(rows) >= 1:
            break
print("  the detection said:")
for r in rows:
    print("   ", r[:110])
check("the dialer shows up by itself",
      any(str(FWD_PORT) in r for r in rows),
      f"the rows were: {rows[:2]}")
check("and it is NAMED, with no help from the log",
      any("thefrozenbox" in r for r in rows),
      f"the rows were: {rows[:2]}")

print()
print("=== the clean up ===")
# The far side goes FIRST, and it is given a moment: the session on
# this side is a child that is told to go, and it holds the
# forwarded port the whole time it takes to go.
#
# AND THE FAR SIDE'S SSH CLIENT IS A SEPARATE PROCESS from the
# dialer: the dialer runs `ssh -N -R ...` as a child, and killing
# the dialer does not kill the ssh.  So the ssh is killed by its own
# name.
for attempt in range(3):
    frun(c, "pkill -9 -f 'dist/linux/ljtunnel' 2>/dev/null; "
            "pkill -9 -f 'ssh -N -p' 2>/dev/null; "
            "pkill -9 -f ljtunnel_sshd_config 2>/dev/null; "
            "pkill -9 -f 'sshd -f' 2>/dev/null; sleep 2; "
            "echo '  gone'", timeout=120)
    time.sleep(2)
    r = frun(c, "ss -ltn 2>/dev/null | grep -c ':10001' || true", timeout=60)
    if r.strip() in ("0", ""):
        break

try:
    proc.terminate()
    proc.wait(timeout=15)
except Exception:
    proc.kill()
time.sleep(3)

# AND THE SESSION ON THIS SIDE IS STOPPED, and it is given a moment
# to go on its own first.
code4 = """
import sys
sys.path.insert(0, r"{win}")
for m in list(sys.modules):
    if m.startswith("ljtunnel"):
        del sys.modules[m]
sys.path = [p for p in sys.path if "site-packages" not in p]
sys.path.insert(0, r"{win}")
from ljtunnel import sshd
# BOTH.  The sessions hold the FORWARDED port and the listener holds
# the listen port, and the test checks both of them.
print("  the sessions stopped:", sshd.stop_sessions())
print("  the listener stopped:", sshd.stop())
""".format(win=WIN)
r4 = subprocess.run([PY, "-c", code4], capture_output=True, text=True,
                    errors="replace", timeout=180)
print((r4.stdout or "").strip()[:80])
time.sleep(2)

r5 = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                     f"(Get-NetTCPConnection -State Listen "
                     f"-LocalPort {LISTEN_PORT},{FWD_PORT} "
                     "-ErrorAction SilentlyContinue | Measure-Object).Count"],
                    capture_output=True, text=True, errors="replace",
                    timeout=120)
check("the ports are free", (r5.stdout or "").strip() == "0",
      f"{(r5.stdout or '').strip()} held")

c.close()

# AND THE TEMPORARY DIRECTORY GOES WITH IT.
shutil.rmtree(tmpdir, ignore_errors=True)

print()
print("=== the summary ===")
for name, ok, detail in results:
    print(f"  {'PASS' if ok else 'FAIL'}  {name}")
passed = sum(1 for _, ok, _ in results if ok)
print(f"  {passed}/{len(results)} passed")
sys.exit(0 if passed == len(results) else 1)
