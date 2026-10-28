"""THE CROSS-MACHINE TEST, WITH THE FAR SIDE SERVING HTTP.

The tunnel's other shape: the unreachable machine offers a WEB PAGE,
and the reachable machine's forwarded port lands on it.  There is no
sshd on the far side, so there is no host key behind the forwarded
port -- and the far side says who it is in a header instead.

WHAT IS MEASURED, END TO END:

  * the far side runs the FROZEN BINARY as an http server
  * the reachable end's forwarded port really carries the page
  * the page is only served WITH the token
  * the reachable end's panel NAMES the dialer, with no help from the
    log -- on Windows the log says nothing, so the name comes from the
    header the server sends

WHAT IS READ FROM THE ENVIRONMENT:

    LJT_FAR_HOST, LJT_FAR_PORT, LJT_FAR_USER, LJT_FAR_PASSWORD
        the unreachable machine
    LJT_FAR_BIN
        the frozen binary on it
    LJT_EXPECT_VERSION
        the version it should say
    LJT_THIS_HOST
        THIS machine's address -- the one the far side dials out to.
        It is the reachable end's address and not the far side's, and
        it is a fact about the network and not about the software, so
        it comes from the environment.
    LJT_THIS_USER
        THIS machine's account -- the one the far side logs in as.

        IT HAS TO BE GIVEN.  MEASURED: the far side worked it out
        from its own environment and got its OWN account, and the
        reachable end said

            the reachable end did not accept this end's key

        which blames the key and is about the ACCOUNT: the far side
        dials out to this machine, so the account it gives has to
        exist HERE.
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

# THE PORTS ARE THIS TEST'S OWN, so they cannot fight with the source
# test's 10001 and 10002.
LISTEN_PORT = 10000
FWD_PORT = 20000

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'}  {name}"
          + (f"   -- {detail}" if not ok and detail else ""))


def frun(c, cmd, timeout=300):
    si, so, se = c.exec_command(cmd, timeout=timeout)
    return (so.read().decode("utf-8", "replace")
            + se.read().decode("utf-8", "replace"))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main():
    host = os.environ.get("LJT_FAR_HOST", "")
    port = int(os.environ.get("LJT_FAR_PORT", "22") or "22")
    user = os.environ.get("LJT_FAR_USER", "")
    password = os.environ.get("LJT_FAR_PASSWORD", "")
    binary = os.environ.get("LJT_FAR_BIN", "/home/liuxd/LjtunnelDev/dist/linux/ljtunnel")
    expect = os.environ.get("LJT_EXPECT_VERSION", "")
    this_host = os.environ.get("LJT_THIS_HOST", "")
    this_user = os.environ.get("LJT_THIS_USER", "")

    if not host or not user or not password:
        print("the environment is not set -- skipping")
        return 0
    if not this_host or not this_user:
        print("LJT_THIS_HOST and LJT_THIS_USER are not set -- "
              "this machine's address and account -- skipping")
        return 0

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(host, port=port, username=user, password=password,
              timeout=40, allow_agent=False, look_for_keys=False)

    print()
    print("=== the far side has the frozen binary ===")
    out = frun(c, f"ls -la {binary} 2>&1")
    check("the frozen binary is there", "ljtunnel" in out, out.strip()[:80])
    if expect:
        out = frun(c, f"{binary} --version 2>&1")
        check("and it is the version that is expected",
              expect in out, out.strip()[:60])

    print()
    print("=== the far side's machine key ===")
    out = frun(c, f"{binary} key 2>&1")
    machine_key = ""
    for line in out.splitlines():
        if line.strip().startswith("ssh-"):
            machine_key = line.strip()
            break
    check("the binary printed its machine key",
          machine_key.startswith("ssh-"), out.strip()[:80])
    if not machine_key:
        c.close()
        return 1

    # ---- a directory to serve, on the far side ----
    tmpdir = f"/home/liuxd/ljt-http-{int(time.time())}"
    # THE DIRECTORY IS MADE AND THE FILE IS WRITTEN, and it is WAITED
    # FOR: MEASURED, the two in one command and the dialer started
    # before the directory was there.
    out = frun(c, f"mkdir -p {tmpdir} && "
                  f"echo '<h1>IT_WORKS</h1>' > {tmpdir}/index.html && "
                  f"ls -la {tmpdir}/index.html")
    check("the directory to serve is there", "index.html" in out,
          out.strip()[-90:])

    # ---- the listener, on this machine ----
    print()
    print("=== the reachable end's listener ===")
    script = f'''
import sys
sys.path.insert(0, r"{WIN}")
from ljtunnel import listen as L, sshd, paths
L.clean_known_hosts()
srv = L.Listener(sshd_port={LISTEN_PORT}, first_port={FWD_PORT}, count=1)
p = srv.start()
import time
time.sleep(1.5)
print("READY", flush=True)
while True:
    time.sleep(1)
'''
    listener = subprocess.Popen([PY, "-c", script], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                errors="replace")
    ready = False
    deadline = time.time() + 60
    while time.time() < deadline:
        line = listener.stdout.readline()
        if not line:
            break
        if "READY" in line:
            ready = True
            break
    check("the listener came up", ready, "READY" if ready else "no READY")
    if not ready:
        listener.kill()
        c.close()
        return 1

    # ---- the far side's key goes into the reachable end's key list ----
    code2 = f"""
import sys
sys.path.insert(0, r"{WIN}")
from ljtunnel import listen as L, sshd
L.add_key({machine_key!r})
L.set_key_name({machine_key!r}, "thewebbox")
sshd.set_authorized_keys(L.read_keys())
print("  the key is in the list")
"""
    r2 = subprocess.run([PY, "-c", code2], capture_output=True, text=True,
                        errors="replace", timeout=180)
    check("the far side's key is in the list",
          "the key is in the list" in (r2.stdout or ""),
          (r2.stdout or r2.stderr or "").strip()[:80])

    # ---- the far side runs the FROZEN BINARY as an http server ----
    print()
    print("=== the far side runs the FROZEN BINARY as the http server ===")
    http_port = free_port()
    # THE FORWARDED PORT IS NAMED, because this test's listener admits
    # ONE port and the dialer would otherwise start at 10002 and walk
    # up past it.
    # THE SERVER ALLOWS WRITING, and it uses the token TABLE -- so
    # the token the test uses has to be in the table, and it is put
    # there first.
    out = frun(c, f"{binary} dialer --listen-host {this_host} "
                  f"--listen-port {LISTEN_PORT} --forward-port {FWD_PORT} "
                  f"--user {this_user} --name thewebbox "
                  f"--http-server --http-directory {tmpdir} "
                  f"--http-port {http_port} --http-token THETOKEN "
                  f"--http-allow-edit "
                  f"--accept-new-host-key > {tmpdir}/dialer.log 2>&1 &")
    time.sleep(12)
    out = frun(c, f"cat {tmpdir}/dialer.log 2>&1 | head -30")
    check("the http server started",
          "http server is up" in out, out.strip()[-140:])
    check("and the forward was taken",
          "is forwarding to this end" in out, out.strip()[-140:])

    print()
    print("=== the forwarded port carries the page ===")
    import http.client
    try:
        cc = http.client.HTTPConnection("127.0.0.1", FWD_PORT, timeout=15)
        cc.request("GET", "/THETOKEN/index.html")
        rr = cc.getresponse()
        body = rr.read()
        cc.close()
        check("the forwarded port serves the page",
              rr.status == 200 and b"IT_WORKS" in body,
              f"{rr.status} {body[:60]}")
        check("and it says who it is",
              rr.getheader("X-LJT-Name") == "thewebbox",
              repr(rr.getheader("X-LJT-Name")))
    except Exception as e:
        check("the forwarded port serves the page", False,
              f"{type(e).__name__}: {e}")

    try:
        cc = http.client.HTTPConnection("127.0.0.1", FWD_PORT, timeout=15)
        cc.request("GET", "/index.html")
        rr = cc.getresponse()
        body = rr.read()
        cc.close()
        check("and it refuses it without the token",
              rr.status == 404 and b"no token" in body,
              f"{rr.status} {body[:40]}")
    except Exception as e:
        check("and it refuses it without the token", False,
              f"{type(e).__name__}: {e}")

    print()
    print("=== the writing goes through the tunnel ===")
    try:
        cc = http.client.HTTPConnection("127.0.0.1", FWD_PORT, timeout=15)
        cc.request("PUT", "/THETOKEN/uploaded.txt", body=b"UPLOADED")
        rr = cc.getresponse()
        rr.read()
        cc.close()
        check("a file can be uploaded through the tunnel",
              rr.status in (201, 204), str(rr.status))
    except Exception as e:
        check("a file can be uploaded through the tunnel", False,
              f"{type(e).__name__}: {e}")

    out = frun(c, f"cat {tmpdir}/uploaded.txt 2>&1")
    check("and it arrived on the far side",
          "UPLOADED" in out, out.strip()[:60])

    try:
        cc = http.client.HTTPConnection("127.0.0.1", FWD_PORT, timeout=15)
        cc.request("GET", "/THETOKEN/uploaded.txt")
        rr = cc.getresponse()
        body = rr.read()
        cc.close()
        check("and it can be read back",
              rr.status == 200 and b"UPLOADED" in body,
              f"{rr.status} {body[:40]}")
    except Exception as e:
        check("and it can be read back", False, f"{type(e).__name__}: {e}")

    try:
        cc = http.client.HTTPConnection("127.0.0.1", FWD_PORT, timeout=15)
        cc.request("DELETE", "/THETOKEN/uploaded.txt")
        rr = cc.getresponse()
        rr.read()
        cc.close()
        check("and it can be deleted with the token that put it there",
              rr.status == 204, str(rr.status))
    except Exception as e:
        check("and it can be deleted with the token that put it there", False,
              f"{type(e).__name__}: {e}")

    out = frun(c, f"ls {tmpdir}/uploaded.txt 2>&1")
    check("and it is gone on the far side",
          "No such file" in out or "not found" in out.lower(),
          out.strip()[:60])

    print()
    print("=== the reachable end's panel NAMES the dialer ===")
    code3 = f"""
import sys
sys.path.insert(0, r"{WIN}")
from ljtunnel import listen as L, scan
srv = L.Listener(sshd_port={LISTEN_PORT}, first_port={FWD_PORT}, count=1)
rows = scan.scan_fast({FWD_PORT}, 1, timeout=15)
for r in rows:
    print("ROW", r.name, r.port, r.fingerprint[:24])
"""
    r3 = subprocess.run([PY, "-c", code3], capture_output=True, text=True,
                        errors="replace", timeout=300)
    out3 = r3.stdout or ""
    print("   ", out3.strip()[:200])
    check("the dialer shows up by itself",
          "ROW" in out3, out3.strip()[:100])
    check("and it is NAMED, with no help from the log",
          "thewebbox" in out3, out3.strip()[:120])

    print()
    print("=== the far side's cleanup ===")
    frun(c, f"pkill -f 'ljtunnel dialer' 2>/dev/null; "
            f"rm -rf {tmpdir}; echo done")

    # ---- and this machine's cleanup ----
    code4 = f"""
import sys
sys.path.insert(0, r"{WIN}")
from ljtunnel import listen as L, sshd
L.remove_key_text({machine_key!r})
print("  the key is out")
"""
    r4 = subprocess.run([PY, "-c", code4], capture_output=True, text=True,
                        errors="replace", timeout=180)
    check("the test's key is out of the real key list",
          "the key is out" in (r4.stdout or ""),
          (r4.stdout or r4.stderr or "").strip()[:80])

    code5 = f"""
import sys
sys.path.insert(0, r"{WIN}")
from ljtunnel import sshd
print("  the sessions stopped:", sshd.stop_sessions())
print("  the listener stopped:", sshd.stop())
"""
    r5 = subprocess.run([PY, "-c", code5], capture_output=True, text=True,
                        errors="replace", timeout=180)
    print((r5.stdout or "").strip()[:80])
    time.sleep(2)

    r6 = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                         f"(Get-NetTCPConnection -State Listen "
                         f"-LocalPort {LISTEN_PORT},{FWD_PORT} "
                         "-ErrorAction SilentlyContinue | Measure-Object).Count"],
                        capture_output=True, text=True, errors="replace",
                        timeout=120)
    check("the ports are free", (r6.stdout or "").strip() == "0",
          f"{(r6.stdout or '').strip()} held")

    try:
        listener.kill()
    except Exception:
        pass
    c.close()

    print()
    print("=== the summary ===")
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"  {passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
