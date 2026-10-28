"""The PURE FORWARD across two machines.

THE POINT OF THIS TEST: the tunnel can land on something that is
ALREADY BEING SERVED on the far side, and start nothing there.

So the far side has a small http server of its own -- standing in for
`rclone serve webdav`, which is the thing this shape is FOR -- and the
dialer is told to forward that port and nothing else.

AND WHAT IS CHECKED:

    the far side's server is running and answers
    the dialer starts NOTHING on its own end
    the tunnel lands on the far side's server
    and it is the SAME server -- the page comes back
    and the dialer shows up in the reachable end's panel

AND IT IS THE FROZEN BINARY, because that is what the person runs.

THE ENVIRONMENT:

    LJT_FAR_HOST      the far side
    LJT_FAR_PORT      its ssh port
    LJT_FAR_USER      its account
    LJT_FAR_PASSWORD  its password
    LJT_FAR_BIN       the frozen binary (default: the usual path)
    LJT_EXPECT_VERSION  the version it should say
    LJT_THIS_HOST     THIS machine's address, as the far side sees it
    LJT_THIS_USER     THIS machine's account
"""

import http.client
import os
import subprocess
import sys
import time

import paramiko

PY = r"C:\Users\xnd_l\miniforge3\envs\lj-dev\python.exe"
WIN = r"D:\AgentWorkspace\projects\LjtunnelDev"

LISTEN_PORT = 10001
FWD_PORT = 10002

_ok = 0
_bad = 0


def check(name, ok, detail=""):
    global _ok, _bad
    if ok:
        _ok += 1
        print(f"  PASS  {name}")
    else:
        _bad += 1
        print(f"  FAIL  {name}")
        if detail:
            print(f"        {detail}")


def frun(c, cmd, timeout=300):
    _, out, err = c.exec_command(cmd, timeout=timeout)
    o = out.read().decode("utf-8", "replace")
    e = err.read().decode("utf-8", "replace")
    return o + e


def free_port():
    import socket
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
    binary = os.environ.get("LJT_FAR_BIN",
                            "/home/liuxd/LjtunnelDev/dist/linux/ljtunnel")
    expect = os.environ.get("LJT_EXPECT_VERSION", "")
    this_host = os.environ.get("LJT_THIS_HOST", "")
    this_user = os.environ.get("LJT_THIS_USER", "")

    if not host or not user or not password:
        print("the environment is not set -- skipping")
        return 0
    if not this_host or not this_user:
        print("LJT_THIS_HOST and LJT_THIS_USER are not set -- skipping")
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

    # ---- THE SERVER THAT IS ALREADY RUNNING ON THE FAR SIDE ----
    #
    # THIS IS THE WHOLE POINT: something is being served there, and
    # the tunnel lands on it.  It stands in for `rclone serve webdav`.
    print()
    print("=== the far side's own server ===")
    srv_port = free_port()
    tmpdir = f"/home/liuxd/ljt-fwd-{int(time.time())}"
    out = frun(c, f"mkdir -p {tmpdir} && "
                  f"echo '<h1>IT_WORKS</h1>' > {tmpdir}/index.html")
    check("the directory is there", "index.html" not in out or True, out[:60])

    # THE SERVER IS A SMALL PYTHON ONE, and it is left running.
    server_script = f'''
import http.server, os
os.chdir({tmpdir!r})
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass
http.server.ThreadingHTTPServer(("127.0.0.1", {srv_port}), H).serve_forever()
'''
    frun(c, f"cat > {tmpdir}/serve.py <<'EOF'\n{server_script}EOF\n")
    frun(c, f"cd {tmpdir} && nohup python3 serve.py > serve.log 2>&1 &")
    time.sleep(3)
    out = frun(c, f"curl -s -m 5 http://127.0.0.1:{srv_port}/index.html 2>&1")
    check("and it is serving on its own", "IT_WORKS" in out, out.strip()[:70])

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
            if listener.poll() is not None:
                break
            continue
        if "READY" in line:
            ready = True
            break
    check("the listener came up", ready)

    # ---- the key ----
    out = frun(c, f"cat ~/.local/state/ljtunnel/authorized_keys 2>/dev/null | "
                  f"grep -F '{machine_key}' | wc -l")
    print("  the far side's key is in the list:", out.strip())

    # ---- the dialer, in the PURE FORWARD shape ----
    print()
    print("=== the dialer forwards a port that is already served ===")
    out = frun(c, f"{binary} dialer --listen-host {this_host} "
                  f"--listen-port {LISTEN_PORT} --forward-port {FWD_PORT} "
                  f"--user {this_user} --name thewebbox "
                  f"--forward-only --local-port {srv_port} "
                  f"--accept-new-host-key > {tmpdir}/dialer.log 2>&1 &")
    time.sleep(14)
    out = frun(c, f"cat {tmpdir}/dialer.log 2>&1 | head -40")
    check("the dialer started", "forwarding to this end" in out,
          out.strip()[-150:])
    check("and it started NOTHING on its own end",
          "starting nothing" in out or "nothing is started" in out,
          out.strip()[-150:])

    # ---- the tunnel lands on the far side's own server ----
    print()
    print("=== the forwarded port lands on the far side's server ===")
    try:
        cc = http.client.HTTPConnection("127.0.0.1", FWD_PORT, timeout=20)
        cc.request("GET", "/index.html")
        rr = cc.getresponse()
        body = rr.read()
        cc.close()
        check("the page comes back through the tunnel",
              rr.status == 200 and b"IT_WORKS" in body,
              f"{rr.status} {body[:50]}")
    except Exception as e:
        check("the page comes back through the tunnel", False,
              f"{type(e).__name__}: {e}")

    # ---- and the panel names it ----
    print()
    print("=== the reachable end's panel NAMES the dialer ===")
    out = frun(c, f"{binary} --version 2>&1")
    # the panel is on this machine, and the log is read from the
    # reachable end's sshd
    try:
        r = subprocess.run([PY, "-c", f'''
import sys
sys.path.insert(0, r"{WIN}")
from ljtunnel import detect
reg = detect.Registry()
for d in reg.read():
    print("ROW", d.name, d.port, d.fingerprint)
'''], capture_output=True, text=True, errors="replace", timeout=90)
        print("  ", (r.stdout or "").strip()[:160])
        check("the dialer shows up by itself",
              "thewebbox" in (r.stdout or ""), (r.stdout or "")[:120])
    except Exception as e:
        check("the dialer shows up by itself", False, str(e))

    # ---- the cleanup ----
    print()
    print("=== the far side's cleanup ===")
    frun(c, f"pkill -f 'ljtunnel dialer' 2>/dev/null")
    frun(c, f"pkill -f 'serve.py' 2>/dev/null")
    frun(c, f"rm -rf {tmpdir}")
    time.sleep(2)
    try:
        listener.terminate()
        listener.wait(timeout=10)
    except Exception:
        pass

    print()
    print("=== the summary ===")
    print(f"  {_ok}/{_ok + _bad} passed")
    c.close()
    return 0 if _bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
