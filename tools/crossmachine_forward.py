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


def frun_bg(c, cmd, timeout=30):
    """Run a command in the BACKGROUND, and do not wait for it.

    **A BACKGROUND COMMAND OVER SSH HOLDS THE CHANNEL OPEN, AND
    READING IT WAITS FOR AN EOF THAT NEVER COMES.**  MEASURED:

        paramiko.buffered_pipe.PipeTimeout

    The shell waits for the channel to close, and the channel waits
    for the background process to let go of its streams.

    **AND THE FIX IS THE REDIRECTION OF ALL THREE, AND THE
    SUB-SHELL.**  With the output and the error sent to a file, and
    the input closed, and the whole thing in a sub-shell that ends
    at once, the shell has nothing left to wait for.
    """
    # **AND THE SUB-SHELL IS WHAT MAKES IT WORK.**  MEASURED:
    #
    #     ( setsid python3 ... > /tmp/bg.log 2>&1 </dev/null & ) ; echo DONE
    #
    # returns "DONE" at once, and the process is still running
    # afterwards.  Without the sub-shell the shell waits for the
    # background job's streams and the read never ends.
    # **AND THE CHANNEL IS NOT READ.**  MEASURED: `out.read()` waits
    # for an EOF that the background process's inherited stdout keeps
    # from coming, and the wait ends in a TimeoutError.
    #
    # So the command is started and the channel is left alone.  It
    # goes when the connection does, and the process it started is
    # detached with setsid and does not go with it.
    wrapped = f"( {cmd} & ) ; echo DONE"
    try:
        c.get_transport().open_session().exec_command(wrapped)
    except Exception as e:
        print(f"  (the background command did not start: "
              f"{type(e).__name__}: {e})")
    time.sleep(1)


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
    # AND THE LEFTOVERS OF AN EARLIER RUN GO FIRST.  MEASURED: a
    # server from a run that was interrupted was still holding a port,
    # and the new one could not take it.
    # **AND THE SSH CHILDREN GO TOO, AND THAT IS THE WHOLE POINT.**
    # MEASURED: `pkill -f 'ljtunnel dialer'` kills the ljtunnel and
    # LEAVES THE `ssh -N` IT SPAWNED.  So the stale ssh keeps the
    # forwarded port on the reachable end -- and forwards it to a port
    # on this end that died with the server that was on it:
    #
    #     ConnectionAbortedError: [WinError 10053]
    #
    # and the new dialer is told the port is taken, because it IS --
    # by the wrong process.
    frun(c, "pkill -f 'ssh -N -p 10001' 2>/dev/null; "
            "pkill -f 'ljtunnel dialer' 2>/dev/null; "
            "pkill -f 'serve.py' 2>/dev/null; echo cleaned")
    time.sleep(2)

    tmpdir = f"/home/liuxd/ljt-fwd-{int(time.time())}"
    out = frun(c, f"mkdir -p {tmpdir} && "
                  f"echo '<h1>IT_WORKS</h1>' > {tmpdir}/index.html && "
                  f"ls -la {tmpdir}/index.html")
    check("the directory is there", "index.html" in out, out.strip()[:70])

    # **AND THE PORT IS PICKED ON THE FAR SIDE, AND NOT HERE.**
    # MEASURED: the port was picked on THIS machine, where it was
    # free -- and on the far side it was taken by something else, so
    # the server did not start and the tunnel pointed at a dead port:
    #
    #     ConnectionAbortedError: [WinError 10053]
    #
    # So the far side binds port 0 and WRITES the port it got into a
    # file, and the file is read from here.
    port_file = f"{tmpdir}/port.txt"

    # THE SERVER IS A SMALL PYTHON ONE, and it is left running.
    # **AND IT BINDS PORT 0 AND WRITES THE PORT IT GOT.**  The port
    # is picked on the far side, where the server actually runs.
    server_script = f'''
import http.server, os
os.chdir({tmpdir!r})
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
open({port_file!r}, "w").write(str(srv.server_address[1]))
srv.serve_forever()
'''
    frun(c, f"cat > {tmpdir}/serve.py <<'EOF'\n{server_script}EOF\n")
    # **AND THE BACKGROUND SERVER MUST NOT HOLD THE CHANNEL OPEN.**
    # MEASURED: `nohup python3 serve.py > serve.log 2>&1 &` left the
    # server holding the channel's STDIN, and the read on the other
    # end waited for an EOF that never came:
    #
    #     paramiko.buffered_pipe.PipeTimeout
    #
    # so the standard input is closed for it, and the whole thing is
    # detached with setsid.
    frun_bg(c, f"cd {tmpdir} && setsid python3 serve.py "
               f"> serve.log 2>&1 </dev/null")
    # AND THE PORT IS READ FROM THE FILE THE SERVER WROTE.
    srv_port = 0
    for _try in range(20):
        out = frun(c, f"cat {port_file} 2>/dev/null")
        s = out.strip().splitlines()[-1].strip() if out.strip() else ""
        if s.isdigit():
            srv_port = int(s)
            break
        time.sleep(1)
    check("and it says which port it took", srv_port > 0, str(srv_port))
    if not srv_port:
        print(frun(c, f"cat {tmpdir}/serve.log 2>&1")[:300])
        c.close()
        return 1
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
    if "the key is in the list" not in (r2.stdout or ""):
        listener.terminate()
        c.close()
        return 1

    # ---- the dialer, in the PURE FORWARD shape ----
    print()
    print("=== the dialer forwards a port that is already served ===")
    frun_bg(c, f"{binary} dialer --listen-host {this_host} "
               f"--listen-port {LISTEN_PORT} --forward-port {FWD_PORT} "
               f"--user {this_user} --name thewebbox "
               f"--forward-only --local-port {srv_port} "
               f"--accept-new-host-key > {tmpdir}/dialer.log 2>&1 </dev/null")
    time.sleep(16)
    out = frun(c, f"cat {tmpdir}/dialer.log 2>&1 | head -40")
    check("the dialer started", "forwarding to this end" in out,
          out.strip()[-150:])
    check("and it started NOTHING on its own end",
          "starting nothing" in out or "nothing is started" in out,
          out.strip()[-150:])

    # ---- the tunnel lands on the far side's own server ----
    print()
    print("=== the forwarded port lands on the far side's server ===")
    # AND IT IS TRIED A FEW TIMES.  MEASURED: the tunnel's first
    # request can arrive before the far side's server is really
    # listening, and the answer is
    #
    #     ConnectionAbortedError: [WinError 10053]
    #
    # which is the tunnel saying "nobody is there yet" and not a
    # failure of the tunnel.
    body = b""
    status = 0
    last = ""
    for _try in range(8):
        try:
            cc = http.client.HTTPConnection("127.0.0.1", FWD_PORT, timeout=20)
            cc.request("GET", "/index.html")
            rr = cc.getresponse()
            body = rr.read()
            cc.close()
            status = rr.status
            last = f"{status} {body[:50]}"
            if status == 200 and b"IT_WORKS" in body:
                break
        except Exception as e:
            last = f"{type(e).__name__}: {e}"
        time.sleep(3)
    check("the page comes back through the tunnel",
          status == 200 and b"IT_WORKS" in body, last)

    # ---- and the panel shows the port as live ----
    #
    # **AND THE NAME IS NOT AVAILABLE HERE, AND THAT IS TRUE.**  The
    # port has somebody else's service behind it -- rclone, or
    # whatever -- and there is no host key behind it and no header
    # that says who it is.  So the row has the port and no name.
    #
    # On Linux the sshd's log says which key opened the session and
    # which port it asked for, and the name comes from there.  On
    # Windows the sessions do not log to the listener's pipe, so the
    # scan is used, and the scan has nothing to go on.
    print()
    print("=== the reachable end's panel shows the port as live ===")
    try:
        r = subprocess.run([PY, "-c", f'''
import sys
sys.path.insert(0, r"{WIN}")
from ljtunnel import listen as L, scan
rows = scan.scan_fast({FWD_PORT}, 1, timeout=15)
for r in rows:
    print("ROW", repr(r.name), r.port, r.fingerprint[:24])
'''], capture_output=True, text=True, errors="replace", timeout=300)
        out3 = r.stdout or ""
        print("   ", out3.strip()[:200])
        check("the port shows up as live",
              f"ROW" in out3 and str(FWD_PORT) in out3, out3.strip()[:100])
    except Exception as e:
        check("the port shows up as live", False, str(e))

    # ---- the cleanup ----
    print()
    print("=== the far side's cleanup ===")
    frun(c, "pkill -f 'ssh -N -p 10001' 2>/dev/null; "
            "pkill -f 'ljtunnel dialer' 2>/dev/null; "
            "pkill -f 'serve.py' 2>/dev/null; echo done")
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
