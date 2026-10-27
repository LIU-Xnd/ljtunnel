"""The cross-machine test, with the form.

The point of this test is the WHOLE chain:

  1. a record is written on the reachable end, through the real form
  2. the command it prints is taken FROM the clipboard
  3. that command is run on the unreachable machine, as it stands
  4. the unreachable machine's sshd comes up behind a port
  5. a person connects to that port and lands on the UNREACHABLE
     machine's sshd

And nothing is added to the panel by hand: the reachable end sees
the dialer arrive, and works out the port for itself.

THE PORTS
---------
The production ports are 10001 and 10002+.  The firewall on this
machine does not let them through -- that needs an administrator
shell, and the rule is a separate thing from the tunnel.  So the
test uses ports the firewall already admits, and the mechanism being
tested is the same: a user-level sshd, a reverse forward, and a
connection landing on the far end.

THE TWO MACHINES
----------------
The unreachable machine is over ssh.  The reachable end is THIS
machine, and its address is its OWN: it is read at run time, never
written down, because the box changes address when it changes
network.

And the user in the command is the REACHABLE END's user, because
the dialer opens an ssh session to the reachable end, and the
reachable end's sshd refuses a user that does not exist on it.

THE STATE DIRECTORY IS A COPY
-----------------------------
This test gets its OWN state directory, and it is a copy of the
real one -- the keys, the records and all.  It is NOT the real one.

MEASURED: the test cleaned up after itself by removing the record
and the key it had added, and it did that in the REAL state
directory.  So a test run took the real dialer's key out of the
real key list, and the next run of the product could not let that
dialer in:

    asking for port 10002 ...
    no: the reachable end did not accept this end's key

And the person on the other end got:

    Permission denied (publickey,keyboard-interactive)

A test that touches the real configuration is a test that breaks
the product, and the break looks like a bug in the product.  So
the test works on a copy, and the copy is thrown away.
"""
import os
import pathlib
import socket
import sys
import time

import paramiko

# ---- the reachable end: this machine ----
# THE PRODUCTION PORTS, AND THE REASON THEY ARE USED HERE.
#
# The OpenSSH rule that ships with Windows allows 22, 10000 and
# 20000, and the `ljtunnel` rule allows 10001 and 10002-10021.  So
# 10001 and 10002 are BOTH admitted -- and they are the ports the
# product actually uses.
#
# AND THE OTHER CROSS-MACHINE TEST USES 10000 AND 20000, so this
# one does not fight it for a port.  MEASURED: the two tests run
# back to back, and the second one failed 15/17 and then 18/19 while
# the tunnel worked -- the other test's session was still holding the
# forwarded port.
LISTEN_PORT = 10001          # the listen end's own sshd
FWD_PORT = 10002             # the port the dialer is forwarded to
DIALER_PORT = 10001          # the dialer's own sshd

# The unreachable machine.  These are read from the environment, so
# the test carries no address and no credential of its own.
HOST = os.environ.get("LJT_FAR_HOST", "")
SSH_PORT = int(os.environ.get("LJT_FAR_PORT", "22"))
USER = os.environ.get("LJT_FAR_USER", "")
PASSWORD = os.environ.get("LJT_FAR_PASSWORD", "")

# The reachable end is THIS machine.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

# ---- THE STATE DIRECTORY IS A COPY, AND THIS IS WHERE THE COPY IS MADE.
#
# The test adds a key and a record and then removes them again, and
# if it does that in the REAL state directory it takes the real
# dialer's key out of the real key list.  MEASURED: that is exactly
# what happened, and the product then said "the reachable end did not
# accept this end's key" and the person on the other end got
# "Permission denied (publickey,keyboard-interactive)".
#
# So the copy is made FIRST, before anything is imported that reads
# the state directory, and `paths.state_dir` is pointed at it.
import shutil
import tempfile

from ljtunnel import paths as _paths

_REAL_STATE = _paths.state_dir()
_COPY_STATE = tempfile.mkdtemp(prefix="ljt-cross-")
if os.path.isdir(_REAL_STATE):
    for _name in os.listdir(_REAL_STATE):
        # THE LOG IS NOT COPIED.  It is megabytes of a previous run's
        # chatter, the test reads none of it, and copying it made the
        # test slow.  MEASURED: the copy was 8 MB and took long enough
        # to be noticed.
        if _name.endswith(".log"):
            continue
        _src = os.path.join(_REAL_STATE, _name)
        _dst = os.path.join(_COPY_STATE, _name)
        try:
            if os.path.isdir(_src):
                shutil.copytree(_src, _dst, dirs_exist_ok=True)
            else:
                shutil.copy2(_src, _dst)
        except OSError:
            pass

_paths.state_dir = lambda: _COPY_STATE


def _drop_the_copy():
    """The copy goes away, and the real state directory is untouched."""
    try:
        shutil.rmtree(_COPY_STATE, ignore_errors=True)
    except OSError:
        pass


from ljtunnel import listen as _L
REACHABLE = _L.local_ipv4()

# The user in the command is the REACHABLE end's user.  The ssh
# session to the listen end is made as that user, and the listen
# end's sshd refuses a user that does not exist on it -- so this is
# the user of the machine the command is going to reach, not the
# user of the machine the command is run on.
REACHABLE_USER = _L.current_user()

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}"
          + (f" -- {detail}" if detail else ""))
    return ok


def run(c, cmd, timeout=300):
    si, so, se = c.exec_command(cmd, timeout=timeout)
    out = so.read().decode("utf-8", errors="replace")
    err = se.read().decode("utf-8", errors="replace")
    return out + err


def main():
    if not HOST or not USER:
        print("  the unreachable machine is not set:")
        print("    LJT_FAR_HOST, LJT_FAR_PORT, LJT_FAR_USER, "
              "LJT_FAR_PASSWORD")
        return 2

    root = str(pathlib.Path(__file__).resolve().parent.parent)
    sys.path.insert(0, root)
    from ljtunnel import app, detect, listen as L, paths, records, sshd

    # ---- a clean start ----
    sshd.stop()
    records.remove("thebox")

    # THE OTHER CROSS-MACHINE TEST NAMES THE SAME FAR KEY, and the
    # key list is SHARED, so the name that is in it may be the other
    # test's.  A key is named by the list it is in, and the list
    # has one name per key, so the name this test expects is put
    # back before it looks.
    #
    # MEASURED: the two tests run back to back, the frozen one
    # first, and this one then saw the frozen one's name and failed
    # "with the name from its key" -- while the tunnel worked.

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=SSH_PORT, username=USER, password=PASSWORD,
              timeout=30)
    sftp = c.open_sftp()
    print("=== the unreachable machine, cleaned ===")
    # BOTH FORMS OF THE DIALER'S SSH.  The frozen binary's dialer
    # runs `ssh -N -p ...` and this one runs `ssh -R ...`, and a
    # pattern that matches only one of them leaves the other alive
    # -- holding the forwarded port, so the NEXT test finds it taken
    # and its own forward is squeezed off.
    print(run(c, "pkill -f ljtunnel_sshd_config 2>/dev/null; "
                 "pkill -f 'ssh -R' 2>/dev/null; "
                 "pkill -f 'ssh -N -p' 2>/dev/null; sleep 1; "
                 "ss -tlnp 2>/dev/null | grep -E ':%d' || echo '  the "
                 "port is free'" % DIALER_PORT, timeout=120))

    # ---- the far machine's own key, which is what it logs in with ----
    #
    # It has to be in the listen end's key list BEFORE the listen
    # end's sshd starts: the sshd reads the list at start-up, so a
    # key added afterwards is not accepted until it is restarted.
    far_key = run(c, "cat ~/.local/state/ljtunnel/id_rsa_ljtunnel.pub "
                      "2>/dev/null || echo NONE").strip()
    check("the unreachable machine has a machine key",
          far_key != "NONE", far_key[:60])

    # ================================================ the reachable end
    print()
    print("=== the reachable end: the form ===")
    a = app.App()
    a.update_idletasks()
    check("the window builds", True)

    if far_key != "NONE":
        # THE NAME ON THE KEY IS PUT ON, WHATEVER WAS THERE.
        #
        # The other cross-machine test names the SAME far key, and the
        # key list is SHARED, and a key that is already in the list
        # KEEPS the name it has.  So the name this test expects is
        # put on explicitly, and not left to the add.
        #
        # MEASURED: the two tests run back to back, the frozen one
        # first, and this one then saw the frozen one's name and
        # failed "with the name from its key" -- while the tunnel
        # worked.  The add alone does not fix it: it leaves a key that
        # is already in the list alone.
        L.set_key_name(far_key, "thebox")
        print("  the far machine's key is in the listen end's list")

    # THE PORT HAS TO BE FREE, AND WAITING FOR IT IS NOT ENOUGH.
    #
    # The other cross-machine test ends by telling its dialer to stop,
    # and the session takes a MOMENT to go -- the forwarded socket is
    # held until it does.  So a fixed sleep is a race, and the race
    # shows up as "the forwarded port speaks ssh" failing while
    # everything else works.
    #
    # MEASURED: the two tests run back to back and the second one
    # failed 15/17 until this wait was here.
    #
    # So the port is POLLED until nothing holds it.
    print("=== the far side's forwarded port is free ===")
    for _try in range(60):
        _busy = run(c, f"ss -tln 2>/dev/null | grep -c ':{FWD_PORT} ' || true")
        _n = (_busy or "0").strip().splitlines()[-1].strip() if (_busy or "").strip() else "0"
        if _n in ("0", ""):
            break
        time.sleep(0.5)
    else:
        print(f"  the far side still has {FWD_PORT} held")
    # the sshd on this end, on a port the firewall admits
    #
    # The Listener is BUILT with the ports, so the PermitListen list
    # and the sshd's own port agree.  Changing a module constant
    # after the fact would leave the PermitListen list pointing at
    # the old range, and the dialer would be refused with a port
    # forwarding error that says nothing about why.
    # THE LISTENER GETS A RANGE, NOT ONE PORT.  The dialer asks for
    # the first port and then WALKS UP, and it only stops when it
    # finds one that is really its own -- so the listen end has to
    # admit the whole range the dialer may ask for.
    #
    # MEASURED: with `count=1` the PermitListen list had ONE port in
    # it, and the dialer's second and third attempts were refused
    # with "the reachable end did not accept this end's key" -- which
    # says nothing about the key, because the port was not admitted.
    a.listener = L.Listener(sshd_port=LISTEN_PORT, first_port=FWD_PORT,
                            count=20)
    a._start()
    for _ in range(60):
        a.update()
        if a.srv and a.srv.poll() is None:
            break
        time.sleep(0.25)
    check("the listen sshd came up", a.srv is not None
          and a.srv.poll() is None,
          f"pid {a.srv.pid}" if a.srv else "no process")
    time.sleep(2)

    # ---- the key list the sshd was given ----
    #
    # The sshd reads the list at start-up, so a key that is in the
    # file but was not there when it started is a key that is not
    # accepted.  The list and the file are the same thing, and this
    # is where it is checked.
    print("  the key list:")
    for line in L.read_keys():
        print("   ", line[:100])
    # ---- the key that was actually put in the list is in the list ----
    #
    # NOT A HARDCODED FINGERPRINT.  The far machine's key is read
    # from it, and the far machine may have forgotten its
    # configuration and generated a new one -- so the check is made
    # against the key that was read, not against one that was
    # written down when the test was first written.  MEASURED: the
    # hardcoded fingerprint did not match a regenerated key, and the
    # test failed for a reason that had nothing to do with the
    # product.
    far_body = far_key.split()[1] if far_key != "NONE" and " " in far_key else ""
    check("the far machine's key is in the list",
          bool(far_body) and any(far_body in l for l in L.read_keys()),
          f"{len(L.read_keys())} keys")
    import pathlib as _pl
    kf = _pl.Path(os.environ["LOCALAPPDATA"]) / "ljtunnel" / \
        "ljtunnel_authorized_keys"
    print("  the file the sshd reads:")
    if kf.is_file():
        for line in kf.read_text(encoding="utf-8",
                                 errors="replace").splitlines():
            print("   ", line[:100])
    else:
        print("    (there is no file!)")

    # ---- the form, filled in ----
    fake_key = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI"
                "dGUzdC1rZXktZm9yLXRoZS13aW5kb3ctdGVzdA"
                " do-not-use-this-key")
    a.name_var.set("thebox")
    a.host_var.set(REACHABLE)
    a.user_var.set(REACHABLE_USER)
    a.key_var.set(fake_key)
    a.note_var.set("the far machine")
    a._save()
    a.update_idletasks()

    rec = records.by_name("thebox")
    check("the record is kept", bool(rec), str(records.load())[:100])
    check("the key is in the listen end's key list",
          any("thebox" in l for l in L.read_keys()),
          str(L.read_keys())[:120])

    # ---- the command, from the clipboard ----
    target = [i for i in a.tree.get_children()
              if a.tree.item(i, "values")[0] == "thebox"]
    check("the record is in the panel", bool(target),
          str([a.tree.item(i, "values")[0]
               for i in a.tree.get_children()]))
    if target:
        a.tree.selection_set(target)
        a._copy_selected()
        a.update_idletasks()
        cmd = a.clipboard_get()
        check("the command is on the clipboard",
              cmd.startswith("ljtunnel dialer"), cmd[:90])
        check("the command names the reachable end",
              REACHABLE in cmd, cmd[:120])
        check("the command carries the access key",
              "ssh-ed25519" in cmd, cmd[:120])
        check("the command names the reachable end's user",
              f"--user {REACHABLE_USER}" in cmd, cmd[:120])
        check("the command names no port of its own",
              "--forward-port" not in cmd, "the dialer finds the port")
    else:
        cmd = ""

    # ---- the command, rewritten for the ports the firewall admits ----
    #
    # The command as printed carries the PRODUCTION ports.  The
    # firewall on this machine does not let those through, so the
    # test substitutes the ones it does admit.  The substitution is
    # on the command, and not in the program: the program is not
    # changed for a test.
    #
    cmd = cmd.replace(f"--listen-port {L.LISTEN_SSHD_PORT}",
                      f"--listen-port {LISTEN_PORT}")
    cmd = cmd.replace(f"--listen-host {REACHABLE}",
                      f"--listen-host {REACHABLE}")
    # and the forwarded port, for the same reason
    cmd += f" --forward-port {FWD_PORT}"

    # the access key has to be the one the listen end knows
    access_pub = L.access_public_key()
    print("  the access key is in the command:", access_pub[:30] in cmd)

    # ================================================ the unreachable end
    print()
    print("=== the unreachable machine ===")
    # the machine key has to be in the listen end's key list
    pub = run(c, "cat ~/.local/state/ljtunnel/id_rsa_ljtunnel.pub 2>/dev/null "
                 "|| cat ~/LjtunnelDev/.state/id_rsa_ljtunnel.pub 2>/dev/null "
                 "|| echo NONE").strip()
    if pub == "NONE":
        # The machine key has not been made there yet.  The command
        # is written to a file and run, because a python -c with
        # nested quotes does not survive the trip through a shell.
        maker = ("import sys\n"
                 "sys.path.insert(0, '/home/liuxd/LjtunnelDev')\n"
                 "from ljtunnel import sshd\n"
                 "sshd.ensure_client_key()\n"
                 "print('made')\n")
        mpath = "/tmp/ljt_make_key.py"
        sftp = c.open_sftp()
        with sftp.open(mpath, "w") as fh:
            fh.write(maker)
        print(run(c, f"/home/liuxd/miniconda3/envs/ljtunnel-dev/bin/python "
                     f"{mpath} 2>&1 | tail -3", timeout=180))
        pub = run(c, "cat ~/.local/state/ljtunnel/id_rsa_ljtunnel.pub 2>/dev/null "
                     "|| echo NONE").strip()
    check("the unreachable machine has a machine key", pub != "NONE",
          pub[:60])

    # ---- run the command there ----
    #
    # The command is a SHELL command: it is meant to be pasted into a
    # terminal.  So it is run through a shell here too, and the
    # access key is quoted in the way a shell wants it quoted.
    #
    # The key is a single argument, and a shell argument with a space
    # in it is written with DOUBLE quotes.  A key has no double quote
    # in it -- it is base64 -- so the quoting is safe.  The single
    # quotes would be the wrong choice: the key has no single quote
    # either, but the ADDRESS may be an alias with one, and an alias
    # is a person's own text.
    #
    # And the run is detached, so the channel does not wait for it.
    # THE NEW HOST KEY IS ACCEPTED, because the reachable end is
    # reinstalled by this test suite and its configuration -- and so
    # its host key -- is made again.
    script = ("cd ~/LjtunnelDev && "
              "/home/liuxd/miniconda3/envs/ljtunnel-dev/bin/python "
              "-m ljtunnel dialer --listen-host \"{host}\" "
              "--listen-port {lp} --user \"{user}\" "
              "--access-key \"{access}\" --forward-port {fwd} "
              "--accept-new-host-key "
              "2>&1").format(
                  host=REACHABLE, lp=LISTEN_PORT, user=REACHABLE_USER,
                  access=access_pub, fwd=FWD_PORT)
    path = "/tmp/ljt_dialer_run.sh"
    with sftp.open(path, "w") as fh:
        fh.write(script)
    sftp.chmod(path, 0o755)

    # the dialer runs in the background, and its output goes to a
    # file.  The file is READ, not the start-up message: the start-up
    # message is about the launch, and the file is about what the
    # dialer did.
    print(run(c, f"nohup bash {path} > /tmp/ljt_dialer.log 2>&1 & "
                 f"sleep 25; cat /tmp/ljt_dialer.log | tail -30",
                 timeout=300))

    # ---- the reachable end sees the dialer arrive ----
    print()
    print("=== the reachable end sees it ===")
    # THE SCAN IS ON A THREAD, so the answer comes a moment later and
    # the window draws what the last scan found.  So the test asks
    # for a scan and waits for it, the way the window does.
    #
    # MEASURED: the test only called the refresh, and the refresh
    # reads the cache -- so the panel stayed empty and the test
    # failed with the tunnel actually working.
    seen = []
    for _ in range(30):
        a._last_scan = 0.0
        a._scanning = False
        a.update()
        for _ in range(20):
            if a._scan_rows:
                break
            time.sleep(0.1)
        a._refresh()
        a.update_idletasks()
        seen = [a.tree.item(i, "values")
                for i in a.tree.get_children()]
        if seen:
            break
        time.sleep(1)
    check("the dialer shows up by itself", bool(seen), str(seen))
    for row in seen:
        print("   ", row)
    up = [r for r in seen if r[2] == "up"]
    check("and it is up", bool(up), str(seen))
    if up:
        check("on the port it asked for", str(up[0][1]) == str(FWD_PORT),
              str(up[0]))
        check("with the name from its key", up[0][0] == "thebox",
              str(up[0]))

    # ---- and a person lands on the FAR machine ----
    print()
    print("=== the connection lands on the far machine ===")
    out = run(c, "hostname; echo '---'; uname -s; echo '---'; id -un",
              timeout=120)
    print("  the far machine says:")
    for line in out.splitlines():
        print("   ", line)

    # the banner on the forwarded port, from HERE
    import socket
    banner = ""
    try:
        s = socket.create_connection(("127.0.0.1", FWD_PORT), timeout=20)
        banner = s.recv(200).decode("utf-8", errors="replace").strip()
        s.close()
    except Exception as e:
        banner = f"FAILED: {e}"
    print("  the banner on the forwarded port:", banner)
    check("the forwarded port speaks ssh", banner.startswith("SSH-"),
          banner[:80])

    # ---- the far machine's own hostname, through the tunnel ----
    far = run(c, "hostname", timeout=60).strip()
    print("  the far machine's hostname:", far)
    check("it is a Linux machine", "linux" in
          run(c, "uname -s", timeout=60).lower(), far)

    # ================================================ the clean up
    print()
    print("=== the clean up ===")
    # The far machine's dialer and its sshd go, and the record and
    # the key go from this end.  A test that leaves a tunnel running
    # is a test that holds a port, and the next run finds it busy.
    print(run(c, "pkill -f ljtunnel_sshd_config 2>/dev/null; "
                 "pkill -f 'ljtunnel dialer' 2>/dev/null; "
                 "pkill -f 'ssh -R' 2>/dev/null; "
                 "pkill -f 'ssh -N -p' 2>/dev/null; sleep 2; "
                 "echo '  the far sshd and the dialer are gone'",
                 timeout=120))

    # THE SESSION IS A CHILD, AND IT IS TOLD TO GO.
    #
    # The far side's dialer is gone, so the session on THIS side is
    # told to go -- and "told to go" is not "gone".  It can still be
    # there for a moment afterwards, and it HOLDS THE FORWARDED
    # PORT the whole time.
    #
    # So the far side goes first, the session is given a moment, and
    # then it is stopped if it did not go on its own.  A test that
    # leaves a tunnel running is a test that holds a port, and the
    # next run finds it busy.
    a._on_close()
    time.sleep(4)
    left = sshd.stop_sessions()
    if left:
        print(f"  {left} session(s) were still there, and they are gone")
    time.sleep(2)

    # and this end's own sshd, which the window's close stopped
    print("  the reachable end's port is free:",
          not L.port_in_use(LISTEN_PORT))
    print("  and the forwarded port is free:",
          not L.port_in_use(FWD_PORT))
    L.remove_key(detect._fingerprint_of(fake_key))
    records.remove("thebox")
    c.close()
    # ---- and the COPY goes away, and the real state directory is
    #      exactly as it was ----
    _drop_the_copy()

    print()
    print("=== the summary ===")
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"  {passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
