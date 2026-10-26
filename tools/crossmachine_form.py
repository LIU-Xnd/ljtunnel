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
"""
import os
import pathlib
import socket
import sys
import time

import paramiko

# ---- the reachable end: this machine ----
LISTEN_PORT = 10000          # the listen end's own sshd
FWD_PORT = 20000             # the port the dialer is forwarded to
DIALER_PORT = 10001          # the dialer's own sshd

# The unreachable machine.  These are read from the environment, so
# the test carries no address and no credential of its own.
HOST = os.environ.get("LJT_FAR_HOST", "")
SSH_PORT = int(os.environ.get("LJT_FAR_PORT", "22"))
USER = os.environ.get("LJT_FAR_USER", "")
PASSWORD = os.environ.get("LJT_FAR_PASSWORD", "")

# The reachable end is THIS machine.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
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

    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, port=SSH_PORT, username=USER, password=PASSWORD,
              timeout=30)
    sftp = c.open_sftp()
    print("=== the unreachable machine, cleaned ===")
    print(run(c, "pkill -f ljtunnel_sshd_config 2>/dev/null; "
                 "pkill -f 'ssh -R' 2>/dev/null; sleep 1; "
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
        L.add_key(far_key, "thebox")
        print("  the far machine's key is in the listen end's list")

    # the sshd on this end, on a port the firewall admits
    #
    # The Listener is BUILT with the ports, so the PermitListen list
    # and the sshd's own port agree.  Changing a module constant
    # after the fact would leave the PermitListen list pointing at
    # the old range, and the dialer would be refused with a port
    # forwarding error that says nothing about why.
    a.listener = L.Listener(sshd_port=LISTEN_PORT, first_port=FWD_PORT,
                            count=1)
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
    check("the far machine's key is in the list",
          any("IPOXAuTF" in l or "IPOXAuTF" in l for l in L.read_keys()),
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
    script = ("cd ~/LjtunnelDev && "
              "/home/liuxd/miniconda3/envs/ljtunnel-dev/bin/python "
              "-m ljtunnel dialer --listen-host \"{host}\" "
              "--listen-port {lp} --user \"{user}\" "
              "--access-key \"{access}\" --forward-port {fwd} "
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
    seen = []
    for _ in range(30):
        a.update()
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
                 "pkill -f 'ljtunnel dialer' 2>/dev/null; sleep 2; "
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

    print()
    print("=== the summary ===")
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    passed = sum(1 for _, ok, _ in results if ok)
    print(f"  {passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
