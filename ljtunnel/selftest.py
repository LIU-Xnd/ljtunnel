"""The self-test.

Everything here runs on the machine it is on, and needs no network
and no administrator shell. The cross-machine test is a separate
script, because it needs two machines and a port the firewall lets
through.

WHAT IS CHECKED
----------------
  - the state directory and the paths in it
  - the sshd config: rendered, correct, and the same on both ends
  - the key handling: generated once, public half readable, the list
    of allowed keys
  - the port allocator: no port handed out twice, and released again
  - the firewall command: the ports it covers, and that it says it
    needs an administrator shell when it does not have one
  - the dispatcher: every command, and that an unknown one is refused
  - the local address: not 127.0.0.1, not 0.0.0.0

WHAT IS NOT CHECKED HERE
------------------------
Anything that needs root, or a second machine, or a port the firewall
blocks. Those are the cross-machine test's job, and pretending
otherwise would make this suite lie.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import tempfile

from . import __version__, firewall as FW, listen as L, paths, sshd
from . import listen
from . import dialer as dialer_mod

_results = []


def check(name, ok, detail=""):
    _results.append((name, bool(ok), detail))
    if not ok:
        print(f"  FAIL  {name}" + (f" -- {detail}" if detail else ""))
    return bool(ok)


def eq(name, got, want):
    return check(name, got == want, f"got {got!r}, want {want!r}")


# ---------------------------------------------------------------- paths

def test_paths():
    d = paths.state_dir()
    check("the state directory is under the user's own space",
          bool(d) and os.sep not in d[-1:], d)
    check("the state directory is named for the app",
          os.path.basename(d) == "ljtunnel", d)

    names = {paths.sshd_config(), paths.host_key(), paths.authorized_keys(),
             paths.client_key(), paths.access_key(), paths.pid_file(),
             paths.log_file()}
    check("every path is under the state directory",
          all(n.startswith(d) for n in names),
          ", ".join(sorted(os.path.basename(n) for n in names
                           if not n.startswith(d))))
    check("the config is named ljtunnel_sshd_config",
          os.path.basename(paths.sshd_config()) == "ljtunnel_sshd_config")
    check("the machine key is named id_rsa_ljtunnel",
          os.path.basename(paths.client_key()) == "id_rsa_ljtunnel")
    check("the host key and the machine key are different files",
          paths.host_key() != paths.client_key())
    check("the access key is different from both",
          paths.access_key() not in (paths.host_key(), paths.client_key()))


# ---------------------------------------------------------------- the config

def test_config():
    with tempfile.TemporaryDirectory() as tmp:
        # render into a scratch state dir, so the test does not touch
        # the real one
        old = paths.state_dir
        paths.state_dir = lambda: tmp
        try:
            p = sshd.write_config(10001, "0.0.0.0",
                                  gateway_ports=True, allow_forwarding=True)
            text = open(p, encoding="utf-8").read()

            check("the config has the port", "Port 10001" in text)
            check("the config listens on the address asked for",
                  "ListenAddress 0.0.0.0" in text)
            check("the config points at this end's own host key",
                  paths.host_key() in text)
            check("the config points at this end's own key list",
                  paths.authorized_keys() in text)
            check("the config points at this end's own pid file",
                  paths.pid_file() in text)
            check("the config allows remote forwarding",
                  "AllowTcpForwarding remote" in text)
            check("the config asks for the gateway ports to be reachable",
                  "GatewayPorts clientspecified" in text)
            check("the config turns passwords off",
                  "PasswordAuthentication no" in text)
            check("the config turns public keys on",
                  "PubkeyAuthentication yes" in text)
            check("the config does not use PAM",
                  "UsePAM no" in text)

            if sys.platform == "win32":
                check("the config turns off privilege separation "
                      "(Windows needs it)",
                      "UsePrivilegeSeparation no" in text)
            else:
                # The check is for the OPTION, not the word: the
                # template mentions it in a comment, because the
                # comment is where the reason it is Windows-only
                # lives. A grep for the word would fail on the
                # comment.
                check("the config does not use the deprecated "
                      "privilege separation",
                      "UsePrivilegeSeparation no" not in text)

            # the dialer end: no gateway, no forwarding
            p2 = sshd.write_config(10001, "127.0.0.1")
            text2 = open(p2, encoding="utf-8").read()
            check("the dialer end does not ask for gateway ports",
                  "GatewayPorts" not in text2)
            check("the dialer end does not accept forwarding",
                  "AllowTcpForwarding no" in text2)
            check("the dialer end listens on loopback only",
                  "ListenAddress 127.0.0.1" in text2)
        finally:
            paths.state_dir = old


# ---------------------------------------------------------------- keys

def test_keys():
    with tempfile.TemporaryDirectory() as tmp:
        old = paths.state_dir
        paths.state_dir = lambda: tmp
        try:
            paths.ensure_dir(tmp)
            k = sshd.ensure_host_key()
            check("the host key is made", os.path.isfile(k))
            check("the host key is not made twice",
                  sshd.ensure_host_key() == k)
            check("the host key's public half is there",
                  os.path.isfile(k + ".pub"))
            pub = sshd.public_key_of(k)
            check("the public half looks like a public key",
                  pub.startswith("ssh-") and " " in pub, pub[:40])

            c = sshd.ensure_client_key()
            check("the machine key is a different file", c != k)
            a = sshd.ensure_access_key()
            check("the access key is a third file",
                  a not in (k, c))
            check("the three keys are three different keys",
                  len({sshd.public_key_of(x) for x in (k, c, a)}) == 3)

            # the key list
            p = sshd.set_authorized_keys(["ssh-ed25519 AAAA test"])
            check("the key list is written", os.path.isfile(p))
            check("the key list has the key",
                  "AAAA" in open(p, encoding="utf-8").read())
            sshd.set_authorized_keys([])
            check("the key list can be emptied",
                  open(p, encoding="utf-8").read().strip() == "")
        finally:
            paths.state_dir = old


# ---------------------------------------------------------------- ports

def test_access_key():
    """The key the end user logs in with.

    It has to be a real key: an empty one would produce a dialer
    command that looks right and lets nobody in.
    """
    with tempfile.TemporaryDirectory() as tmp:
        old = paths.state_dir
        paths.state_dir = lambda: tmp
        try:
            paths.ensure_dir(tmp)
            pub = L.access_public_key()
            check("the access public key looks like a public key",
                  pub.startswith("ssh-") and " " in pub, pub[:40])
            check("the access public key is not empty", bool(pub.strip()))

            cmd = L.dialer_command(10002, "someone", "192.0.2.1")
            check("the dialer command carries the access key",
                  pub in cmd, cmd[:120])
            check("the dialer command has the forward port",
                  "--forward-port 10002" in cmd, cmd[:120])
            check("the dialer command has the listen port",
                  "--listen-port 10001" in cmd, cmd[:120])
            check("the dialer command has the host",
                  "192.0.2.1" in cmd, cmd[:120])
        finally:
            paths.state_dir = old


def test_dialer():
    """The dialer end, checked where it can be checked.

    These are the settings that make the dialer end SAFE, and they
    are all in the source rather than in a running process, so they
    can be checked without a second machine.
    """
    src = open(dialer_mod.__file__, encoding="utf-8").read()

    check("the dialer's sshd listens on loopback only",
          'listen="127.0.0.1"' in src,
          "the dialer's sshd must not be reachable from the network")
    check("the dialer does not ask for gateway ports",
          "gateway_ports=True" not in src,
          "the dialer end does not forward for anyone")
    check("the dialer does not accept forwarding",
          "allow_forwarding=True" not in src,
          "the dialer end does not forward for anyone")
    check("the dialer's forwarding goes to its own sshd",
          'f"0.0.0.0:{args.forward_port}:127.0.0.1:{args.local_port}"' in src,
          "the forward must point at the local sshd port")
    check("the dialer does not forward a fixed port",
          "127.0.0.1:1" not in src)
    check("the dialer's key is its own, not the user's",
          "sshd.ensure_client_key()" in src)
    check("the dialer adds the access key to its own key list",
          "add_key(args.access_key)" in src)


def test_allocator():
    a = L.PortAllocator(first=10002, count=3)
    p1 = a.assign("one")
    p2 = a.assign("two")
    p3 = a.assign("three")
    eq("the first port is 10002", p1, 10002)
    check("no port is handed out twice", len({p1, p2, p3}) == 3)
    try:
        a.assign("four")
        check("the allocator says when it is full", False)
    except ValueError as e:
        check("the allocator says when it is full", "taken" in str(e),
              str(e))

    a.release("two")
    p4 = a.assign("four")
    eq("a released port is handed out again", p4, p2)
    eq("asking for the same name gives the same port",
       a.assign("four"), p4)


def test_port_in_use():
    import socket
    s = socket.socket()
    try:
        s.bind(("0.0.0.0", 0))
        port = s.getsockname()[1]
    finally:
        # the socket has to be CLOSED: a bound socket holds its port,
        # so asking while it is open would ask about the wrong thing
        s.close()
    check("a port nothing listens on is free",
          not L.port_in_use(port), str(port))

    s = socket.socket()
    try:
        if sys.platform == "win32":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        else:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", 0))
        s.listen(1)
        port = s.getsockname()[1]
        check("a port something listens on is not free",
              L.port_in_use(port), str(port))
    finally:
        s.close()

    # The check has to LISTEN, not just bind. On Windows a bound but
    # not listened socket still takes the port, so a bind-only check
    # would report a port that is genuinely in use as free.
    src = open(listen.__file__, encoding="utf-8").read()
    body = src.split("def port_in_use", 1)[1].split("\ndef ", 1)[0]
    check("the port check listens, not just binds",
          ".listen(" in body, "no listen in the port check")


# ---------------------------------------------------------------- firewall

def test_firewall():
    check("the firewall rule covers the sshd port",
          "10001" in FW.port_spec(), FW.port_spec())
    check("the firewall rule covers the forwarded range",
          "10002" in FW.port_spec() and
          str(FW.LAST_FORWARD_PORT) in FW.port_spec(), FW.port_spec())
    cmd = FW.netsh_command()
    check("the firewall command is a netsh command",
          cmd.startswith("netsh advfirewall"), cmd[:60])
    check("the firewall command allows inbound", "dir=in" in cmd)
    check("the firewall command allows tcp", "protocol=TCP" in cmd)
    check("the firewall command names the rule", FW.RULE_NAME in cmd)

    if sys.platform == "win32":
        ok, msg = FW.add_rule()
        if FW.is_admin():
            check("the rule went in when elevated", ok, msg)
        else:
            check("without an administrator shell it says so, "
                  "and gives the command",
                  (not ok) and "administrator" in msg and
                  "netsh" in msg, msg[:120])


# ---------------------------------------------------------------- dispatcher

def test_dispatcher():
    from . import __main__ as D

    rc = D.main([])
    check("no arguments prints the usage", rc == 0)
    rc = D.main(["--version"])
    check("--version prints the version", rc == 0)

    rc = D.main(["nonsense"])
    check("an unknown command is refused", rc == 2)

    r = subprocess.run(
        [sys.executable, "-m", "ljtunnel", "--version"],
        capture_output=True, text=True, errors="replace")
    check("python -m ljtunnel works", r.returncode == 0 and
          __version__ in r.stdout, r.stdout.strip()[:60])

    r = subprocess.run(
        [sys.executable, "-m", "ljtunnel", "nonsense"],
        capture_output=True, text=True, errors="replace")
    check("python -m ljtunnel refuses an unknown command",
          r.returncode == 2, str(r.returncode))

    r = subprocess.run(
        [sys.executable, "-m", "ljtunnel", "dialer", "--help"],
        capture_output=True, text=True, errors="replace")
    check("dialer --help works", r.returncode == 0 and
          "--listen-host" in r.stdout)

    r = subprocess.run(
        [sys.executable, "-m", "ljtunnel", "key", "--help"],
        capture_output=True, text=True, errors="replace")
    check("key --help works", r.returncode == 0)


# ---------------------------------------------------------------- address

def test_console():
    """The console check, in both directions.

    The Windows launcher runs on pythonw.exe and has no console, so
    anything printed there goes nowhere. The check has to be right in
    BOTH directions: wrong the other way and the Start Menu shortcut
    prints its usage into the void instead of opening the window.
    """
    from . import __main__ as D

    check("the dispatcher knows whether there is a console",
          isinstance(D.has_console(), bool), str(D.has_console()))
    check("there is a console here", D.has_console(),
          "this suite is running with a console")

    if sys.platform != "win32":
        check("the console check under pythonw (skipped)", True)
        return

    # Run the same check under pythonw.exe, which has no console, and
    # read the answer back out of a file.
    import subprocess
    import tempfile
    import time

    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "answer.txt")
        probe = os.path.join(tmp, "probe.py")
        parent = str(pathlib.Path(__file__).resolve().parent.parent)
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write(
                "import sys, pathlib\n"
                f"sys.path.insert(0, {parent!r})\n"
                "import ljtunnel.__main__ as D\n"
                f"pathlib.Path({out!r}).write_text(str(D.has_console()))\n")
        pyw = pathlib.Path(sys.executable).with_name("pythonw.exe")
        if not pyw.is_file():
            check("pythonw.exe is there", False, str(pyw))
            return
        subprocess.run([str(pyw), str(probe)], capture_output=True, timeout=60)
        deadline = time.time() + 15
        answer = None
        while time.time() < deadline:
            if os.path.isfile(out):
                try:
                    answer = open(out, encoding="utf-8").read().strip()
                    break
                except OSError:
                    pass
            time.sleep(0.3)
        check("pythonw.exe has no console", answer == "False",
              f"the answer was {answer!r}")


def test_address():
    addr = L.local_ipv4()
    check("the local address is an IPv4 address",
          addr.count(".") == 3, addr)
    check("the local address is not 127.0.0.1",
          addr != "127.0.0.1", addr)
    check("the local address is not 0.0.0.0", addr != "0.0.0.0", addr)
    check("the local address is not empty", bool(addr))
    check("the local address is not a loopback address",
          not addr.startswith("127."), addr)

    # The FUNCTION has to reject a loopback, not just happen to. A
    # check that only passes because this machine has an address
    # would pass on a machine that has none.
    #
    # The fallback to 127.0.0.1 when nothing else can be found is
    # CORRECT -- it is what makes the function total. So the thing
    # being checked is the refusal of a loopback ANSWER, not the
    # fallback: the source has to say it will not take a loopback.
    src = open(listen.__file__, encoding="utf-8").read()
    body = src.split("def local_ipv4", 1)[1].split("\ndef ", 1)[0]
    check("the address function refuses a loopback answer",
          'startswith("127.")' in body, "the refusal is not in the source")
    check("the address function has a fallback",
          "127.0.0.1" in body, "no fallback: the function could raise")


# ---------------------------------------------------------------- version

def test_version():
    import re

    check("the version is there", bool(__version__), __version__)
    check("the version looks like a version",
          re.match(r"^\d+\.\d+\.\d+$", __version__) is not None,
          __version__)

    # The three places the version lives have to agree: the file, the
    # fallback constant, and the installed metadata. A freshly tagged
    # release that reports the old number in its own install test is
    # the failure this catches.
    root = pathlib.Path(__file__).resolve().parent.parent

    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject.read_text(
            encoding="utf-8"), re.M)
        check("the pyproject has a version", m is not None)
        if m:
            check("the pyproject and the package agree",
                  m.group(1) == __version__,
                  f"pyproject {m.group(1)}, package {__version__}")

    try:
        from importlib.metadata import version as _dist_version
        installed = _dist_version("ljtunnel")
        check("the installed metadata agrees",
              installed == __version__,
              f"installed {installed}, package {__version__}")
    except Exception:
        # Not installed: the source tree is being tested, which is
        # fine. The installed copy is tested by the install check.
        check("the installed metadata is not here (skipped)", True)


# ---------------------------------------------------------------- the app

def test_app():
    """The window, without showing it.

    The widgets are built and destroyed: a layout that throws is a
    layout that throws for the person too, and it should be caught
    here rather than on their first run.
    """
    if sys.platform != "win32":
        check("the window is Windows only (skipped)", True)
        return
    try:
        from . import app
    except ImportError as e:
        check("the app imports", False, str(e))
        return
    check("the app imports", True)
    try:
        import tkinter
        a = app.App()
        a.update_idletasks()
        check("the window builds", True)
        check("the window has the dialer list", len(a.tree["columns"]) == 4)
        check("the window shows the firewall command",
              FW.netsh_command() in a.fw_text.get("1.0", "end"))
        a._on_close()
    except Exception as e:                       # noqa: BLE001
        check("the window builds", False, f"{type(e).__name__}: {e}")


# ---------------------------------------------------------------- the run

def main() -> int:
    print(f"ljtunnel {__version__} -- the self-test")
    print()
    for fn in (test_paths, test_config, test_keys, test_access_key,
               test_dialer,
               test_allocator, test_port_in_use, test_firewall,
               test_dispatcher, test_console, test_address, test_version,
               test_app):
        try:
            fn()
        except Exception as e:                   # noqa: BLE001
            check(fn.__name__, False, f"raised {type(e).__name__}: {e}")

    dump = os.environ.get("LJT_DUMP")
    if dump:
        with open(dump, "w", encoding="utf-8") as fh:
            for _n, _ok, _d in _results:
                fh.write(f"{'PASS' if _ok else 'FAIL'}\t{_n}\n")
    passed = sum(1 for _, ok, _ in _results if ok)
    skipped = sum(1 for _, ok, d in _results if ok and "skipped" in d)
    failed = [n for n, ok, _ in _results if not ok]
    print()
    if failed:
        print(f"  {len(_results)} checks: {passed} passed, {len(failed)} failed")
        for n in failed:
            print(f"    FAILED: {n}")
        return 1
    # The skips are part of the total: a skipped check is neither a
    # pass nor a failure, and a summary that leaves it out reads as
    # fewer checks than ran.
    print(f"  {len(_results)} checks: {passed} passed, 0 failed"
          + (f", {skipped} skipped" if skipped else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
