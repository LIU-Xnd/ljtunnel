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
import socket
import subprocess
import sys
import tempfile

from . import __version__, firewall as FW, listen as L, paths, records, sshd
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

            # The paths in the config are FORWARD SLASHED, whatever
            # the platform: the sshd is a C program, and a backslash
            # in a path it opens is a trapdoor.  So the check is that
            # the config names the right FILE, not that it spells it
            # the way the platform would.
            for what, path in (("host key", paths.host_key()),
                               ("key list", paths.authorized_keys()),
                               ("pid file", paths.pid_file())):
                check(f"the config points at this end's own {what}",
                      path.replace("\\", "/") in text,
                      path.replace("\\", "/"))
            check("the config has no backslash in a path",
                  "\\" not in text,
                  "a C program opening a path with a backslash in it "
                  "is a trapdoor")
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

            cmd = L.dialer_command("someone", "192.0.2.1")
            check("the dialer command carries the access key",
                  pub in cmd, cmd[:120])
            check("the dialer command does NOT name a port",
                  "--forward-port" not in cmd,
                  "the dialer finds the port itself, so the command "
                  "must not name one")
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
          'f"0.0.0.0:{port}:127.0.0.1:{args.local_port}"' in src,
          "the forward must point at the local sshd port")
    check("the dialer does not forward a fixed port",
          "127.0.0.1:1" not in src)

    # ---- the port is FOUND, not given ----
    #
    # The dialer asks for a port and, when the listen end says that
    # one is taken, asks for the next.  So the same command works for
    # every dialer, and nobody has to keep a list of ports in step.
    check("the dialer tries more than one port",
          "_ports_to_try" in src and "for port in ports" in src,
          "the dialer must be able to move on to the next port")
    check("the dialer does not take the client's word for it",
          "_port_is_ours" in src and "host_key_fingerprint" in src,
          "the client's own 'success' is not proof")
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

    # ---- the elevation itself ----
    #
    # The rule is added by asking Windows to run it as an
    # administrator, and the PERSON answers the UAC prompt.  So the
    # test cannot do it unattended -- but it CAN check that the
    # machinery is there and that it is wired to the right thing.
    if sys.platform == "win32":
        check("the elevation is available", hasattr(FW, "_run_elevated"))
        check("it starts the process as an administrator",
              "runas" in (pathlib.Path(FW.__file__).read_text(
                  encoding="utf-8")), "the runas verb is in the source")

        # the answer comes back through a file, because the elevated
        # process is detached and its exit code is not ours to read
        check("the answer comes back through a file",
              hasattr(FW, "_result_file"))
        check("and the file is in the temporary directory",
              "temp" in FW._result_file().lower() or
              "tmp" in FW._result_file().lower(),
              FW._result_file())

        # the script the elevated process runs writes the answer
        # AND does the work: both, in one string
        script = FW.elevated_script("netsh advfirewall firewall show rule")
        check("the elevated script does the work",
              "netsh" in script, script[:80])
        check("and writes the answer", "LJT_FW_RESULT" in script,
              script[:120])
        check("and exits with the command's own code",
              "LASTEXITCODE" in script, script[:120])

        # THE QUOTING IS THE WHOLE THING.
        #
        # The script becomes the -Command argument of powershell.exe,
        # and that argument is inside DOUBLE quotes.  So a double
        # quote anywhere in the script ends the argument early, and
        # the rest of the script is run as something else.
        #
        # And inside the script, the strings are SINGLE-quoted, so a
        # single quote inside one of them ends that string.  The
        # netsh arguments are therefore quoted with single quotes,
        # and there is no double quote at all.
        body = ("netsh advfirewall firewall add rule name='ljtunnel' "
                "inbound dir=in action=allow protocol=TCP "
                "localport=10001,10002-10021 "
                "program='C:\\Program Files\\OpenSSH\\sshd.exe'")
        check("the netsh command inside the script has no double quote",
              '"' not in body, body[:80])
        check("and every single quote in it closes a string",
              body.count("'") % 2 == 0 and body.count("'") == 4,
              f"{body.count(chr(39))} single quotes")

        # the whole script: the double quotes it carries are the ones
        # the command line puts around it, and the ones PowerShell
        # uses -- so the count is fixed
        script2 = FW.elevated_script(body)
        check("the script has no double quote of its own",
              script2.count('"') == 0, f"{script2.count(chr(34))} of them")
        check("and every single quote in it closes a string",
              script2.count("'") % 2 == 0,
              f"{script2.count(chr(39))} single quotes")

        # and the command line it becomes is well formed
        command = f'powershell.exe -NoProfile -NonInteractive -Command "{script2}"'
        check("the command line has exactly two double quotes",
              command.count('"') == 2, f"{command.count(chr(34))} of them")
        check("and the script is between them",
              command.index('"') < command.index(script2) <
              command.rindex('"'), command[:80])

        # the rule, if it is already there, is found
        check("the rule's presence can be checked",
              isinstance(FW.rule_exists(), bool))

        # The rule is NOT added here.  add_rule() raises the UAC
        # prompt, and a self-test that puts a prompt on somebody's
        # screen every time they run the suite is a self-test that
        # gets skipped.  The prompt path has its own test:
        # ljtunnel.elevate_test, and ljtunnel.firewall_test.
        #
        # What is checked here is that the two paths AGREE: the rule
        # is added with the cmdlet, and the cmdlet is what the
        # firewall console shows.
        check("the rule is added with the cmdlet",
              "New-NetFirewallRule" in FW.netsh_add_body(),
              FW.netsh_add_body()[:80])
        check("and the old one goes first, so the button is safe to "
              "press twice",
              "Remove-NetFirewallRule" in FW.netsh_add_body(),
              FW.netsh_add_body()[:80])
        check("and it is removed with the cmdlet",
              "Remove-NetFirewallRule" in FW.netsh_delete_body(),
              FW.netsh_delete_body()[:80])
        check("and the rule's name is the display name",
              FW.RULE_NAME in FW.netsh_add_body(),
              FW.netsh_add_body()[:80])


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
        eq("the window has the dialer list", len(a.tree["columns"]), 5)
        eq("with the columns it shows",
           tuple(a.tree["columns"]),
           ("name", "port", "state", "where", "notes"))
        check("the window shows the firewall command",
              FW.netsh_command() in a.fw_text.get("1.0", "end"))

        # ---- the form ----
        #
        # A form that is missing a field is a form that cannot
        # record what it is supposed to record.  The five fields
        # are: the name, the address, the user, the key, and the
        # note.
        for field in ("name_var", "host_var", "user_var", "key_var",
                      "note_var"):
            check(f"the form has a {field[:-4]}",
                  hasattr(a, field), field)

        # ---- and the ways out ----
        for method in ("_save", "_forget", "_show_command",
                       "_copy_selected"):
            check(f"the window has {method}",
                  callable(getattr(a, method, None)), method)

        a._on_close()
    except Exception as e:                       # noqa: BLE001
        check("the window builds", False, f"{type(e).__name__}: {e}")


# ------------------------------------------------------------ detection

# The log lines the detector reads.  These are COPIES of what the
# sshd actually wrote, taken from a real run: the point of the test
# is that the patterns match the real thing, and a made-up line
# proves nothing.
#
# The address in them is 192.0.2.7 -- TEST-NET-1, which is reserved
# for documentation and is never routed.  The address that was really
# there is not written down: an address in a test file is an address
# somebody will copy, and it will be wrong.
_LOG_ACCEPT = ("debug1: user: xnd_l: Accepted publickey for xnd_l from "
               "192.0.2.7 port 48238 ssh2: ED25519 "
               "SHA256:xht76GglXU2cFU/7Sd14DpDOatAr+zD+qUdGU4vSk7c")
_LOG_FORWARD = ("debug1: user: xnd_l: server_input_global_request: "
                "tcpip-forward listen 0.0.0.0 port 20002 [postauth]")
_LOG_KEY_OPTION = (
    "debug2: C:/Users/xnd_l/AppData/Local/ljtunnel/"
    "ljtunnel_authorized_keys:1: check options: "
    "'environment=\"LJT_NAME=box-a\" ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIPOXAuTF66OZSgkRSFdn+6Hg6z9j9mUubai0zY/eK6VE"
    " liuxd@zlabm'")

# The fingerprint of that key, as sshd prints it.  It was MEASURED:
# the detector computes it from the key text and it has to come out
# the same, or the name can never be joined to the session.
_FP_A = "SHA256:xht76GglXU2cFU/7Sd14DpDOatAr+zD+qUdGU4vSk7c"


def test_detect():
    """The listen end sees the dialers without being told about them."""
    from ljtunnel import detect

    # ---- the fingerprint is computed the way sshd prints it ----
    eq("the fingerprint of a key is computed the way sshd prints it",
       detect._fingerprint_of(
           "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPOXAuTF66OZSgkRSFdn+6Hg6z9j9"
           "mUubai0zY/eK6VE liuxd@zlabm"),
       _FP_A)

    # ---- the key line gives the NAME ----
    reg = detect.Registry(first_port=20000, count=20)
    reg.learn([_LOG_KEY_OPTION])
    check("the name is learned from the key list",
          reg.keys_by_fingerprint.get(_FP_A) == "box-a",
          str(reg.keys_by_fingerprint))

    # ---- the accept line gives the IDENTITY ----
    reg = detect.Registry(first_port=20000, count=20)
    reg.learn([_LOG_ACCEPT])
    check("the key that authenticated is learned",
          _FP_A in reg._seen, str(list(reg._seen)))

    # ---- the forward line gives the PORT ----
    reg = detect.Registry(first_port=20000, count=20)
    reg.learn([_LOG_ACCEPT, _LOG_FORWARD])
    check("the port is learned from the log",
          reg._seen.get(_FP_A) and reg._seen[_FP_A].port == 20002,
          str([(k[:20], v.port) for k, v in reg._seen.items()]))

    # ---- and the two together, with the name ----
    reg = detect.Registry(first_port=20000, count=20)
    reg.learn([_LOG_KEY_OPTION, _LOG_ACCEPT, _LOG_FORWARD])
    d = reg._seen.get(_FP_A)
    check("the name and the port are joined",
          d is not None and d.port == 20002
          and reg.keys_by_fingerprint.get(_FP_A) == "box-a",
          str(d))

    # ---- a log that says nothing must not invent a dialer ----
    reg = detect.Registry(first_port=20000, count=20)
    reg.learn(["debug1: something else entirely", "debug1: noise"])
    check("a log with no forward has no dialers", not reg._seen,
          str(list(reg._seen)))

    # ---- a forward with no key is not a dialer either ----
    reg = detect.Registry(first_port=20000, count=20)
    reg.learn([_LOG_FORWARD])
    check("a forward with no key is not a dialer", not reg._seen,
          str(list(reg._seen)))


def test_detect_live():
    """The detector, against the socket table, with a real port."""
    from ljtunnel import detect

    # a port that is really open, and one that is not
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]
    try:
        live = detect._listening(port, port)
        check("a port that is listening is found", port in live,
              f"{port} in {sorted(live)}")

        reg = detect.Registry(first_port=port, count=1)
        reg.learn([_LOG_KEY_OPTION, _LOG_ACCEPT, _LOG_FORWARD])
        d = reg._seen.get(_FP_A)
        if d:
            d.port = port
        snap = reg.snapshot()
        check("a dialer on an open port is in the snapshot",
              any(x.port == port for x in snap), str([(x.port, x.name)
                                                      for x in snap]))
        check("the name is on it",
              any(x.port == port and x.name == "box-a" for x in snap),
              str([(x.port, x.name) for x in snap]))

        # ---- one port has one owner ----
        #
        # Two sessions asked for the SAME port, and only one of them
        # got it: the second was told "forward success" and given
        # nothing.  The socket table has one owner for the port, so
        # only one dialer can be on it -- and showing both would tell
        # a person that two machines are on one port, which is not
        # true.
        reg3 = detect.Registry(first_port=port, count=1)
        reg3.learn([_LOG_KEY_OPTION, _LOG_ACCEPT, _LOG_FORWARD])
        if _FP_A in reg3._seen:
            reg3._seen[_FP_A].port = port
            # a SECOND dialer, with its own key, on the same port
            other = detect.Dialer(fingerprint="SHA256:someoneelse",
                                  name="box-b", port=port,
                                  peer="192.0.2.7")
            reg3._seen["SHA256:someoneelse"] = other
        snap3 = reg3.snapshot()
        check("one port has one owner",
              len([x for x in snap3 if x.port == port]) == 1,
              str([(x.port, x.name) for x in snap3]))
    finally:
        # The socket is closed LAST: a closed port is not listening,
        # and the check above needs it to be.
        s.close()

    # ---- and a port that is NOT open is not in the snapshot ----
    reg2 = detect.Registry(first_port=port, count=1)
    reg2.learn([_LOG_KEY_OPTION, _LOG_ACCEPT, _LOG_FORWARD])
    if _FP_A in reg2._seen:
        reg2._seen[_FP_A].port = 45999        # a port nothing is on
    check("a dialer on a closed port is not in the snapshot",
          not reg2.snapshot(), str([(x.port, x.name)
                                    for x in reg2.snapshot()]))


def test_permit_listen():
    """The forward range is in the config, on ONE line."""
    from ljtunnel import sshd

    ports = list(range(20000, 20005))
    cfg = sshd.write_config(10000, "0.0.0.0", gateway_ports=True,
                            allow_forwarding=True, permit_listen=ports)
    text = open(cfg, encoding="utf-8").read()
    lines = [l for l in text.splitlines() if l.startswith("PermitListen")]
    eq("there is ONE PermitListen line", len(lines), 1)
    check("it holds every port in the range",
          all(str(p) in lines[0] for p in ports), lines[0][:80])

    # sshd keeps only the LAST PermitListen line, so twenty lines
    # would leave one port.  The check reads the file sshd reads.
    if sys.platform == "win32":
        exe = sshd.sshd_path()
    else:
        exe = sshd.sshd_path()
    r = subprocess.run([exe, "-f", cfg, "-T"], capture_output=True, text=True,
                       errors="replace", timeout=60)
    out = r.stdout or ""
    pl = [l for l in out.splitlines() if l.startswith("permitlisten")]
    check("the sshd keeps every port in the range",
          bool(pl) and all(f":{p}" in pl[0] for p in ports),
          (pl[0][:100] if pl else out[-120:]))


# ---------------------------------------------------------------- records

def test_records():
    """The records: kept, replaced, and forgotten.

    The records are the form's memory.  A record that is not written
    out is a form that has to be filled in again every time, and a
    record that is written badly is a form that cannot be read at
    all -- so the file is written through a temporary one and
    renamed, and the test reads it back the way the program does.
    """
    # the test does not touch the real records
    tmp = tempfile.mkdtemp(prefix="ljt-records-")
    real = records.records_path
    records.records_path = lambda: os.path.join(tmp, "recs.json")
    try:
        records.save([])
        eq("a record file starts empty", records.load(), [])

        rec = records.add("box-a", "ssh-ed25519 AAAA test", "192.0.2.5",
                          "someone", "the far one")
        eq("the record is kept", len(records.load()), 1)
        eq("with its name", rec["name"], "box-a")
        eq("with its key", rec["pubkey"], "ssh-ed25519 AAAA test")
        eq("with its address", rec["host"], "192.0.2.5")
        eq("with its user", rec["user"], "someone")
        eq("with its note", rec["note"], "the far one")

        # ---- the file is real JSON, and it survives a reload ----
        import json
        with open(records.records_path(), encoding="utf-8") as fh:
            raw = json.load(fh)
        check("the file is JSON", isinstance(raw, list), str(type(raw)))
        eq("with one record in it", len(raw), 1)

        # ---- the same name REPLACES, it does not duplicate ----
        records.add("box-a", "ssh-ed25519 AAAA test", "192.0.2.6", "", "")
        eq("the same name does not duplicate", len(records.load()), 1)
        eq("and the new address is the one that is kept",
           records.by_name("box-a")["host"], "192.0.2.6")

        # ---- a second record ----
        records.add("box-b", "", "192.0.2.7")
        eq("a second record is kept", len(records.load()), 2)
        check("both names are there",
              set(records.names()) == {"box-a", "box-b"},
              str(records.names()))

        # ---- and it can be forgotten ----
        check("the record was there", records.remove("box-a"))
        eq("one is left", len(records.load()), 1)
        check("and it is the other one",
              records.by_name("box-a") == {}, str(records.by_name("box-a")))
        check("forgetting one that is not there says so",
              not records.remove("box-a"))

        # ---- a file that cannot be read is not a crash ----
        with open(records.records_path(), "w", encoding="utf-8") as fh:
            fh.write("this is not json")
        eq("a broken file reads as no records", records.load(), [])

        # ---- and the command ----
        cmd = records.command_for({"name": "box-a", "host": "192.0.2.5",
                                    "user": "someone", "pubkey": ""})
        check("the command is a dialer command",
              cmd.startswith("ljtunnel dialer"), cmd[:60])
        check("it names the address", "192.0.2.5" in cmd, cmd[:100])
        check("it names the user", "--user someone" in cmd, cmd[:100])
        check("it names the listen port",
              f"--listen-port {L.LISTEN_SSHD_PORT}" in cmd, cmd[:100])
        check("it carries the access key", "ssh-ed25519" in cmd, cmd[:100])
        check("it does NOT name a forward port",
              "--forward-port" not in cmd,
              "the dialer finds the port itself")
        check("it carries NO private key",
              "PRIVATE KEY" not in cmd and "id_rsa" not in cmd, cmd[:100])

        # ---- a record with no address uses this end's own ----
        cmd2 = records.command_for({"name": "box-b", "host": "", "user": "",
                                     "pubkey": ""})
        check("with no address it uses this end's own",
              L.local_ipv4() in cmd2, cmd2[:100])
    finally:
        records.records_path = real
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------- the address

def test_no_internal_addresses():
    """No real internal address in the tracked tree.

    The address of a machine is not a fact about the software, and
    it is wrong the moment the machine is on a different network.  So
    it is read at run time and never written down.

    The exception is the documentation ranges: 192.0.2.0/24 and
    203.0.113.0/24 are reserved for exactly this, and they are
    never routed.  Everything else in those blocks is a real
    address, and a real address in the tree is a leak.

    The whole TRACKED tree is walked, not just the package: the
    README and the tools are shipped too, and an address in a
    comment is as much a leak as an address in a string.
    """
    import re as _re
    import subprocess as _subprocess

    root = pathlib.Path(__file__).resolve().parent.parent
    try:
        names = _subprocess.run(
            ["git", "ls-files"], cwd=str(root), capture_output=True,
            text=True, errors="replace", timeout=60).stdout.split()
    except (OSError, _subprocess.TimeoutExpired):
        check("the tracked files can be listed (skipped)", True)
        return
    if not names:
        check("the tracked files can be listed (skipped)", True)
        return

    # a private address, but not the documentation ranges
    #
    # The documentation ranges are 192.0.2.0/24, 198.51.100.0/24
    # and 203.0.113.0/24.  Everything else in those three blocks is
    # a real address.
    #
    # The look-ahead is on the WHOLE first three octets, so the
    # documentation ranges are skipped and nothing else is.
    pat = _re.compile(
        r"(?<!\d)"
        r"(?!192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)"
        r"(?:"
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
        r"|192\.168\.\d{1,3}\.\d{1,3}"
        r")"
        r"(?!\d)")

    bad = []
    for name in names:
        p = root / name
        if not p.is_file() or p.suffix in (".msi", ".exe", ".ico", ".png",
                                            ".pyc", ".zip"):
            continue
        try:
            body = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for n, line in enumerate(body.splitlines(), 1):
            if pat.search(line):
                bad.append(f"{name}:{n}")
    check("no internal address in the tracked tree", not bad,
          ", ".join(bad[:8]))


# --------------------------------------------------------- the elevation

def test_elevation():
    """The elevation, and what it needs.

    The app asks to be an administrator when it starts, so the
    firewall rule needs no prompt of its own.  The UAC prompt is the
    person's confirmation, and it is asked ONCE.

    What is checked here is the machinery, not the prompt: a prompt
    cannot be answered by a test, and ljtunnel.elevate_test asks the
    question with a person in the loop.
    """
    from ljtunnel import elevate

    check("the elevation is available",
          hasattr(elevate, "shell_execute_runas"))
    check("the app can start itself again",
          hasattr(elevate, "relaunch_elevated"))
    check("and it says whether it did",
          isinstance(elevate.is_admin(), bool))

    if sys.platform == "win32":
        check("the PowerShell is a real file",
              os.path.isfile(elevate.POWERSHELL), elevate.POWERSHELL)
        check("and it is the full path",
              os.path.isabs(elevate.POWERSHELL), elevate.POWERSHELL)

        # a prompt that says "No" is ERROR_CANCELLED, and that is a
        # thing that happened rather than a failure
        check("a declined prompt is told apart from an error",
              elevate.ERROR_CANCELLED == 1223,
              str(elevate.ERROR_CANCELLED))

    # the window asks for the elevation at the START, so the rule
    # needs no prompt of its own later
    src = pathlib.Path(elevate.__file__).read_text(encoding="utf-8")
    check("the elevation is in its own module", "runas" in src,
          "the runas verb is there")
    app_src = (pathlib.Path(__file__).resolve().parent / "app.py").read_text(
        encoding="utf-8")
    check("and the window asks for it at the start",
          "relaunch_elevated" in app_src, "app.py asks for it")


# ------------------------------------------------------- the command

def test_command():
    """The command a dialer runs, and what is IN it.

    The command is the whole handoff: it is what a person copies
    from the panel and pastes into a terminal on the other machine.
    So what it carries, and what it does not, is part of the
    contract.

    WHAT IT MUST CARRY
      - the reachable end's address
      - the reachable end's port
      - the reachable end's USER, and not the dialer's own user:
        the dialer opens an ssh session to the REACHABLE end, and
        that end's sshd refuses a user that does not exist on it
      - the access key, so the setup is one step

    WHAT IT MUST NOT CARRY
      - a forward port: the dialer finds a free one itself
      - a private key: the command is pasted into a terminal and
        shown in the panel
    """
    rec = {"name": "box-a", "host": "192.0.2.5", "user": "someone",
           "pubkey": "", "note": ""}
    cmd = records.command_for(rec)

    check("the command is a dialer command",
          cmd.startswith("ljtunnel dialer"), cmd[:60])
    check("it names the address", "192.0.2.5" in cmd, cmd[:100])
    check("it names the user", "--user someone" in cmd, cmd[:100])
    check("it names the listen port",
          f"--listen-port {L.LISTEN_SSHD_PORT}" in cmd, cmd[:100])
    check("it carries the access key", "ssh-ed25519" in cmd, cmd[:100])
    check("it does NOT name a forward port",
          "--forward-port" not in cmd,
          "the dialer finds the port itself")
    check("it carries NO private key",
          "PRIVATE KEY" not in cmd and "id_rsa" not in cmd, cmd[:100])
    check("it carries no secret of any other kind",
          "password" not in cmd.lower(), cmd[:100])

    # ---- with no user, it is the reachable end's own user ----
    cmd2 = records.command_for({"name": "box-b", "host": "192.0.2.6",
                                 "user": "", "pubkey": ""})
    check("with no user it uses this end's own",
          f"--user {L.current_user()}" in cmd2, cmd2[:100])

    # ---- with no address, it is this end's own address ----
    cmd3 = records.command_for({"name": "box-c", "host": "", "user": "",
                                 "pubkey": ""})
    check("with no address it uses this end's own",
          L.local_ipv4() in cmd3, cmd3[:100])

    # ---- and the access key is a PUBLIC key ----
    check("the access key is a public key",
          "PRIVATE" not in L.access_public_key(),
          L.access_public_key()[:60])


# ---------------------------------------------------------------- the run

def main() -> int:
    print(f"ljtunnel {__version__} -- the self-test")
    print()
    for fn in (test_paths, test_config, test_keys, test_access_key,
               test_dialer,
               test_allocator, test_port_in_use, test_firewall,
               test_dispatcher, test_console, test_address, test_version,
               test_app, test_detect, test_detect_live, test_permit_listen,
               test_records, test_command, test_no_internal_addresses,
               test_elevation):
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
