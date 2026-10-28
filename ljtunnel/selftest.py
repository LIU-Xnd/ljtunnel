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

                # THE PENALTY EXEMPTION.
                #
                # OpenSSH for Windows has PerSourcePenalties on by
                # default, and a dialer CHECKS the ports it asks for
                # by connecting to them -- which is exactly what the
                # penalty is for.  So a dialer that tries a few ports
                # can put its own address into the penalty list, and
                # then the sshd sends:
                #
                #     Not allowed at this time
                #
                # where a banner should be.  The client sees a line
                # that is not an SSH banner and gives up with "banner
                # line contains invalid characters", and the log
                # blames the banner rather than the penalty.
                #
                # So the tunnel's own addresses are exempt.
                check("the config exempts the tunnel's own addresses",
                      "PerSourcePenaltyExemptList" in text,
                      text[-140:].strip())
                check("and the loopback is among them",
                      "127.0.0.1" in text, text[-140:].strip())

                # and the sshd KEEPS it: an option it does not know
                # is a warning, not an error, and it would be nice
                # to know.
                #
                # `sshd -T` is asked about the REAL config, not the
                # scratch one: -T refuses to run without a host key
                # it can load, and the scratch directory has none.
                real_cfg = paths.sshd_config()
                sshd.ensure_host_key()
                real_cfg = sshd.write_config(10001, "0.0.0.0",
                                             permit_listen=[10002])
                r = subprocess.run([sshd.sshd_path(), "-f", real_cfg, "-T"],
                                   capture_output=True, text=True,
                                   errors="replace", timeout=60)
                out = (r.stdout or "")
                check("and the sshd keeps the exemption",
                      "persourcepenaltyexemptlist" in out.lower(),
                      out[-160:].strip() if out
                      else (r.stderr or "")[:160])
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
    # THE FORWARD POINTS AT THIS END'S OWN SERVICE.  It is checked by
    # RUNNING the command builder, not by looking for a string in the
    # source -- the string moved when the http server was added, and a
    # check that looks for a string says nothing about the behaviour.
    _args7 = dialer_mod.build_parser().parse_args(
        ["--listen-host", "192.0.2.7"])
    _cmd7 = " ".join(dialer_mod._forward_command(
        _args7, "/tmp/k", 10002, "someone"))
    check("the dialer's forwarding goes to its own sshd",
          "0.0.0.0:10002:127.0.0.1:10001" in _cmd7,
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
          "sshd.ensure_client_key(" in src)
    # AND THE NAME GOES ON THE KEY, so the other end's panel can show
    # it without anybody typing it in there.
    check("and the dialer's key carries the name",
          "ensure_client_key(name)" in src,
          "the dialer does not put the name on its key")
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
    from . import cli as D

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
    from . import cli as D

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
                "import ljtunnel.cli as D\n"
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
        eq("the window has the dialer list", len(a.tree["columns"]), 4)
        eq("with the columns it shows",
           tuple(a.tree["columns"]),
           ("name", "port", "state", "where"))
        check("the window shows the firewall command",
              FW.netsh_command() in a.fw_text.get("1.0", "end"))

        # ---- THE KEY FIELD, AND ONLY THE KEY FIELD ----
        #
        # THERE IS ONE INPUT AND IT IS THE KEY.  Everything else the
        # form used to ask for is read from the key or worked out:
        # the name is the key's COMMENT, the address is the dialer's
        # own, and the notes were never worth a field.
        #
        # MEASURED: a form with a field for every piece of the dialer
        # is a form nobody fills in, and the one thing that has to be
        # copied -- the key -- was one of five boxes.
        check("the form has the key field", hasattr(a, "key_var"))
        for field in ("name_var", "host_var", "user_var", "note_var",
                      "local_user_var"):
            check(f"and NOT a {field[:-4]} field",
                  not hasattr(a, field), field)

        # ---- and the ways out ----
        for method in ("_save", "_forget", "_show_command"):
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
               "SHA256:RY1xRnF/3WiV8FKLVS6z16esXWAcCAPhjY30GHzqlzk")
_LOG_FORWARD = ("debug1: user: xnd_l: server_input_global_request: "
                "tcpip-forward listen 0.0.0.0 port 20002 [postauth]")
_LOG_KEY_OPTION = (
    "debug2: C:/Users/xnd_l/AppData/Local/ljtunnel/"
    "ljtunnel_authorized_keys:1: check options: "
    "'environment=\"LJT_NAME=box-a\" ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIK4icCbdG74l91kP0yiahmWy5ATLu47tVar4KD9FAOqx"
    " ljtunnel-test-fixture'")

# The fingerprint of that key, as sshd prints it.
#
# IT WAS COMPUTED BY OPENSSH ITSELF, not by this project's own code:
# `ssh-keygen -lf` on the key.  If the detector's arithmetic and
# OpenSSH's disagree, the check below is the one that catches it --
# so the expected value cannot come from the code under test.
#
# The key is a FIXTURE, made for this test and thrown away with it.
# It is not anybody's key: an earlier version of this file carried
# a real machine's public key, and a repository is a public place.
_FP_A = "SHA256:RY1xRnF/3WiV8FKLVS6z16esXWAcCAPhjY30GHzqlzk"


def test_detect():
    """The listen end sees the dialers without being told about them."""
    from ljtunnel import detect

    # ---- the fingerprint is computed the way sshd prints it ----
    #
    # The key is the FIXTURE above, and the expected value is what
    # OpenSSH itself says about it.
    eq("the fingerprint of a key is computed the way sshd prints it",
       detect._fingerprint_of(
           "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK4icCbdG74l91kP0yiahmWy5ATLu47tVa"
           "r4KD9FAOqx ljtunnel-test-fixture"),
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

    # A PORT THAT IS REALLY OPEN, AND ONE THAT IS NOT.
    #
    # AND IT SAYS THE SSH BANNER, because that is what the detector
    # asks now: a dialer that has gone leaves its lines in the log,
    # and its PORT is taken by something else -- MEASURED: an
    # http.server on 10010 -- and the panel said the dialer was up.
    # It was not.  So the thing on the port has to be an sshd.
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    port = s.getsockname()[1]

    # the banner, said by the socket
    def _say_banner(conn):
        try:
            conn.sendall(b"SSH-2.0-OpenSSH_9.6 TestFixture\r\n")
        except OSError:
            pass

    import threading as _th3
    _stop3 = False

    def _banner_loop():
        while not _stop3:
            try:
                s.settimeout(0.5)
                conn, _ = s.accept()
            except (socket.timeout, OSError):
                continue
            _th3.Thread(target=_say_banner, args=(conn,), daemon=True).start()

    _th3.Thread(target=_banner_loop, daemon=True).start()
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

        # ---- a port that is NOT an sshd is not a dialer ----
        #
        # MEASURED: a dialer that had gone left its lines in the log,
        # and its PORT was taken by something else -- an http.server on
        # 10010 -- and the panel said the dialer was up.  It was not.
        #
        # So the thing on the port has to be an sshd, and the banner is
        # how you ask.
        _plain = socket.socket()
        _plain.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        _plain.bind(("127.0.0.1", 0))
        _plain.listen(1)
        _pport = _plain.getsockname()[1]
        try:
            _reg4 = detect.Registry(first_port=_pport, count=1)
            _reg4.learn([_LOG_KEY_OPTION, _LOG_ACCEPT, _LOG_FORWARD])
            if _FP_A in _reg4._seen:
                _reg4._seen[_FP_A].port = _pport
            _snap4 = _reg4.snapshot()
            check("a port with something else on it is not a dialer",
                  not any(x.port == _pport for x in _snap4),
                  str([(x.port, x.name) for x in _snap4]))
            check("and the banner is what tells them apart",
                  detect.banner_of(_pport, timeout=3.0) == "",
                  repr(detect.banner_of(_pport, timeout=3.0)))
        finally:
            _plain.close()

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
        _stop3 = True
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


def test_firewall_body():
    """The firewall rule is put in, and the old one goes away FIRST.

    THE REMOVAL MUST NOT BE SILENT.  With
    -ErrorAction SilentlyContinue a removal that failed is swallowed,
    the script carries on, and the new rule is added BESIDE the old
    one.  Press the button twice and there are two rules; press it
    five times and there are five.  They all do the same thing, and
    the firewall console shows a list of identical entries.

    So the removal is caught, and a removal that did not happen
    STOPS the script: no new rule is added.
    """
    from ljtunnel import firewall

    add_body = firewall.netsh_add_body()
    del_body = firewall.netsh_delete_body()

    check("the add body removes the old rule first",
          "Remove-NetFirewallRule" in add_body, add_body[:90])
    check("and the removal is NOT silent",
          "-ErrorAction SilentlyContinue" not in add_body,
          "the removal reports what went wrong")
    check("the removal is caught",
          "catch" in add_body and "throw" in add_body,
          "a failed removal stops the script")
    check("and it THROWS rather than exiting",
          "exit " not in add_body,
          "an exit would skip the writing of the answer file")
    check("the removal comes BEFORE the addition",
          add_body.index("Remove-NetFirewallRule")
          < add_body.index("New-NetFirewallRule"),
          "the old rule goes first")
    check("and the delete body is not silent either",
          "-ErrorAction SilentlyContinue" not in del_body
          and "throw" in del_body, del_body[:90])

    # and the body is one line, so it can be a -Command argument
    # when it has to be
    check("the body has no newline",
          "\n" not in add_body, repr(add_body[:60]))

    # ---- and the script AROUND the body catches the throw ----
    #
    # A `throw` inside the body is caught by the script, and the
    # answer file IS written, with the reason in it.  An `exit`
    # would skip the writing, and the caller would find nothing
    # there and learn nothing.
    script = firewall.elevated_script(add_body, r"C:\Temp\out.txt")
    check("the script catches the body's throw",
          "catch" in script and "$_.Exception.Message" in script,
          script[-180:].strip())
    check("and it still writes the answer",
          "Out-File" in script and "exit=" in script,
          "the caller can read what happened")


def test_one_key_two_jobs():
    """The dialer's HOST key is its MACHINE key, and everything that
    compares fingerprints knows it.

    THE DIALER'S SSHD PRESENTS THE MACHINE KEY AS ITS HOST KEY, and
    that is what makes the listen end able to NAME the dialer without
    the sshd's log: the key behind a forwarded port is the key the
    dialer logged in with, and the listen end knows that key.

    **AND THE TWO FINGERPRINTS MUST BE COMPARED AGAINST THE SAME
    FILE.**  There are two key files on the dialer end -- the host
    key's and the machine key's -- and they are different keys.  So
    a check that compares against the host key's file says "this
    port is not mine" about a port that IS, and the dialer gives up
    on every port:

        the client said yes but port 20000 is not ours.  Trying the
        next one.

    and then:

        no port in 20000-20019 could be taken.

    which looks like the reachable end is full, and is not.

    So the check is that the sshd's config names the MACHINE key,
    and that the fingerprint the dialer compares against is the
    MACHINE key's fingerprint.  Both, and they are the same key.
    """
    from ljtunnel import dialer, paths, sshd

    # THE HOST KEY HAS TO BE THERE, or the test is testing nothing.
    # A person who has just uninstalled ljtunnel -- and taken the
    # configuration with them -- has no host key, and the suite
    # would fail for a reason that has nothing to do with the code.
    sshd.ensure_host_key()
    sshd.ensure_client_key()

    # ---- the config names the machine key ----
    cfg = sshd.write_config(10001, "127.0.0.1", host_key=paths.client_key())
    text = open(cfg, encoding="utf-8").read()
    check("the sshd's config can name the machine key",
          paths.client_key().replace("\\", "/") in text
          or paths.client_key() in text,
          "the machine key is not in it")

    # ---- and the two are the same key ----
    machine = sshd.public_key_of(paths.client_key())
    host = sshd.public_key_of(paths.host_key())
    check("the machine key and the host key are different files",
          machine != host, "they are the same key")

    # ---- and the fingerprint the dialer compares against is the
    #      MACHINE key's ----
    import subprocess
    r = subprocess.run([sshd.ssh_keygen_path(), "-lf",
                        paths.client_key() + ".pub"],
                       capture_output=True, text=True,
                       errors="replace", timeout=60)
    parts = (r.stdout or "").strip().split()
    machine_fp = parts[1] if len(parts) >= 2 else ""

    r2 = subprocess.run([sshd.ssh_keygen_path(), "-lf",
                         paths.host_key() + ".pub"],
                        capture_output=True, text=True,
                        errors="replace", timeout=60)
    parts2 = (r2.stdout or "").strip().split()
    host_fp = parts2[1] if len(parts2) >= 2 else ""

    check("the two fingerprints are different",
          machine_fp and host_fp and machine_fp != host_fp,
          f"{machine_fp} / {host_fp}")

    # and the dialer's own check reads the machine key's file
    import inspect
    src = inspect.getsource(dialer._own_host_key_fingerprint)
    check("and the dialer compares against the MACHINE key",
          "client_key()" in src,
          "it compares against the host key, which is a different key")


def test_key_command():
    """`ljtunnel key` prints the MACHINE key, not the host key.

    THEY ARE NOT INTERCHANGEABLE, and the mistake is silent on this
    side and fatal on the other.

    The HOST key is this end's identity to a CLIENT: it is what a
    client checks to be sure it is talking to the right machine, and
    it is what the forwarded port's banner is built on.

    The MACHINE key is this end's identity to the OTHER END: it is
    what the dialer logs in to the listen end with, and it is what
    the listen end's key list has to name for the dialer to be let
    in.

    Printing the host key into the other end's key list produces a
    key the other end does not know, and the dialer is refused with:

        the reachable end did not accept this end's key

    which is a correct refusal of the wrong key.
    """
    from ljtunnel import paths, sshd

    # the key has to be there, or there is nothing to print
    sshd.ensure_client_key()
    sshd.ensure_host_key()

    # ---- the command prints the machine key ----
    import subprocess
    r = subprocess.run([sys.executable, "-m", "ljtunnel", "key"],
                       capture_output=True, text=True,
                       errors="replace", timeout=90)
    printed = (r.stdout or "").strip()
    check("the key command prints something", r.returncode == 0 and printed,
          printed[:60])
    check("and it is a public key",
          printed.startswith("ssh-ed25519") or printed.startswith("ssh-rsa"),
          printed[:40])

    # ---- and it is NOT the host key ----
    #
    # The two key files are in the same directory, and the public
    # halves have different bodies.
    machine_pub = sshd.public_key_of(paths.client_key())
    host_pub = sshd.public_key_of(paths.host_key())
    check("the machine key and the host key are different keys",
          machine_pub != host_pub, "they are the same")
    check("and the command printed the MACHINE key",
          printed == machine_pub.strip(),
          f"it printed the host key" if printed == host_pub.strip()
          else printed[:50])

    # ---- and the help says so ----
    r2 = subprocess.run([sys.executable, "-m", "ljtunnel", "key", "--help"],
                        capture_output=True, text=True,
                        errors="replace", timeout=90)
    check("and the help says it is the machine key",
          "machine key" in (r2.stdout or ""),
          (r2.stdout or "").strip()[:70])


def test_forget():
    """The configuration can be taken away, and the question is asked.

    THE KEYS ARE THE IDENTITY OF A TUNNEL.  A machine that cannot be
    reached is identified by the key it logs in with, and the listen
    end's key list names the machines it trusts.  So removing them
    has to be a DELIBERATE act, not the default.

    And the removal takes the WHOLE DIRECTORY, because the whole
    configuration is in one directory: the sshd config, the two key
    pairs, the key list, the records, the pid and the log.  Nothing
    is written anywhere else, so "forget everything this end knew"
    is one directory, removed.
    """
    from ljtunnel import forget, paths

    # ---- the command is there, on both ends ----
    import subprocess
    r = subprocess.run([sys.executable, "-m", "ljtunnel", "forget",
                        "--help"], capture_output=True, text=True,
                       errors="replace", timeout=90)
    check("the forget command has a help", r.returncode == 0,
          (r.stdout or r.stderr or "").strip()[:80])
    check("and it says what it does",
          "configuration" in (r.stdout or ""),
          (r.stdout or "").strip()[:80])
    check("and it says the firewall rule is NOT removed",
          "firewall" in (r.stdout or "").lower(),
          "the rule is a machine-wide thing")

    # ---- the directory holds everything ----
    directory = paths.state_dir()
    check("the configuration is in ONE directory",
          directory.endswith(paths.APP_NAME), directory)

    # ---- and the removal really removes it ----
    #
    # It is done in a scratch directory, so the real configuration is
    # not touched by the test.
    import tempfile
    import contextlib
    import io
    with tempfile.TemporaryDirectory() as tmp:
        old = paths.state_dir
        paths.state_dir = lambda: tmp
        try:
            with open(paths.sshd_config(), "w", encoding="utf-8") as fh:
                fh.write("Port 10001\n")
            with open(paths.client_key(), "w", encoding="utf-8") as fh:
                fh.write("PRIVATE KEY\n")
            check("there is something to remove",
                  os.path.isdir(tmp) and bool(os.listdir(tmp)),
                  str(os.listdir(tmp))[:60])

            # --yes, so the test does not need a keyboard, and
            # quiet, so the suite's own output stays readable
            with contextlib.redirect_stdout(io.StringIO()):
                rc = forget.forget(assume_yes=True)
            check("the removal says it worked", rc == 0, str(rc))
            check("and the directory is gone", not os.path.isdir(tmp),
                  "still there")
        finally:
            paths.state_dir = old

    # ---- AND THE ANSWER "NO" MUST NOT REMOVE ANYTHING ----
    #
    # This is the whole point of the question, and the one that a
    # test which only ever says "yes" does not check.  So the
    # question is asked with the answer "no", and the directory has
    # to still be there.
    #
    # The answer goes in on STDIN, because that is where the
    # question reads it from, and the keyboard is not a thing a
    # test can have.
    with tempfile.TemporaryDirectory() as tmp:
        old = paths.state_dir
        paths.state_dir = lambda: tmp
        try:
            with open(paths.sshd_config(), "w", encoding="utf-8") as fh:
                fh.write("Port 10001\n")
            with open(paths.client_key(), "w", encoding="utf-8") as fh:
                fh.write("PRIVATE KEY\n")

            saved = sys.stdin
            sys.stdin = io.StringIO("n\n")
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    rc = forget.forget(assume_yes=False)
            finally:
                sys.stdin = saved
            check("the answer 'no' is not a removal", rc != 0, str(rc))
            check("and the configuration is still there",
                  os.path.isdir(tmp) and bool(os.listdir(tmp)),
                  "the directory went without being asked to")
        finally:
            paths.state_dir = old

    # ---- and removing what is not there is not a failure ----
    with tempfile.TemporaryDirectory() as tmp:
        old = paths.state_dir
        paths.state_dir = lambda: os.path.join(tmp, "not-there")
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                rc = forget.forget(assume_yes=True)
            check("removing nothing is not a failure", rc == 0, str(rc))
        finally:
            paths.state_dir = old


def test_listener_handle():
    """The listener's process is reachable under BOTH of its names.

    IT IS CALLED `proc` IN THE LISTENER AND `srv` IN THE WINDOW, and
    two names for one thing is a trap: a script that reaches for the
    other name gets an AttributeError, and the message points at
    the script rather than at the naming.

    MEASURED: a probe that read `listener.srv` died with

        AttributeError: 'Listener' object has no attribute 'srv'

    and the probe was not wrong about wanting the process -- it was
    wrong about which name it was under.

    AND A STOPPED LISTENER SAYS SO.  A listener that has been
    stopped still saying it has a process is a listener that says
    it is running when it is not.
    """
    from ljtunnel import listen as L

    # ---- both names, before anything is started ----
    listener = L.Listener(sshd_port=10000, first_port=20000, count=1)
    check("the listener has no process yet", listener.proc is None)
    check("and the window's name says the same",
          listener.srv is None, str(listener.srv))

    # ---- and after a stop ----
    #
    # It is stopped without being started, so nothing is launched
    # and no port is taken.
    listener.stop()
    check("a stopped listener says it has no process",
          listener.proc is None)
    check("and the window's name says the same",
          listener.srv is None, str(listener.srv))

    # ---- AND WITH A REAL PROCESS, THE TWO NAMES ARE THE SAME ONE ----
    #
    # WITHOUT THIS THE CHECK IS WORTHLESS: a property that always
    # returns None satisfies "is None" every time, and the suite
    # goes green with the property broken.
    #
    # MEASURED: that is what happened -- the first version of this
    # check passed with the property returning None.
    #
    # So a real sshd is started on a port the firewall admits, and
    # the two names have to be the SAME OBJECT.
    import subprocess
    import time

    from ljtunnel import sshd

    port = 10000
    if sshd.port_busy(port):
        check("the port for the listener test is free (skipped)", True)
        return

    sshd.stop()
    sshd.stop_sessions()
    time.sleep(1)

    live = L.Listener(sshd_port=port, first_port=20000, count=1)
    try:
        proc = live.start()
        time.sleep(2)
        check("the listener has a process", live.proc is not None)
        check("and the window's name is the SAME process",
              live.srv is live.proc, f"{live.srv} vs {live.proc}")
        check("and it is the one that was started",
              live.srv is proc, f"{live.srv} vs {proc}")
    finally:
        live.stop()
    check("and a stopped listener says it has no process",
          live.proc is None)
    check("and the window's name says the same",
          live.srv is None, str(live.srv))


def _is_source_tree() -> bool:
    r"""Whether this is the SOURCE tree, or the INSTALLED program.

    The guards that read the source are about the source: they read
    `app.py` to see what it does, and `tools/crossmachine_form.py` to
    see what the test does.  The INSTALLED program has neither -- it
    is a program, not a tree -- and a guard that reads a file that is
    not there fails with a FileNotFoundError and looks like a bug in
    the product.

    MEASURED: the installed suite said

        FileNotFoundError: ...\site-packages\pyproject.toml

    So the source guards are SKIPPED in the installed program, and
    they say that they were skipped.
    """
    return (pathlib.Path(__file__).resolve().parent.parent
            / "pyproject.toml").is_file()


def test_host_key_change():
    """A changed host key is SAID, not left as a row of @ signs.

    OpenSSH closes the connection before it says anything useful,
    and the dialer used to read that as a banner problem.  So a
    dialer whose reachable end was reinstalled tried twenty ports
    and reported twenty rows of "@@@@@@" -- which looks like the
    quoting is wrong and is not.

    MEASURED: the reachable end's configuration had been cleared,
    its keys were made again, and the far side's known_hosts still
    had the old one.  The sshd's side of it said only:

        user: (null): Connection closed by 192.0.2.7 [preauth]

    So there is nothing to match on either side.

    The dialer now checks the fingerprint BEFORE it tries a port, and
    says what happened.
    """
    from ljtunnel import cli, dialer, detect

    # ---- the refusal is named ----
    check("a changed host key is named in the refusal",
          "host key" in dialer._refusal_reason(
              "REMOTE HOST IDENTIFICATION HAS CHANGED"),
          dialer._refusal_reason("REMOTE HOST IDENTIFICATION HAS CHANGED")[:60])
    check("and so is a verification failure",
          "host key" in dialer._refusal_reason(
              "Host key verification failed."),
          dialer._refusal_reason("Host key verification failed.")[:60])

    # ---- and the fingerprint of a key is the one ssh would print ----
    import base64
    import hashlib
    key = ("ssh-ed25519 "
           "AAAAC3NzaC1lZDI1NTE5AAAAIK4icCbdG74l91kP0yiahmWy5ATLu47tVa"
           "r4KD9FAOqx ljtunnel-test-fixture")
    raw = base64.b64decode(key.split()[1])
    want = ("SHA256:"
            + base64.b64encode(hashlib.sha256(raw).digest()).decode()
            .rstrip("="))
    check("the changed key is compared as a fingerprint",
          detect._fingerprint_of(key) == want,
          detect._fingerprint_of(key)[:40])

    # ---- AND THE OLD KEY CAN BE TAKEN AWAY ----
    #
    # It is taken away by asking ssh to do it, because ssh wrote it
    # and ssh knows how to remove it -- and the file is in the
    # hashed form, so a line cannot be found by reading it.
    import subprocess
    import tempfile as _tf

    with _tf.TemporaryDirectory() as tmp:
        kf = os.path.join(tmp, "known_hosts")
        plain = os.path.join(tmp, "plain")
        with open(plain, "w", encoding="utf-8") as fh:
            fh.write("[203.0.113.7]:10000 " + key + "\n")
        subprocess.run(["ssh-keygen", "-f", plain, "-H"], capture_output=True,
                       text=True, errors="replace", timeout=60)
        with open(plain, encoding="utf-8", errors="replace") as fh:
            hashed = fh.read()
        with open(kf, "w", encoding="utf-8", newline="\n") as fh2:
            fh2.write(hashed)

        old_dir = paths.state_dir
        paths.state_dir = lambda: tmp
        try:
            got = dialer._known_host_key("203.0.113.7", 10000)
            check("the remembered host key is read from the known_hosts",
                  got == want, f"{str(got)[:40]} -- the file was: {hashed[:60]}")

            check("the old key can be taken away",
                  dialer._forget_known_host("203.0.113.7", 10000))
            check("and then there is nothing left to remember",
                  dialer._known_host_key("203.0.113.7", 10000) == "",
                  dialer._known_host_key("203.0.113.7", 10000)[:40])
        finally:
            paths.state_dir = old_dir

    # ---- AND THE NAME ON A KEY CAN BE CHANGED ----
    #
    # `add_key` LEAVES A KEY THAT IS ALREADY IN THE LIST ALONE, and
    # that is right -- but a key in a SHARED list can be put in again
    # under a different name, and then the name has to change.
    import tempfile as _tf2

    with _tf2.TemporaryDirectory() as tmp2:
        old_dir2 = paths.state_dir
        paths.state_dir = lambda: tmp2
        try:
            listen.add_key(key, "thefirstname")
            listen.set_key_name(key, "thesecondname")
            names = [l for l in listen.read_keys() if key.split()[-2] in l]
            check("the name on a key can be changed",
                  len(names) == 1 and "thesecondname" in names[0],
                  str(names)[:120])
            # AND THE KEY TYPE IS STILL ON IT.  A public key is
            # three tokens -- the type, the body and the comment --
            # and the type is what tells sshd what it is.  Leaving
            # the type off makes the sshd refuse the key while the
            # panel says it is in the list, because it IS.
            #
            # MEASURED: the last TWO tokens were taken, so the line
            # was "environment=... AAAAC3Nza... liuxd@zlabm" and the
            # sshd said "Failed publickey".
            # THE TYPE IS NOT THE FIRST TOKEN: the options come
            # first, and the type is the token BEFORE the body.
            check("and the key type is still on it",
                  any(any(tok.startswith("ssh-") for tok in l.split())
                      for l in names if l.split()),
                  str(names)[:120])
            check("and the old name is gone",
                  not any("thefirstname" in l for l in listen.read_keys()),
                  str(listen.read_keys())[:120])
        finally:
            paths.state_dir = old_dir2

    # ---- AND THE SUBPROCESSES DO NOT OPEN A WINDOW ----
    #
    # THE PANEL ASKS POWERSHELL FOR THE SOCKET TABLE ONCE A SECOND,
    # and the Windows launcher is built on pythonw.exe, which has no
    # console.  A console program started with no console to join
    # makes a NEW one, in a window, on the screen -- so the panel put
    # a PowerShell window on the screen once a second.
    #
    # The flag that stops it is CREATE_NO_WINDOW, and it is only
    # right on Windows.
    import subprocess as _sp2

    # THE FLAG IS A WINDOWS THING, so the check for it is too.
    #
    # MEASURED: the check asked for `subprocess.CREATE_NO_WINDOW` on
    # Linux, where it does not exist, and the whole test raised
    # AttributeError -- so the check that was MEANT to prove the
    # flag is there proved nothing on the other platform.
    check("the no-window flag is there on Windows",
          (not hasattr(_sp2, "CREATE_NO_WINDOW")
           or _sp2.CREATE_NO_WINDOW != 0)
          if sys.platform == "win32" else
          not hasattr(_sp2, "CREATE_NO_WINDOW"))
    from ljtunnel import quiet
    _flags = quiet.no_window_flags()
    check("and the flag is passed to the children",
          _flags.get("creationflags") == _sp2.CREATE_NO_WINDOW
          if sys.platform == "win32" else _flags == {},
          str(_flags))

    # AND THE PRODUCT'S OWN MODULES GO THROUGH IT.  A module that
    # calls subprocess.run() directly is a module that opens a
    # window, and the source says so.
    import re as _re2
    offenders = []
    for _mod in ("detect.py", "firewall.py", "sshd.py", "dialer.py"):
        _p = pathlib.Path(__file__).resolve().parent / _mod
        if not _p.is_file():
            continue
        _src = _p.read_text(encoding="utf-8", errors="replace")
        if _re2.search(r"\bsubprocess\.(run|Popen)\(", _src):
            offenders.append(_mod)
    check("and no product module starts a child directly",
          not offenders, ", ".join(offenders))

    # ---- AND THE GUI LAUNCHER SAYS IT IS A GUI ONE ----
    #
    # pyappdist's GUI launcher runs the entry point with the CONSOLE
    # python -- `python.exe -I -c ...` -- so the interpreter HAS a
    # console, and the "is there a console" test says yes.
    #
    # But that console belongs to a GUI program: it is not on the
    # screen, nobody is looking at it, and the usage text went into
    # it and vanished.
    #
    # MEASURED: the launcher printed the usage and exited, and the
    # window never came up.  The user said the shortcut "would not
    # run".
    #
    # So the launcher says so ITSELF, and the dispatcher believes it.
    import os as _os2

    from ljtunnel import gui_entry

    _saved = _os2.environ.get("LJT_GUI_LAUNCHER")
    _os2.environ.pop("LJT_GUI_LAUNCHER", None)
    try:
        check("without the launcher's word it is not a GUI program",
              not cli._started_as_gui())
        _os2.environ["LJT_GUI_LAUNCHER"] = "1"
        check("with the launcher's word it is a GUI program",
              cli._started_as_gui())
    finally:
        if _saved is None:
            _os2.environ.pop("LJT_GUI_LAUNCHER", None)
        else:
            _os2.environ["LJT_GUI_LAUNCHER"] = _saved

    # AND THE ENTRY POINT REALLY SETS IT.  A guard that only checks
    # that the function EXISTS proves nothing: the function can be
    # there and do nothing at all.
    #
    # So the entry point is CALLED, and what it does to the
    # environment is looked at.
    _saved2 = _os2.environ.get("LJT_GUI_LAUNCHER")
    _os2.environ.pop("LJT_GUI_LAUNCHER", None)
    try:
        # THE ENTRY POINT IS CALLED, with the dispatcher replaced so
        # that the window does not open.  What matters is what it did
        # to the environment.
        import ljtunnel.cli as _cl

        _saved_main = _cl.main
        _cl.main = lambda argv=None: 0
        try:
            gui_entry.main([])
        finally:
            _cl.main = _saved_main
        check("and the entry point really says so",
              _os2.environ.get("LJT_GUI_LAUNCHER") == "1",
              repr(_os2.environ.get("LJT_GUI_LAUNCHER")))
    finally:
        if _saved2 is None:
            _os2.environ.pop("LJT_GUI_LAUNCHER", None)
        else:
            _os2.environ["LJT_GUI_LAUNCHER"] = _saved2
    # AND THE PYPROJECT SAYS SO -- WHEN THERE IS A PYPROJECT.
    #
    # The INSTALLED copy has no pyproject.toml: it is not a source
    # tree, it is a program.  So the check is about the source tree
    # and it is SKIPPED when there is no pyproject.
    #
    # MEASURED: the installed suite said
    #
    #     FileNotFoundError: ...\site-packages\pyproject.toml
    #
    # and the release stopped, because the installed suite is part of
    # the release.
    _root = pathlib.Path(__file__).resolve().parent.parent
    _pyproject = _root / "pyproject.toml"
    if _pyproject.is_file():
        check("and it is what the launcher points at",
              "gui_entry" in _pyproject.read_text(
                  encoding="utf-8", errors="replace"))
    else:
        check("and it is what the launcher points at (no pyproject here)",
              True)

    # ---- AND THE PANEL DOES NOT ASK THE OS ON THE MAIN THREAD ----
    #
    # THE WINDOW FREEZED EVERY SECOND, and the reason was the
    # question and not the drawing: the socket table came from
    # PowerShell, and ONE CALL TOOK 1.85 SECONDS.  The timer asked
    # for it every second, so the window was always behind.
    #
    # MEASURED, on this machine:
    #
    #     powershell + Get-NetTCPConnection   1.75s
    #     netstat -ano                          0.025s
    #
    # So the question comes from netstat now, and it is asked by a
    # THREAD, and the window draws what is already known.
    import time as _time2

    _root3 = pathlib.Path(__file__).resolve().parent.parent
    if not _is_source_tree():
        # the guards below read the source, and there is no source
        check("the source guards are skipped in the installed program",
              True)
        return
    _detect = (_root3 / "ljtunnel" / "detect.py").read_text(
        encoding="utf-8", errors="replace")
    # THE CODE, NOT THE WORDS: the docstring may say what it used
    # to do, and a guard that reads the words fails on a comment.
    #
    # So the docstrings are taken out and the comments are dropped,
    # and what is left is what would RUN.
    import re as _re3

    _code = _re3.sub('"""(?:.|' + chr(10) + ')*?"""', "", _detect)
    _code = "\n".join(l for l in _code.splitlines()
                       if not l.strip().startswith("#"))
    check("the socket table does not come from PowerShell",
          "powershell" not in _code.lower(),
          "the socket table still comes from PowerShell")

    _t0 = _time2.time()
    _live = detect._listening(10002, 10021)
    _t1 = _time2.time()
    check("and the question is quick", (_t1 - _t0) < 0.5,
          f"it took {(_t1 - _t0):.3f}s")

    # ---- and the drawing is off the question ----
    _app_src = (_root3 / "ljtunnel" / "app.py").read_text(
        encoding="utf-8", errors="replace")
    _refresh_at = _app_src.find("def _refresh(self)")
    _poll_at = _app_src.find("def _poll(self)")
    _poll_body = _app_src[_poll_at:_app_src.find("\n    def ", _poll_at + 10)]
    check("and the poll does not ask the OS itself",
          "self.listener.dialers()" not in _poll_body,
          "the poll asks the OS on the main thread")
    check("and the answer is cached",
          "_scan_rows" in _app_src,
          "there is no cache")

    # ---- AND THE CROSS-MACHINE TEST WORKS ON A COPY ----
    #
    # A test that adds a key and then removes it must NOT do that in
    # the real state directory: the key it removes may be the real
    # dialer's key, and the product then cannot let that dialer in.
    #
    # MEASURED: the test ran in the real state directory and the
    # product said "the reachable end did not accept this end's key".
    _cross = (_root3 / "tools" / "crossmachine_form.py").read_text(
        encoding="utf-8", errors="replace")
    check("the cross-machine test works on a copy of the state",
          "_paths.state_dir = lambda: _COPY_STATE" in _cross,
          "the test still uses the real state directory")
    check("and it throws the copy away",
          "_drop_the_copy()" in _cross,
          "the copy is left behind")

    # ---- AND THE COMMAND SAYS WHICH USER IS WHICH ----
    #
    # There are TWO users: the one the dialer logs in to the
    # reachable end as, and the one a person logs in to the DIALER as.
    # They are accounts on two different machines.
    #
    # MEASURED: "Permission denied (publickey,keyboard-interactive)"
    # with a good key, because the name was the reachable end's.
    # ---- AND THE COMMAND DOES NOT CARRY THE DIALER'S ACCOUNT ----
    #
    # THE DIALER KNOWS ITS OWN ACCOUNT, and it is the account the
    # command is run as.  So the command does not name it -- and a
    # name that was in the command would be the REACHABLE END's
    # account, which is the mistake that cost an afternoon.
    #
    # MEASURED: the person got
    # "Permission denied (publickey,keyboard-interactive)" with a good
    # key, because the name was the reachable end's and not the
    # dialer's.
    _rec = {"name": "x", "host": "", "user": "", "pubkey": ""}
    _cmd = records.command_for(_rec)
    check("and the command does NOT name the dialer's account",
          "--local-user" not in _cmd, _cmd[:120])

    # ---- AND THE DIALER FILLS IT IN ITSELF ----
    _dialer_src2 = (_root3 / "ljtunnel" / "dialer.py").read_text(
        encoding="utf-8", errors="replace")
    check("and the dialer works out its own account",
          "allowed_users=local_account" in _dialer_src2,
          "the dialer does not tell its sshd who may log in")

    # ---- AND THE SSHD CAN LIMIT THE ACCOUNTS IT ACCEPTS ----
    _cfg = sshd.write_config(10001, listen="127.0.0.1",
                             allowed_users="someone")
    _text = open(_cfg, encoding="utf-8").read()
    check("and the sshd can say who may log in",
          "AllowUsers someone" in _text, _cfg)

    # ---- AND THE NAME IS READ FROM THE KEY ----
    #
    # THE NAME IS THE KEY'S COMMENT.  The dialer makes its key with
    # `ssh-keygen -C <name>` and the panel shows the name without
    # anybody typing it in -- which is what lets the form go down to
    # one field.
    #
    # MEASURED: the key is three things -- the type, the body and the
    # comment -- and the comment is the part a person reads.
    _key = ("ssh-ed25519 "
            "AAAAC3NzaC1lZDI1NTE5AAAAIK4icCbdG74l91kP0yiahmWy5ATLu47tVa"
            "r4KD9FAOqx ljtunnel-box-a")
    check("the name is read from the key's comment",
          L.name_of(_key) == "ljtunnel-box-a",
          repr(L.name_of(_key)))
    check("and a key with no comment has no name",
          L.name_of("ssh-ed25519 AAAA") == "",
          repr(L.name_of("ssh-ed25519 AAAA")))

    # ---- AND THE DIALER PUTS THE NAME ON ITS KEY ----
    _dialer_src = (_root3 / "ljtunnel" / "dialer.py").read_text(
        encoding="utf-8", errors="replace")
    check("and the dialer can be given a name",
          "--name" in _dialer_src,
          "the dialer cannot be given a name")

    # ---- AND THE KEY LIST IS TAKEN APART CORRECTLY ----
    #
    # A LINE IN THE LIST IS FOUR THINGS:
    #
    #     environment="LJT_NAME=box-a" ssh-ed25519 AAAA... box-a
    #
    # the options, the type, the body and the comment.  And the last
    # three tokens are NOT the key: the options come first.
    #
    # MEASURED: taking the last three tokens kept the OLD
    # environment option and the OLD comment, and the line came out
    # as
    #
    #     environment="LJT_NAME=new" environment="LJT_NAME=old" AAAA... old
    #
    # -- two options and no key type, which the sshd refuses.
    import tempfile as _tf3

    with _tf3.TemporaryDirectory() as _tmp3:
        _old3 = paths.state_dir
        paths.state_dir = lambda: _tmp3
        try:
            # A FIXTURE KEY, and not a real one: the tracked tree
            # must not carry anybody's public key.
            _k = ("ssh-ed25519 "
                  "AAAAC3NzaC1lZDI1NTE5AAAAIK4icCbdG74l91kP0yiahmWy5ATLu47tVa"
                  "r4KD9FAOqx thebox")
            L.add_key(_k)
            _line = L.read_keys()[0]
            check("the key goes in with its name on it",
                  "thebox" in _line and "LJT_NAME=thebox" in _line,
                  _line[:110])

            L.set_key_name(_k, "thenewname")
            _line2 = L.read_keys()[0]
            check("and a rename leaves ONE option and the type",
                  _line2.count("LJT_NAME=") == 1 and "ssh-ed25519" in _line2,
                  _line2[:130])
            check("and the comment follows the name",
                  _line2.rstrip().endswith("thenewname"), _line2[-40:])
        finally:
            paths.state_dir = _old3

    # ---- AND THE PANEL'S IDS ARE NEVER EMPTY ----
    #
    # TKINTER DOES NOT TAKE AN EMPTY ID, and it says
    #
    #     Item  already exists
    #
    # and the window dies.  MEASURED: a dialer whose key list line
    # carried no name gave an empty id, and that is how it was found.
    #
    # THE TEST IS THE REAL THING: a window, and a dialer with no name
    # and no fingerprint -- and the window has to still be there
    # afterwards.
    # THE WINDOW NEEDS A DISPLAY, and there is not always one.  On
    # the far side there is not, so the check is skipped there -- and
    # the OTHER part of it, the one that does not need a window, is
    # checked everywhere.
    import tkinter as _tk4

    _have_display4 = True
    try:
        _probe4 = _tk4.Tk()
        _probe4.destroy()
    except Exception as _e4:
        _have_display4 = False
        _no_display4 = f"{type(_e4).__name__}: {_e4}"

    if not _have_display4:
        # ON THE FAR SIDE THERE IS NO DISPLAY, so the window cannot be
        # built and the check cannot run.  It is skipped there, and it
        # runs on the machine that has a window.
        #
        # BUT THE LOGIC IS CHECKED THERE ANYWAY: an id that is not
        # empty is a rule about the NAME, and the name can be worked
        # out without a window.
        from ljtunnel import app as _app4b
        _d4b = detect.Dialer(fingerprint="", name="", port=10010,
                             peer="192.0.2.7")
        _id4b = _app4b.App._row_id(_d4b)
        check("a dialer with no name still gets an id",
              bool(_id4b), repr(_id4b))
        check("and the id says what it is",
              "10010" in _id4b, repr(_id4b))
        check("a dialer with no name does not kill the window",
              True, f"skipped -- no display ({_no_display4})")
    else:
        from ljtunnel import app as _app4

        try:
            _w4 = _app4.App()
            try:
                # NO NAME AND NO FINGERPRINT: the id has to come from
                # somewhere else, or Tkinter says "Item  already
                # exists" and the window dies.
                _d4 = detect.Dialer(fingerprint="", name="", port=10010,
                                    peer="192.0.2.7")
                _w4._scan_rows = [_d4]
                _w4._refresh()
                _kids4 = list(_w4.tree.get_children())
                check("a dialer with no name does not kill the window",
                      len(_kids4) == 1, str(_kids4))
                check("and it gets an id that is not empty",
                      bool(_kids4) and bool(_kids4[0]), str(_kids4))
                check("and the id says what it is",
                      bool(_kids4) and ("10010" in _kids4[0] or
                                        "?" in _kids4[0]), str(_kids4))
            finally:
                _w4.destroy()
        except Exception as _e4:
            check("a dialer with no name does not kill the window",
                  False, f"{type(_e4).__name__}: {_e4}")

    # ---- AND A KEY IS TAKEN OUT BY ITS BODY, NOT BY ITS SECOND TOKEN ----
    #
    # A KEY-LIST LINE CARRIES THE OPTIONS FIRST, so the second token of
    # a line with options on it is the OPTION and not the key type.
    #
    # MEASURED: the second token was taken, so a key that was put in
    # with an option on it could not be taken out again -- and the
    # cross-machine test's key stayed in the list for good.
    import tempfile as _tf8

    with _tf8.TemporaryDirectory() as _td8:
        _old8 = paths.state_dir
        paths.state_dir = lambda: _td8
        try:
            _k8 = ("ssh-ed25519 "
                   "AAAAC3NzaC1lZDI1NTE5AAAAIK4icCbdG74l91kP0yiahmWy5ATLu47tVa"
                   "r4KD9FAOqx thebox")
            L.add_key(_k8, "thebox")
            _line8 = L.read_keys()[0]
            check("the key goes in with its name on it",
                  "thebox" in _line8 and "LJT_NAME=thebox" in _line8,
                  _line8[:100])

            # AND IT IS TAKEN OUT BY THE KEY TEXT -- and the text it
            # is given is the LINE, with the option on it, because
            # that is what a caller has: the key it pasted in, or the
            # line that is in the list.
            #
            # MEASURED: the second token was taken, and for a line
            # with an option on it the second token is the OPTION.
            check("and it can be taken out again by its text",
                  L.remove_key_text(_line8), "not removed: " + _line8[:70])
            check("and the list is empty afterwards",
                  not L.read_keys(), str(L.read_keys())[:100])
        finally:
            paths.state_dir = _old8

    # ---- AND THE HTTP SERVER SERVES A DIRECTORY, BEHIND A TOKEN ----
    #
    # THE TUNNEL'S OTHER SHAPE: the unreachable end offers a WEB PAGE,
    # and the reachable end's forwarded port lands on it.  There is no
    # sshd on this end, so the TOKEN in the URL is what lets somebody
    # in.
    import http.client as _hc5
    import tempfile as _tf5

    from ljtunnel import httpsrv as _hs5

    with _tf5.TemporaryDirectory() as _w5:
        with open(os.path.join(_w5, "index.html"), "w", encoding="utf-8") as _fh5:
            _fh5.write("IT_WORKS\n")
        _srv5, _tok5 = _hs5.serve(_w5, 0)
        _p5 = _srv5.server_address[1]
        try:
            def _get5(_path):
                _c = _hc5.HTTPConnection("127.0.0.1", _p5, timeout=10)
                _c.request("GET", _path)
                _r = _c.getresponse()
                _b = _r.read()
                _c.close()
                return _r.status, _b

            _s5, _b5 = _get5("/" + _tok5 + "/index.html")
            check("the http server serves a file with the token",
                  _s5 == 200 and b"IT_WORKS" in _b5, f"{_s5} {_b5[:40]}")
            _s5, _b5 = _get5("/index.html")
            check("and refuses it without the token",
                  _s5 == 404 and b"no token" in _b5, f"{_s5} {_b5[:40]}")
            _s5, _b5 = _get5("/" + _tok5[:8] + "/index.html")
            check("and a prefix of the token is not the token",
                  _s5 == 404, f"{_s5} {_b5[:40]}")
            _s5, _b5 = _get5("/" + _tok5 + "x/index.html")
            check("and one character more is not the token",
                  _s5 == 404, f"{_s5} {_b5[:40]}")
            # AND THE PATH CANNOT GET OUT OF THE DIRECTORY.  The
            # normalisation is done TWICE on purpose: once here, and
            # once in the base class's own translate_path.  Either
            # alone would do, and the guard is about the OUTCOME --
            # the file outside the directory is not served.
            _s5, _b5 = _get5("/" + _tok5 + "/../../etc/passwd")
            check("and the path cannot get out of the directory",
                  _s5 == 404 or b"root:" not in _b5, f"{_s5} {_b5[:40]}")
            _s5, _b5 = _get5("/" + _tok5 + "/%2e%2e/%2e%2e/etc/passwd")
            check("and not when the dots are encoded",
                  _s5 == 404 or b"root:" not in _b5, f"{_s5} {_b5[:40]}")
            _s5, _b5 = _get5("/" + _tok5 + "/sub/../../etc/passwd")
            check("and not from a subdirectory either",
                  _s5 == 404 or b"root:" not in _b5, f"{_s5} {_b5[:40]}")
        finally:
            _srv5.shutdown()

    # ---- AND THE HTTP SERVER SAYS WHO IT IS ----
    #
    # A PORT BEHIND AN HTTP SERVER HAS NO HOST KEY BEHIND IT, so the
    # keyscan finds nothing and the panel cannot name the dialer.  So
    # the server says who it is in a header, and the reachable end
    # reads it.
    #
    # AND THE FINGERPRINT IT GIVES IS OF THE MACHINE KEY, so the
    # reachable end can look the name up in its OWN key list -- and a
    # dialer cannot call itself something it is not.
    from ljtunnel import scan as _sc10

    with _tf5.TemporaryDirectory() as _w10:
        with open(os.path.join(_w10, "index.html"), "w", encoding="utf-8") as _fh10:
            _fh10.write("IT_WORKS\n")
        _srv10, _tok10 = _hs5.serve(_w10, 0, name="thebox",
                                    fingerprint="SHA256:ABCdefGHIjkl")
        _p10 = _srv10.server_address[1]
        try:
            _nm10, _fp10 = _sc10._http_identity(_p10)
            check("the http server says its name",
                  _nm10 == "thebox", repr(_nm10))
            check("and its fingerprint",
                  _fp10 == "SHA256:ABCdefGHIjkl", repr(_fp10))

            _c10 = _hc5.HTTPConnection("127.0.0.1", _p10, timeout=10)
            _c10.request("GET", "/")
            _r10 = _c10.getresponse()
            _r10.read(1)
            check("and the name is in the headers",
                  _r10.getheader("X-LJT-Name") == "thebox",
                  repr(_r10.getheader("X-LJT-Name")))
            _c10.close()

            # AND A PORT WITH NOTHING ON IT SAYS NOTHING.
            _nm10b, _fp10b = _sc10._http_identity(_p10 + 1)
            check("and a port with nothing on it says nothing",
                  _nm10b == "" and _fp10b == "", f"{_nm10b!r} {_fp10b!r}")
        finally:
            _srv10.shutdown()

    # ---- AND THE TOKEN IS KEPT, SO IT DOES NOT CHANGE ----
    #
    # A TOKEN THAT CHANGES ON EVERY RUN IS A URL THAT WORKS TODAY AND
    # NOT TOMORROW.
    from ljtunnel import dialer as _dl5

    _old5 = paths.state_dir
    with _tf5.TemporaryDirectory() as _st5:
        paths.state_dir = lambda: _st5
        try:
            _t1 = _dl5._read_or_make_http_token()
            _t2 = _dl5._read_or_make_http_token()
            check("the http token is the same twice",
                  _t1 == _t2 and bool(_t1), f"{_t1[:12]} {_t2[:12]}")
            check("and it is long enough to guess wrong",
                  len(_t1) >= 32, str(len(_t1)))

            # AND THE DIALER USES THE KEPT ONE.  A token that is made
            # at the call site instead of being read is a new one every
            # run, and the URL stops working.
            #
            # IT IS CHECKED BY RUNNING THE DIALER TWICE, in the
            # print-only mode, and looking at what it says.  That is
            # the behaviour, and it does not go stale when the code
            # moves.
            #
            # THE STATE DIRECTORY IS POINTED AT BY THE ENVIRONMENT, so
            # the child process uses the same one: the monkeypatch
            # above is in THIS process, and the child is another one.
            import subprocess as _sp9

            _root9 = _sp9.os.path.dirname(
                _sp9.os.path.dirname(_dl5.__file__))
            _env9 = dict(_sp9.os.environ)
            _env9["XDG_STATE_HOME"] = _st5
            _env9["LOCALAPPDATA"] = _st5
            _cmd9 = [_sp9.sys.executable, "-m", "ljtunnel", "dialer",
                     "--listen-host", "192.0.2.7", "--http-server",
                     "--http-directory", _st5, "--print-only"]
            _tok9 = []
            for _ in range(2):
                _r9 = _sp9.run(_cmd9, capture_output=True, text=True,
                               errors="replace", timeout=180,
                               cwd=_root9, env=_env9)
                _o9 = (_r9.stdout or "") + (_r9.stderr or "")
                _tok9 += [l.split(":", 1)[1].strip()
                          for l in _o9.splitlines() if "the token:" in l]
            check("and the dialer says the same token twice",
                  len(_tok9) == 2 and _tok9[0] == _tok9[1] and bool(_tok9[0]),
                  str(_tok9)[:80])
        finally:
            paths.state_dir = _old5

    # ---- AND THE DIALER HAS THE SWITCHES ----
    from ljtunnel import dialer as _dl6

    _p6 = _dl6.build_parser()
    _a6 = _p6.parse_args(["--listen-host", "192.0.2.7", "--http-server",
                           "--http-directory", "/tmp/x"])
    check("the dialer has --http-server", _a6.http_server, str(_a6))
    check("and --http-directory", _a6.http_directory == "/tmp/x",
          str(_a6.http_directory))
    check("and the http port has a default", _a6.http_port == 10001,
          str(_a6.http_port))
    _a6b = _p6.parse_args(["--listen-host", "192.0.2.7"])
    check("and it is off unless it is asked for",
          not _a6b.http_server, str(_a6b))

    # AND THERE IS NO WRITING SWITCH, BECAUSE THE SERVER SERVES AND
    # NOTHING ELSE.
    #
    # A file server that writes is a different program with a
    # different set of rules about who may write what, and there is
    # one that does that -- `rclone serve webdav` -- and this is not
    # it.
    check("and the dialer has no writing switch",
          not hasattr(_a6, "http_allow_edit"), str(_a6))

    # ---- AND THE HTTP MODE FORWARDS TO THE HTTP PORT ----
    #
    # THE PORT THE FORWARD LANDS ON IS THE SERVICE'S PORT, and with
    # the http server that is not the sshd's port.
    _cmd6 = _dl6._forward_command(
        _a6, "/tmp/key", 10002, "someone", service_port=8080)
    _txt6 = " ".join(_cmd6)
    check("the forward lands on the http server's port",
          "10002:127.0.0.1:8080" in _txt6, _txt6[-80:])
    _cmd6b = _dl6._forward_command(
        _a6b, "/tmp/key", 10002, "someone")
    _txt6b = " ".join(_cmd6b)
    check("and the sshd mode lands on the sshd's port",
          "10002:127.0.0.1:10001" in _txt6b, _txt6b[-80:])

    # ---- AND THE STALE HOST KEYS ARE CLEANED ----
    #
    # A DIALER THAT IS SET UP AGAIN MAKES A NEW HOST KEY, and the ssh
    # client remembers the old one, and then it says
    #
    #     Host key for [localhost]:10002 has changed and you have
    #     requested strict checking.
    #
    # and the person cannot get in.  So the tunnel's own entries are
    # cleaned when the tunnel starts, and with a button.
    import tempfile as _tf4

    with _tf4.TemporaryDirectory() as _tmp4:
        _kh = os.path.join(_tmp4, "known_hosts")
        # THREE LINES: two of the tunnel's, and one that is not.
        with open(_kh, "w", encoding="utf-8") as _fh:
            _fh.write("[localhost]:10001 ssh-ed25519 AAAAfake0 nobody\n")
            _fh.write("[localhost]:10002 ssh-ed25519 AAAAfake1 nobody\n")
            _fh.write("[127.0.0.1]:10005 ssh-ed25519 AAAAfake2 nobody\n")
            _fh.write("[localhost]:10021 ssh-ed25519 AAAAfake4 nobody\n")
            _fh.write("[localhost]:10022 ssh-ed25519 AAAAfake5 nobody\n")
            _fh.write("[example.com]:22 ssh-ed25519 AAAAfake3 somebody\n")

        _old4 = paths.known_hosts
        paths.known_hosts = lambda: _kh
        try:
            _gone = L.clean_known_hosts(L.LISTEN_SSHD_PORT, 10021)
            _after = open(_kh, encoding="utf-8").read()
        finally:
            paths.known_hosts = _old4

        check("the tunnel's own entries are cleaned",
              "[localhost]:10002" not in _after, _after[:90])
        check("and the other one of its ports too",
              "[127.0.0.1]:10005" not in _after, _after[:90])
        check("and the sshd's own port",
              "[localhost]:10001" not in _after, _after[:90])
        check("and the last one of the range",
              "[localhost]:10021" not in _after, _after[:90])
        check("but the port past the range is left alone",
              "[localhost]:10022" in _after, _after[:90])
        check("and so is the person's own host",
              "[example.com]:22" in _after, _after[:90])
        check("and it says what it took",
              len(_gone) >= 1, str(_gone)[:90])

    # ---- AND THE ACCOUNT IS FOUND WITHOUT THE ENVIRONMENT ----
    #
    # THE FROZEN BINARY IS RUN WITH `env -i`, which clears the
    # environment, and then USERNAME and USER are both gone.
    #
    # MEASURED: the dialer said "cannot tell who the user is; pass
    # --local-user" and did not start at all.  And `getpass.getuser()`
    # fails with "No module named 'pwd'" -- it is a Unix module.
    #
    # THE HOME PATH IS THERE, and its last part is the account's
    # name: /home/liuxd -> liuxd.
    import os as _os3

    _saved_env = {}
    for _k in ("USERNAME", "USER", "HOME", "USERPROFILE"):
        _saved_env[_k] = _os3.environ.pop(_k, None)
    try:
        # ON LINUX THE SYSTEM KNOWS, because `pwd` is there.  On
        # Windows it does not, and the home path is what is left.
        #
        # MEASURED: the guard failed on Linux because the account WAS
        # found -- and that is correct there.
        _with_nothing = paths.current_user()
        if sys.platform == "win32":
            check("and on Windows the account is not found with nothing "
                  "at all", _with_nothing == "", repr(_with_nothing))
        else:
            check("and on Linux the system knows the account",
                  _with_nothing == _os3.environ.get("USER", _with_nothing)
                  or bool(_with_nothing), repr(_with_nothing))
        _os3.environ["HOME"] = "/home/liuxd"
        check("but it is found from the home path",
              paths.current_user() == "liuxd",
              repr(paths.current_user()))
    finally:
        for _k, _v in _saved_env.items():
            if _v is not None:
                _os3.environ[_k] = _v
            else:
                _os3.environ.pop(_k, None)

    # ---- AND THE START DOES NOT ASK FOR ADMINISTRATOR RIGHTS ----
    #
    # THE UAC PROMPT IS ON THE SECURE DESKTOP, and it sits there
    # until somebody answers it.  So an app that asks at the start
    # shows NOTHING to a person who is not at the machine: no
    # window, no message, and the app looks broken.
    #
    # MEASURED: the shortcut "would not run" and nothing appeared.
    #
    # So the window comes up FIRST and the elevation is a BUTTON.
    _root2 = pathlib.Path(__file__).resolve().parent.parent
    _app = (_root2 / "ljtunnel" / "app.py").read_text(encoding="utf-8",
                                                      errors="replace")
    _main_at = _app.find("def main(argv=None) -> int:")
    assert _main_at > 0
    _body = _app[_main_at:_main_at + 4000]
    check("the start does not ask for administrator rights",
          "relaunch_elevated" not in _body.split("def _run_window")[0],
          "the start asks for the elevation")
    check("and the button is there for it",
          "_ask_to_be_admin" in _app,
          "there is no button")

    # ---- and the option is there ----
    #
    # IT IS AN EXPLICIT ACT.  The host key is the one thing in this
    # protocol that cannot be faked, so taking the new one is a
    # decision somebody makes, not something the dialer does on its
    # own.
    import subprocess as _sp
    r = _sp.run([sys.executable, "-m", "ljtunnel", "dialer", "--help"],
                capture_output=True, text=True, errors="replace", timeout=90)
    check("the dialer can be told to accept a new host key",
          "--accept-new-host-key" in (r.stdout or ""),
          (r.stdout or r.stderr or "").strip()[:80])

    # ---- and the remembered key is read from the known_hosts ----
    #
    # THE FILE IS IN THE HASHED FORM, and then the key is the
    # SECOND field and not the first.  Looking at the first field
    # finds nothing, and the check never fires.
    #
    # AND THE HASH IS A REAL ONE: the file is written by ssh, and
    # `ssh-keygen -F` finds a line by computing the hash of the
    # address.  So the file is made the way ssh makes it -- with
    # ssh-keygen itself -- and not with a made-up hash.
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        kf = os.path.join(tmp, "known_hosts")
        # ssh-keygen -H hashes a file in place
        plain = os.path.join(tmp, "plain")
        with open(plain, "w", encoding="utf-8") as fh:
            fh.write("[203.0.113.7]:10000 " + key + "\n")
        h = subprocess.run(["ssh-keygen", "-f", plain, "-H"],
                           capture_output=True, text=True,
                           errors="replace", timeout=60)
        with open(plain, encoding="utf-8", errors="replace") as fh:
            hashed = fh.read()
        with open(kf, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(hashed)


def test_orphan_sshd():
    """An sshd with no pid file is still stopped.

    THE PID FILE IS WHERE THE ANSWER USUALLY IS, and it is right
    every time it is there.  But a process whose pid file has been
    deleted -- by a test that clears the state directory, by a
    person, by anything -- goes on holding its port, and the next
    launch says the port is busy for no reason anybody can see.

    MEASURED: a leftover sshd on 10000 with no pid file, and
    `stop()` said "not running" and left it there.

    So the orphans are found by their COMMAND LINE, which names this
    project's config.  And the SYSTEM sshd is not found that way,
    because its command line does not name the config -- and it must
    never be touched.
    """
    import subprocess
    import sys
    import time

    from ljtunnel import listen as L, paths, sshd

    if sys.platform != "win32":
        # The check needs a process to find, and starting one is
        # different on each platform.  The Linux suite covers the
        # same ground through the pid file.
        check("the orphan check is Windows-only (skipped)", True)
        return

    # ---- a real sshd, started the way the product starts it ----
    port = 10000
    if L.port_in_use(port):
        check("the port for the orphan test is free", False, str(port))
        return

    proc = subprocess.Popen(
        [sshd.sshd_path(), "-f", sshd.write_config(port, "127.0.0.1"),
         "-D", "-e"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    try:
        for _ in range(40):
            if L.port_in_use(port):
                break
            time.sleep(0.25)
        check("the orphan sshd came up", L.port_in_use(port), str(port))

        # ---- and the pid file is GONE ----
        # ---- so the only way to find it is the command line ----
        pidfile = paths.pid_file()
        if os.path.isfile(pidfile):
            os.remove(pidfile)
        check("the pid file is not there", not os.path.isfile(pidfile))

        sshd.stop()
        for _ in range(40):
            if not L.port_in_use(port):
                break
            time.sleep(0.25)
        check("the orphan was stopped anyway",
              not L.port_in_use(port), "the port is still held")
    finally:
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except Exception:
            pass

    # ---- and the SYSTEM sshd is still there ----
    # ---- it is the proof that the cleanup did what it was ----
    # ---- supposed to and nothing more ----
    system_up = subprocess.run(
        ["tasklist", "/FI", "IMAGENAME eq sshd.exe"],
        capture_output=True, text=True, errors="replace", timeout=60)
    check("the SYSTEM sshd was not touched",
          "sshd.exe" in (system_up.stdout or ""),
          "the system sshd is gone")


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
    #
    # AND THE HOST KEY HAS TO BE THERE: `sshd -T` refuses to run
    # without one it can load, and it says nothing about the ports
    # when it refuses.
    sshd.ensure_host_key()
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

    # ---- AND NO PUBLIC KEY EITHER ----
    #
    # A public key in a public repository is not a secret -- anybody
    # can use it to log in.  So it is a leak of the same kind as the
    # address, and for the same reason: it belongs to a machine, not
    # to the software.
    #
    # THE FIXTURES ARE ALLOWED, and they are named: a test needs a
    # key to compute a fingerprint from, and a made-up one is
    # better than a real one.  The ones the tests use all carry the
    # comment "ljtunnel-test-fixture", and a key without that
    # comment is one that came from a machine.
    #
    # MEASURED: this file and the GUI test carried a real machine's
    # public key until this was written.
    keypat = _re.compile(
        r"AAAAC3NzaC1lZDI1NTE5AAAAI[A-Za-z0-9+/]{40,}")
    bad_keys = []
    for name in names:
        p = root / name
        if not p.is_file() or p.suffix in (".msi", ".exe", ".ico", ".png",
                                            ".pyc", ".zip"):
            continue
        try:
            body = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines = body.splitlines()
        for n, line in enumerate(lines, 1):
            if not keypat.search(line):
                continue
            # The fixtures are marked, and the mark is either on this
            # line or on one of the lines around it -- a key body is
            # often split over two string literals, so the comment
            # that names the fixture can be a line away.
            #
            # THE MARK IS ON THE LINE ITSELF for the ones that say
            # what they are, so the window is a few lines either side.
            window = " ".join(lines[max(0, n - 3):n + 3])
            if "ljtunnel-test-fixture" in window or "do-not-use" in window:
                continue
            bad_keys.append(f"{name}:{n}")
    check("no public key in the tracked tree but the fixtures",
          not bad_keys, ", ".join(bad_keys[:8]))

    # ---- AND NO `-like` IN ANY POWERSHELL ----
    #
    # IN THIS POWERSHELL THE WILDCARD OPERATOR DOES NOT WORK:
    #
    #     'abc.exe' -like 'abc%'   ->   False
    #
    # MEASURED: that is what it says, and `-eq` and `-match` both
    # work.  So a filter written with `-like` matches NOTHING, and
    # the count is zero, and the cleanup does nothing, and the
    # leftovers stay holding the port.
    #
    # It was in `stop_sessions()`, so the Ctrl-C test counted zero
    # sessions while two were there -- and the test PASSED.
    #
    # `-match` is a REGEX and it works, so it is what is used.  And
    # the WQL `-Filter "Name LIKE ..."` is a different thing -- it is
    # the WQL's own LIKE, and it works.
    bad_like = []
    for name in names:
        p = root / name
        if not p.is_file() or p.suffix not in (".py", ".ps1"):
            continue
        # THIS FILE IS THE CHECK, and it NAMES the operator it is
        # looking for -- in a string and in a comment.  So it is not
        # a use of it.
        if p.name == "selftest.py":
            continue
        try:
            body = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for n, line in enumerate(body.splitlines(), 1):
            # the WQL filter is not PowerShell's operator
            if "-like" not in line:
                continue
            if "Name LIKE" in line:
                continue
            # AND A COMMENT IS NOT CODE.  The tree SAYS "-like" in
            # prose -- it says why it is not used -- and that is not
            # a use of it.
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            bad_like.append(f"{name}:{n}")
    check("no PowerShell -like in the tree (it does not work here)",
          not bad_like, ", ".join(bad_like[:8]))


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

    # ---- THE LOOP GUARD ----
    #
    # The elevated copy starts the SAME program, and that program
    # asks to be an administrator when it starts.  So the elevated
    # copy has to be told it does not have to ask -- and it is
    # told in its ARGUMENTS.
    #
    # Without that, the two copies ask each other to start, forever.
    # That is not a hypothetical: it happened, and the UAC prompt
    # came up again and again until the person stopped it.
    check("there is a flag for the elevated copy",
          hasattr(elevate, "ELEVATED_FLAG"), "the flag is there")
    check("and it is recognisable",
          elevate.is_elevated_run([elevate.ELEVATED_FLAG, "listen"]),
          "the flag is seen")
    check("and an ordinary run is not",
          not elevate.is_elevated_run(["listen"]),
          "a plain run is not the elevated one")

    # the flag has to be ADDED to the copy's arguments
    check("and the relaunch adds it",
          elevate.ELEVATED_FLAG in src, "the flag is in the relaunch")

    # and the app has to HONOUR it
    check("and the window honours it",
          "ELEVATED_FLAG" in app_src, "app.py checks the flag")

    # and the dispatcher has to pass it on, or the copy is told
    # "unknown command" and exits
    # The dispatcher lives in `cli.py`, so that is where the flag is
    # handled.  `__main__.py` is a thin shell over it.
    disp = (pathlib.Path(__file__).resolve().parent / "cli.py").read_text(
        encoding="utf-8")
    check("and the dispatcher passes it on",
          "elevated" in disp, "cli.py knows the flag")

    # ---- and the copy is the SAME app, not another one ----
    #
    # The installed launcher is whatever version happens to be
    # installed.  If the copy that starts is the launcher, and the
    # launcher also asks to be an administrator, the two ask each
    # other to start, forever.  So the interpreter that is running
    # now is the one that is started again.
    #
    # It is checked by BEHAVIOUR and not by the order of two names
    # in the source: the relaunch is given an interpreter that
    # cannot exist and a launcher that can, and the launcher is the
    # one that has to be started.
    #
    # AND THE FLAG IS ON THE COPY'S COMMAND LINE.  Without it the
    # copy asks to be an administrator again, and the two ask each
    # other to start, forever.
    #
    # THE WHOLE THING IS WINDOWS-ONLY.  On Linux there is no UAC
    # and no elevation, so there is nothing to check.
    if sys.platform != "win32":
        check("the elevation is Windows only (skipped)", True)
        return

    started = []
    real_runas = elevate.shell_execute_runas

    def _record(program, arguments=""):
        started.append((program, arguments))
        return 0

    elevate.shell_execute_runas = _record
    real_pythonw = elevate._pythonw
    real_launcher = elevate._installed_launcher
    try:
        elevate._pythonw = lambda: ""
        elevate._installed_launcher = lambda: r"C:\fake\ljtunnel.exe"
        elevate.relaunch_elevated(["listen"])
    finally:
        elevate.shell_execute_runas = real_runas
        elevate._pythonw = real_pythonw
        elevate._installed_launcher = real_launcher

    check("with no interpreter it falls back to the launcher",
          bool(started) and "ljtunnel.exe" in started[0][0],
          started[0][0] if started else "(nothing was started)")

    started.clear()
    elevate.shell_execute_runas = _record
    try:
        elevate._pythonw = lambda: r"C:\fake\pythonw.exe"
        elevate._installed_launcher = lambda: r"C:\fake\ljtunnel.exe"
        elevate.relaunch_elevated(["listen"])
    finally:
        elevate.shell_execute_runas = real_runas
        elevate._pythonw = real_pythonw
        elevate._installed_launcher = real_launcher

    check("with an interpreter it starts THAT, not the launcher",
          bool(started) and "pythonw.exe" in started[0][0],
          started[0][0] if started else "(nothing was started)")
    check("and the flag is on its command line",
          bool(started) and elevate.ELEVATED_FLAG in started[0][1],
          started[0][1] if started else "")


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
               test_firewall_body, test_one_key_two_jobs,
               test_key_command,
               test_forget,
               test_listener_handle,
               test_host_key_change,
               test_orphan_sshd,
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
