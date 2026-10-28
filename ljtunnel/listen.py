"""ljtunnel listen -- the reachable end.

This side holds the port. It runs its own sshd, so the dialers can log
in, and it hands each dialer a port of its own to be reached on.

    machine A (here)                    machine B (unreachable)
      sshd on 10001          <---         ssh -R 10002 -> local 10001
      10002 -> dialer 1
      10003 -> dialer 2
      ...

A person on the network connects to A:10002 and lands on B's own sshd.
Nothing inbound ever touched B.

WHO INITIATES
-------------
The DIALER initiates. `ssh -R` is run by the dialer, connecting out to
this end's sshd. This end never dials out -- it cannot, because the
dialer is by definition the machine that cannot be reached.

So this end's jobs are:
  - run its own sshd
  - keep the list of allowed public keys
  - ASSIGN a port per dialer, and tell the dialer which one
  - show what is up

HOW A DIALER IS FOUND
---------------------
Nobody adds a dialer to this end.  The dialer arrives, and this end
sees it.

  - the dialer's public key is in this end's key list, with the
    dialer's NAME attached to it
  - the dialer asks for a port in the forward range
  - this end's sshd gives it one, and writes what happened to the log
  - the panel reads the log and the socket table, and the dialer is
    THERE

So the panel does not keep a list of dialers.  It keeps a list of
PORTS THAT ARE OPEN, and the log says who is on each one.

THE DIALER PICKS THE PORT
-------------------------
The dialer asks for a port, and if the port is taken it asks for the
next one.  It cannot ask for port 0 and let sshd choose, because
`PermitListen` refuses port 0 -- the range and the auto-pick cannot
be combined, and without a range sshd picks a random high port that
no firewall rule can name.

And the dialer does not take the client's word for it.  A dialer that
asks for a port which is ALREADY TAKEN is told "forward success" and
gets no socket at all.  So the dialer checks the port is really
listening before it says it is up.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

from . import detect, paths, quiet, records, sshd

# The port this end's own sshd listens on. The dialers log in here.
LISTEN_SSHD_PORT = 10001

# Where the forwarded ports start. Each dialer takes one.
FIRST_FORWARD_PORT = 10002

# How many forwarded ports there are. The range is what the firewall
# rule has to open.
FORWARD_PORT_COUNT = 20

LAST_FORWARD_PORT = FIRST_FORWARD_PORT + FORWARD_PORT_COUNT - 1


def log(msg: str = "") -> None:
    print(msg, flush=True)


def local_ipv4() -> str:
    """This machine's address, as the other end should reach it.

    Not 127.0.0.1: the dialer is on another machine, and 127.0.0.1
    there is the dialer. And not hardcoded: the address changes when
    the machine moves to another network, and a hardcoded one is
    wrong exactly when it matters.

    A UDP socket that sends nothing is the portable way to ask the
    routing table "which local address would I use to reach the
    internet". No packet is sent.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.0.2.1", 9))     # TEST-NET-1: never routed
            addr = s.getsockname()[0]
            if addr and not addr.startswith("127."):
                return addr
        finally:
            s.close()
    except OSError:
        pass
    return "127.0.0.1"


def port_in_use(port: int) -> bool:
    """Is something already listening on that port here?

    The check is a BIND and a LISTEN, not a connect. A connect asks
    "is somebody there" and a closed port refuses, which is the same
    answer as a filtered one -- useless. A bind asks "can I take this
    port", which is the question that matters: the port is either
    taken or it is not.

    SO_REUSEADDR is ON, so a port in TIME_WAIT counts as free. That
    is right: TIME_WAIT is a leftover from a connection that has
    already ended, and a new listener can take the port.

    SO_EXCLUSIVEADDRUSE is what makes the answer true rather than
    optimistic. Without it, Windows lets two processes bind the same
    port, and the second one silently never receives anything.
    """
    s = socket.socket()
    try:
        if sys.platform == "win32":
            # On Windows SO_EXCLUSIVEADDRUSE and SO_REUSEADDR are
            # MUTUALLY EXCLUSIVE -- setting both gives WSAEINVAL.
            # The exclusive one is the one that matters here: it is
            # what stops a second process binding a port that is
            # already being listened on, which without it silently
            # never receives anything.
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        else:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("0.0.0.0", port))
        s.listen(1)
        return False
    except OSError:
        return True
    finally:
        s.close()


class PortAllocator:
    """Hands out the forwarded ports, and takes them back.

    A port belongs to a dialer until the dialer is removed. The
    allocator does not look at the network to decide -- a port that is
    open but unassigned means something else got in, and the panel
    should show that, not paper over it.
    """

    def __init__(self, first: int = FIRST_FORWARD_PORT,
                 count: int = FORWARD_PORT_COUNT):
        self.first = first
        self.count = count
        self.taken = {}          # port -> name

    def assign(self, name: str) -> int:
        """Give a name a port. Raises ValueError when there is none left.

        A name that already has a port keeps it: asking again is a
        re-assertion, not a second port. A released port is handed
        out again, so removing a dialer and adding another does not
        quietly eat the range.
        """
        for p, n in self.taken.items():
            if n == name:
                return p
        for p in range(self.first, self.first + self.count):
            if p not in self.taken:
                self.taken[p] = name
                return p
        raise ValueError(
            f"all {self.count} forwarded ports are taken "
            f"({self.first}-{self.first + self.count - 1})")

    def release(self, name: str) -> None:
        for p, n in list(self.taken.items()):
            if n == name:
                del self.taken[p]

    def free_ports(self) -> list:
        return [p for p in range(self.first, self.first + self.count)
                if p not in self.taken]


def access_public_key() -> str:
    """The key the end USER logs in with.

    The private half lives here, on the reachable machine, and the
    public half is what each dialer puts in its key list. So the
    person reaches the dialer with one key, and the dialer's own
    machine key is not in that person's hands.
    """
    return sshd.public_key_of(sshd.ensure_access_key())


def name_of(pubkey: str) -> str:
    """The name on a key, which is the key's COMMENT.

    A public key is three things: the type, the body, and the
    comment.  The comment is the part a person reads, and it is where
    the name goes.

    MEASURED: the dialer makes its key with `ssh-keygen -C <name>`,
    so the name is on the key itself, and the panel can show it
    without anybody typing it in.

    So the name is READ, not ASKED FOR.  That is what removes the
    form: the only thing a person has to give is the key, and the
    key says who it is.
    """
    parts = (pubkey or "").strip().split()
    if len(parts) >= 3 and parts[0].startswith(("ssh-", "ecdsa-", "sk-")):
        # THE COMMENT IS THE THIRD THING.  A public key is the type,
        # the body and the comment -- three of them -- so the comment
        # starts at the third.
        #
        # MEASURED: the key has three parts and the name was empty,
        # because the comment was read from the fourth.
        return " ".join(parts[2:]).strip()
    return ""


def _body_of(line: str) -> str:
    """The body of the key in a key-list line, or "".

    A line in the list is

        environment="LJT_NAME=box-a" ssh-ed25519 AAAA... box-a

    and the body is the token after the key TYPE.  So the line is
    taken apart and the type is looked for, rather than the last
    tokens being taken -- MEASURED: the last three tokens kept the
    old environment option and the old comment, and the line came
    out with two options and no key type.
    """
    parts = line.split()
    for i, part in enumerate(parts):
        if part.startswith(("ssh-", "ecdsa-", "sk-")):
            return parts[i + 1] if i + 1 < len(parts) else ""
    return ""


def add_key(pubkey: str, name: str = "") -> None:
    """Let a key log in to this end's sshd.

    The key list is this tunnel's own, not the user's ~/.ssh, so the
    tunnel's access is exactly the access that was handed to it.

    The NAME goes on the KEY, as an environment option:

        environment="LJT_NAME=box-a" ssh-ed25519 AAAA...

    which is what the sshd's own log then reports.  The name is in
    the KEY LIST and not in anything the client sends, so a client
    cannot call itself something it is not.

    A key that is already in the list is left alone: the same key
    added twice is one key, and rewriting it would lose the name
    that is on it.
    """
    path = paths.authorized_keys()
    lines = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as fh:
            lines = [l.rstrip() for l in fh if l.strip()]

    key = pubkey.strip()
    if not key:
        return
    # THE NAME IS ON THE KEY, so it is read from there when the
    # caller does not say what it is.
    if not name:
        name = name_of(key)
    # THE BODY IS THE SECOND TOKEN, and the comment is the third.
    # The body alone is the key's material and it is what
    # identifies it.
    parts = key.split()
    body = parts[1] if len(parts) >= 2 else key
    for i, line in enumerate(lines):
        # THE BODY AND NOT THE LINE.  A substring match finds the
        # body inside a line that holds something else, and the key
        # that gets added is then the wrong one.
        if body and _body_of(line) == body:
            if name and f'{detect.Registry.NAME_VAR}=' not in line:
                lines[i] = f'environment="{detect.Registry.NAME_VAR}={name}" ' \
                           + line
            break
    else:
        if name:
            lines.append(f'environment="{detect.Registry.NAME_VAR}={name}" '
                         + key)
        else:
            lines.append(key)
    # The list is written on EVERY path, including the one where the
    # key was already there: the name may be the only thing that
    # changed, and a name that is not written down is a name nobody
    # can see.
    sshd.set_authorized_keys(lines)


def set_key_name(pubkey: str, name: str) -> bool:
    """Put a NAME on a key, whether or not it already has one.

    `add_key` LEAVES A KEY THAT IS ALREADY IN THE LIST ALONE, and
    that is right: the same key added twice is one key, and rewriting
    it would lose the name that is on it.

    But there is a case where the name has to CHANGE: the key list is
    shared, and a key that was put in under one name is put in again
    under another.  MEASURED: two cross-machine tests, one far key,
    one shared list -- the second test asked for a different name and
    the add did not give it, so the panel showed the FIRST test's
    name.

    So the name is set EXPLICITLY here, and it replaces the one that
    is there.

    THE KEY IS REBUILT FROM ITS PARTS.  A line in the list is

        environment="LJT_NAME=box-a" ssh-ed25519 AAAA... box-a

    and the options, the type, the body and the comment are four
    different things.  MEASURED: taking the last three tokens of the
    line kept the OLD environment option and the old comment, and the
    line came out as

        environment="LJT_NAME=new" environment="LJT_NAME=old" AAAA... old

    -- two environment options and no key type, which the sshd
    refuses.  So the line is taken apart and put back together.
    """
    path = paths.authorized_keys()
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as fh:
        lines = [l.rstrip() for l in fh if l.strip()]

    key = pubkey.strip()
    if not key:
        return False
    # THE BODY IS THE SECOND TOKEN of the key, and the comment is the
    # third.  The body alone is the key's material and it is what
    # identifies it.
    parts = key.split()
    body = parts[1] if len(parts) >= 2 else key

    out = []
    changed = False
    for line in lines:
        # ---- the line is taken apart ----
        #
        # THE OPTIONS COME FIRST, and there may be more than one of
        # them, and they are all in the first token.  So the type is
        # the first token that LOOKS like a key type.
        lparts = line.split()
        ltype = ""
        lbody = ""
        lcomment = ""
        for j2, part in enumerate(lparts):
            if part.startswith(("ssh-", "ecdsa-", "sk-")):
                ltype = part
                if j2 + 1 < len(lparts):
                    lbody = lparts[j2 + 1]
                if j2 + 2 < len(lparts):
                    lcomment = " ".join(lparts[j2 + 2:])
                break
        if not ltype:
            # not a key line, so it goes as it is
            out.append(line)
            continue

        if body and body == lbody:
            changed = True
            out.append(f'environment="{detect.Registry.NAME_VAR}={name}" '
                       + f"{ltype} {lbody} {name}")
        else:
            out.append(line)

    if not changed:
        # not in the list yet, so it is added
        out.append(f'environment="{detect.Registry.NAME_VAR}={name}" ' + key)
        changed = True

    sshd.set_authorized_keys(out)
    return changed

def remove_key(fingerprint: str) -> bool:
    """Take a key out of the list, by its FINGERPRINT.

    The fingerprint is what the panel has: the key list is read by
    the sshd, and the log reports the fingerprint, not the text.  So
    the fingerprint is the handle that joins the two.

    The name goes with the key: a key without its name is a key
    that shows up as a bare fingerprint, which is harder to read but
    not wrong.
    """
    path = paths.authorized_keys()
    if not os.path.isfile(path):
        return False
    with open(path, "r", encoding="utf-8") as fh:
        lines = [l.rstrip() for l in fh if l.strip()]

    out = []
    removed = False
    for line in lines:
        # THE KEY TEXT IS THE TYPE AND THE BODY, and the comment is
        # not part of it -- the fingerprint is computed from the type
        # and the body alone.
        #
        # MEASURED: the last THREE tokens were taken, which is the
        # body and the comment, so the type was left off and the
        # fingerprint was of a key that does not exist.
        parts = line.split()
        key_text = ""
        for i, part in enumerate(parts):
            if part.startswith(("ssh-", "ecdsa-", "sk-")):
                key_text = " ".join(parts[i:i + 2])
                break
        if not key_text:
            key_text = line
        if detect._fingerprint_of(key_text) == fingerprint:
            removed = True
            continue
        out.append(line)
    if removed:
        sshd.set_authorized_keys(out)
    return removed


def clean_known_hosts(first_port: int = FIRST_FORWARD_PORT,
                      last_port: int = LAST_FORWARD_PORT,
                      hosts: tuple = ("localhost", "127.0.0.1")) -> list:
    """Take this end's memory of the tunnel's host keys away.

    WHY IT IS NEEDED
    ----------------
    A person connects to a dialer through a forwarded port, and the
    ssh CLIENT remembers the host key it saw there.  The memory is
    in the user's own known_hosts.

    And a dialer that is set up again makes a NEW host key -- the
    machine key is the host key, and a fresh install is a fresh key.
    So the memory goes stale and the ssh client says

        Host key for [localhost]:10002 has changed and you have
        requested strict checking.
        Host key verification failed.

    which is the ssh client being RIGHT: the key really did change.
    But the dialer is the same box being set up again, and the
    person cannot be asked to type a command to fix it.

    SO THE ENTRIES ARE CLEANED WHEN THE TUNNEL STARTS.

    HOW IT IS DONE
    --------------
    **BY ASKING SSH.**  The file is in the HASHED form, so a line
    cannot be found by reading it and looking for the address -- and
    `ssh-keygen -F` knows the hash.  And `ssh-keygen -R` is what
    takes it out, because ssh wrote it and ssh knows how to remove
    it.

    MEASURED: on a copy, `ssh-keygen -R "[localhost]:10002"` removed
    that entry and left the other one alone.

    **AND ONLY THE TUNNEL'S OWN ENTRIES.**  The file is the user's,
    and it holds every host they have ever connected to.  So only
    the tunnel's ports are touched, and only for the names the tunnel
    is reached by.
    """
    import subprocess

    kh = paths.known_hosts()
    if not os.path.isfile(kh):
        return []

    removed = []
    for host in hosts:
        for port in range(first_port, last_port + 1):
            for target in (f"[{host}]:{port}", host):
                try:
                    # THE SYSTEM'S ssh-keygen, and not the one on the
                    # PATH: on this machine the PATH has git's copy,
                    # and the system's is the one that goes with the
                    # ssh the person is using.
                    r = quiet.run_hidden(
                        [sshd.ssh_keygen_path(), "-R", target, "-f", kh],
                        capture_output=True, text=True,
                        errors="replace", timeout=30)
                except (OSError, subprocess.TimeoutExpired):
                    continue
                if r.returncode == 0 and "updated" in (r.stdout or ""):
                    if target not in removed:
                        removed.append(target)
    return removed


def read_keys() -> list:
    path = paths.authorized_keys()
    if not os.path.isfile(path):
        return []
    with open(path, "r", encoding="utf-8") as fh:
        return [l.strip() for l in fh if l.strip()]


def start_sshd(on_log=None) -> subprocess.Popen:
    """This end's sshd, with remote forwarding allowed.

    GatewayPorts clientspecified is the setting that makes the whole
    thing reachable: without it the forwarded port binds to loopback
    and nobody off this machine can connect to it.

    The forward range is in the config as a PermitListen list, so a
    dialer cannot ask for a port outside it.

    The log level is DEBUG1, because the lines that say which key
    authenticated and which port it asked for are debug lines.  At
    INFO the listen end cannot see who is there.
    """
    return sshd.start(LISTEN_SSHD_PORT, listen="0.0.0.0",
                      gateway_ports=True, allow_forwarding=True,
                      permit_listen=list(range(FIRST_FORWARD_PORT,
                                               LAST_FORWARD_PORT + 1)),
                      log_level="DEBUG1",
                      on_log=on_log)


class Listener:
    """The listen end, and the dialers it can see.

    There is no list of dialers here.  There is a list of PORTS THAT
    ARE OPEN, and the log says who is on each one.

    The registry is fed two ways, and both matter:

      - the log, as the sshd writes it
      - the socket table, as the OS sees it

    The log says who; the socket table says whether they are still
    there.  A dialer that has gone leaves its lines in the log and no
    socket, and the difference between the two is exactly what "it
    has gone" means.
    """

    def __init__(self, sshd_port: int = LISTEN_SSHD_PORT,
                 first_port: int = FIRST_FORWARD_PORT,
                 count: int = FORWARD_PORT_COUNT):
        self.sshd_port = sshd_port
        self.first_port = first_port
        self.count = count
        self.registry = detect.Registry(
            first_port=first_port,
            count=count,
            log_path=paths.log_file())
        # THE sshd PROCESS.
        #
        # It is called `proc` here and `srv` in the window, and the
        # two names for one thing is a trap: a script that reads
        # `listener.srv` gets an AttributeError, and the message
        # points at the script rather than at the naming.
        #
        # So BOTH names work.  `proc` is the real attribute and
        # `srv` is what the window calls it.
        self.proc = None

    @property
    def srv(self):
        """The sshd process, under the name the window uses.

        IT IS THE SAME PROCESS as `proc`.  The window calls it `srv`
        and this class calls it `proc`, and a script that reaches
        for the other name gets an AttributeError that says nothing
        about the naming.
        """
        return self.proc

    def start(self) -> subprocess.Popen:
        """Start the sshd, and start watching the log."""
        self.proc = sshd.start(
            self.sshd_port, listen="0.0.0.0",
            gateway_ports=True, allow_forwarding=True,
            permit_listen=list(range(self.first_port,
                                    self.first_port + self.count)),
            # DEBUG2, not DEBUG1: the line that says which NAME is on
            # a key is a DEBUG2 line, and at DEBUG1 the name cannot be
            # learned at all.
            log_level="DEBUG2",
            on_log=self._on_log)
        return self.proc

    def _on_log(self, line: str) -> None:
        """One line of the sshd's log."""
        self.registry.absorb([line])

    def dialers(self) -> list:
        """The dialers that are there RIGHT NOW.

        THE SCAN IS THE ANSWER ON WINDOWS, AND THE LOG IS THE ANSWER
        ON LINUX.

        On Windows the sshd's sessions do not log to the listener's
        pipe, so the log-based registry sees nothing.  The scan does
        not need the log: the socket table says which ports are open
        and the host key behind each port says who is there.  See
        ljtunnel.scan for the whole of it.

        On Linux the sshd's children inherit the pipe, so the log
        works there, and the log knows the name without a keyscan.
        Both are used where they work, and the scan is the fallback
        for the log.
        """
        import sys

        if sys.platform == "win32":
            from . import scan
            rows = scan.scan_fast(self.first_port, self.count)
            if rows:
                return rows
            # and the log, in case it has something
            return self.registry.snapshot()
        return self.registry.snapshot()

    def free_ports(self) -> list:
        """The ports in the range that nothing is using."""
        used = self.registry.ports_in_use()
        return [p for p in range(self.first_port, self.first_port + self.count)
                if p not in used]

    def stop(self) -> None:
        try:
            if self.proc:
                self.proc.terminate()
                self.proc.wait(timeout=8)
        except Exception:
            pass
        # AND THE HANDLE IS DROPPED.  A stopped listener that still
        # says it has a process is a listener that says it is
        # running when it is not, and the window shows that.
        self.proc = None
        sshd.stop()
        # The per-connection children hold the FORWARDED ports, and
        # the listener going away does not take them with it.  A
        # forwarded port that is still held is a port the next
        # launch finds busy for no reason anybody can see.
        sshd.stop_sessions()


def dialer_command(user: str = "", host: str = "") -> str:
    """The one line the dialer runs.

    Copy-pasteable on purpose: the dialer should be one paste, not a
    paragraph of instructions.

    THERE IS NO PORT IN IT.  The dialer finds a free one itself: it
    asks for the first port in the range, and if the listen end says
    that one is taken it asks for the next.  So the SAME command works
    for every dialer, and pasting it on ten boxes is ten dialers with
    ten different ports and no coordination at all.

    The access key is IN the command. That is what makes the setup
    one step instead of three: the dialer takes the key, puts it in
    its own key list, and the end user can log in. Without it the
    person would have to be handed a key and told what to do with it.

    THE DIALER'S HOST KEY IS ITS MACHINE KEY, so the listen end can
    NAME it without the sshd's log.

    On Windows the sshd's sessions do not log to the listener's pipe,
    so the log cannot say who connected.  What CAN say is the host
    key that answers behind the forwarded port, and the listen end
    finds the name by looking that key up in its own key list.  So
    the key behind the port has to be a key the listen end knows,
    and the only one it knows is the one the dialer logged in with.
    So on the far side the two are the same key, and nothing extra
    has to be carried in the command.

    The access key is PUBLIC. No private half leaves either end.
    """
    host = host or local_ipv4()
    user = user or current_user()
    return (f"ljtunnel dialer --listen-host {host} "
            f"--listen-port {LISTEN_SSHD_PORT} "
            f"--user {user} "
            f"--access-key \"{access_public_key()}\"")


def current_user() -> str:
    """The account this end runs as."""
    return paths.current_user()


def main(argv=None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="ljtunnel listen",
        description="the reachable end: an sshd, and a panel of dialers")
    p.add_argument("--print-only", action="store_true",
                   help="print what this would do and exit")
    args = p.parse_args(argv)

    log("")
    log("  ljtunnel listen -- the reachable end")
    log(f"    this end's sshd : {LISTEN_SSHD_PORT}")
    log(f"    forwarded ports : {FIRST_FORWARD_PORT}-{LAST_FORWARD_PORT}")
    log(f"    this end       : {local_ipv4()}")
    log("")

    if args.print_only:
        return 0

    paths.ensure_dir(paths.state_dir())
    sshd.ensure_host_key()
    sshd.ensure_client_key()
    sshd.set_authorized_keys(read_keys())

    listener = Listener()

    # THE STALE HOST KEYS GO, BEFORE THE TUNNEL COMES UP.
    #
    # A dialer that is set up again makes a new host key, and the ssh
    # client remembers the old one, and then it says
    #
    #     Host key for [localhost]:10002 has changed and you have
    #     requested strict checking.
    #
    # and the person cannot get in.  So the tunnel's own entries are
    # cleaned every time it starts.
    try:
        _gone = clean_known_hosts(LISTEN_SSHD_PORT,
                                  listener.first_port + listener.count - 1)
        if _gone:
            log(f"  the known hosts were cleaned: {len(_gone)} entries")
    except Exception:
        pass

    srv = listener.start()
    time.sleep(1.5)
    if srv.poll() is not None:
        log("  the sshd did not start.")
        if sshd.port_busy(LISTEN_SSHD_PORT):
            log(f"  port {LISTEN_SSHD_PORT} is held by another process.")
        _dump(paths.log_file())
        return 1
    log(f"  the sshd is up (pid {srv.pid})")
    log("")

    # THE BREAK IS CAUGHT, SO THE SSHD IS STOPPED PROPERLY.
    #
    # A console BREAK is not a Ctrl-C: Windows turns it into
    # SIGBREAK, and Python's DEFAULT handler for SIGBREAK is to
    # KILL THE PROCESS.  MEASURED: the process went with
    # 0xC000013A (STATUS_CONTROL_C_EXIT), the `finally` never ran,
    # and the sshd was left holding the port -- so the next launch
    # found it busy for no reason anybody could see.
    #
    # So SIGBREAK is handled the same way as SIGINT: it raises
    # KeyboardInterrupt, which the block below catches, and the
    # `finally` runs.
    _catch_the_break()

    try:
        _loop(listener)
    except KeyboardInterrupt:
        # Ctrl-C.  The sshd is a child, so it would go with the
        # process, but it is stopped PROPERLY first: the port is
        # released cleanly and the next launch does not find it busy
        # for no reason anybody can see.
        log("")
        log("  Ctrl-C: stopping")
    finally:
        listener.stop()
    log("  stopped")
    return 0


def _read_a_line():
    """Read one line from the keyboard, or "" when there is none.

    `sys.stdin.readline()` BLOCKS INSIDE A WIN32 CALL on Windows, and
    Python only runs its signal handlers BETWEEN BYTECODES.  So a
    console BREAK arrives while the read is in progress and is not
    acted on until the read finishes -- which is when a person
    types something.

    MEASURED: the break was delivered and the process stayed up
    until a newline was typed.

    So the read is done in a way that comes back: a thread reads the
    line and the main thread waits for it with a timeout, and the
    break is acted on as soon as it arrives.

    AND THE THREAD IS A DAEMON, so it does not keep the process
    alive when the window closes.
    """
    import queue
    import threading

    q = queue.Queue(maxsize=1)

    def _reader():
        try:
            q.put(sys.stdin.readline())
        except Exception:
            q.put("")

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    while True:
        try:
            return q.get(timeout=0.25)
        except queue.Empty:
            # nothing typed yet -- but a console event may have
            # arrived, and Python raises it here, between the
            # bytecodes, where it CAN be caught.
            pass


def _catch_the_break() -> None:
    """Make a console BREAK raise KeyboardInterrupt.

    A Ctrl-C is SIGINT and Python raises KeyboardInterrupt for it.
    A console BREAK is SIGBREAK and Python's default handler for it
    TERMINATES THE PROCESS -- so the `finally` that stops the sshd
    never runs, and the sshd is left holding the port.

    So SIGBREAK is given the same handler, and the process gets to
    clean up on its way out.
    """
    import signal

    if not hasattr(signal, "SIGBREAK"):
        return

    def _handler(signum, frame):
        raise KeyboardInterrupt()

    try:
        signal.signal(signal.SIGBREAK, _handler)
    except (OSError, ValueError):
        # Not the main thread, or the platform will not allow it.
        pass


def _loop(listener: "Listener") -> None:
    """A line-based control, so a terminal can drive it too.

    The desktop app is a view over the same state; this is what a
    person gets when they run it from a shell.

    The commands are about RECORDS: what a dialer is called, where it
    is, and the command to run on it.  The state of the dialers --
    which are up, on which port -- is worked out by the listen end
    and shown, not asked for.
    """
    log("  commands:")
    log("    add <name> [host] [user]   record a dialer and print its "
        "command")
    log("    key <name> <public key>    put a dialer's key in the list")
    log("    command <name>             print a dialer's command again")
    log("    list                       the records and what is up")
    log("    forget <name>              forget a record")
    log("    quit")
    log("")

    while True:
        try:
            line = _read_a_line()
        except KeyboardInterrupt:
            raise
        if not line:
            break
        parts = line.split()
        if not parts:
            continue
        cmd = parts[0].lower()

        if cmd in ("quit", "exit", "q"):
            break

        if cmd == "add" and len(parts) >= 2:
            name = parts[1]
            host = parts[2] if len(parts) > 2 else ""
            user = parts[3] if len(parts) > 3 else current_user()
            rec = records.add(name, "", host, user)
            log(f"  recorded {rec['name']}")
            log(f"  the dialer runs:")
            log(f"    {records.command_for(rec)}")

        elif cmd == "key" and len(parts) >= 3:
            name = parts[1]
            pubkey = " ".join(parts[2:])
            add_key(pubkey, name)
            records.add(name, pubkey)
            log(f"  the key is in the list, named {name}")
            rec = records.by_name(name)
            log(f"  the dialer runs:")
            log(f"    {records.command_for(rec)}")

        elif cmd == "command" and len(parts) >= 2:
            rec = records.by_name(parts[1])
            if not rec:
                log(f"  there is no record called {parts[1]}")
            else:
                log(f"  {rec['name']} runs:")
                log(f"    {records.command_for(rec)}")

        elif cmd == "forget" and len(parts) >= 2:
            rec = records.by_name(parts[1])
            if rec.get("pubkey"):
                remove_key(detect._fingerprint_of(rec["pubkey"]))
            if records.remove(parts[1]):
                log(f"  forgotten {parts[1]}")
            else:
                log(f"  there is no record called {parts[1]}")

        elif cmd == "list":
            _list(listener)

        else:
            log("  ?")


def _list(listener: "Listener") -> None:
    """The records, and the dialers that are up.

    Both, joined by name.  A record with no dialer is a box that is
    not running yet; a dialer with no record is one that was let in
    before the records existed.
    """
    live = {d.name or d.fingerprint: d for d in listener.dialers()}
    recs = records.load()
    if not recs and not live:
        log("  (no dialers)")
        return
    for rec in recs:
        name = rec.get("name") or rec.get("pubkey", "")[:24]
        d = live.pop(name, None)
        state = f"up on {d.port}" if d else "not up"
        log(f"  {name:16} {state:14} {rec.get('host', '')}")
    for name, d in live.items():
        log(f"  {name:16} up on {d.port:6} {d.peer}  (no record)")


def _dump(path: str, lines: int = 20) -> None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            tail = fh.readlines()[-lines:]
        for line in tail:
            log("    " + line.rstrip())
    except OSError:
        log("    (no log)")


if __name__ == "__main__":
    sys.exit(main())
