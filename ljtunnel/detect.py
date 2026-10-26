"""Seeing the dialers, without being told about them.

The listen end used to keep a list of dialers that somebody had
filled in by hand: a name, a host, a port.  That is three things to
get right before anything works, and the person filling them in is
the person most likely to get one of them wrong.

But the information is ALREADY THERE.  By the time a dialer is
forwarding a port, this machine's own sshd knows:

  - which forwarded ports are open, and which process holds each one
  - which public key each session used
  - which port each session asked for
  - the name attached to that key

None of that needs a protocol of our own.  It is OpenSSH's own
bookkeeping, and it is all in two places: the log and the socket
table.

THE LOG
-------
The listen end's sshd writes a line per event.  The two that matter:

    Accepted publickey for xnd_l from 192.0.2.7 port 35536 ssh2:
        ED25519 SHA256:xht76GglXU2cFU/...

    debug1: user: xnd_l: server_input_global_request: rtype
        tcpip-forward listen 0.0.0.0 port 10002 [postauth]

The first says WHICH KEY.  The second says WHICH PORT.  They are in
the same session, and a session's lines are contiguous, so the
forward is read by walking the log in order: a key, then the port
that key asked for.

THE SOCKET TABLE
----------------
The forwarded socket belongs to the per-connection child of the
sshd, so the LISTEN sockets in the forward range ARE the live
forwards:

    Listen 0.0.0.0:10002  pid 36540  sshd-session.exe

So the socket table says whether a port is open RIGHT NOW, and the
log says who asked for it.  The panel needs both: the log to name
the dialer, the socket table to know it is still there.

WHY THE CLIENT'S "SUCCESS" IS NOT USED
--------------------------------------
A dialer that asks for a port which is already taken is told

    remote forward success for: listen 0.0.0.0:10002

and gets NO socket.  The client says success and the forward is not
there.  So nothing here believes the client: the socket table is the
truth, and the log is the story of how it got that way.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field

# The log line that says which key was used.  The fingerprint is what
# identifies the dialer: the key TEXT is long and the fingerprint is
# short, and the fingerprint is what sshd itself prints.
#
# The address in the example below is 192.0.2.7 -- TEST-NET-1, which
# is reserved for documentation and is never routed.  The address that
# was really there is not written down: an address in a source file is
# an address somebody will copy, and it will be wrong.
_ACCEPTED_KEY = re.compile(
    r"Accepted publickey for \S+ from (?P<peer>\S+) port (?P<peerport>\d+) "
    r"ssh2: (?P<type>\S+) (?P<fingerprint>SHA256:\S+)")

# The log line that says which port a session asked for.
#
# The pattern is deliberately loose about the text BEFORE it: the
# sshd writes the request type on some builds and not on others
# ("server_input_global_request: rtype tcpip-forward listen ..." on
# one, "server_input_global_request: tcpip-forward listen ..." on
# another), and a pattern that insists on the exact wording is a
# pattern that stops matching when OpenSSH is upgraded.
_FORWARD = re.compile(
    r"tcpip-forward listen (?P<bind>\S+) port (?P<port>\d+)")

# The key list line, with the name attached to the key.  This is the
# dialer's NAME, and it comes from the key list rather than from the
# client, so the client cannot claim to be somebody else.
#
# The line is a DEBUG2 line, so the listen end runs at DEBUG2: at
# DEBUG1 the key options are not in the log at all, and the name
# cannot be learned.
_KEY_OPTION = re.compile(
    r"check options: 'environment=\"(?P<var>[A-Z_]+)=(?P<value>[^\"]*)\" "
    r"(?P<type>\S+) (?P<key>\S+)")

# The fingerprint is computed from the WHOLE key, so the type and the
# body have to be put back together: the log has them as two tokens
# and the fingerprint needs "ssh-ed25519 AAAA...".
_KEY_OPTION_FULL = re.compile(
    r"check options: 'environment=\"(?P<var>[A-Z_]+)=(?P<value>[^\"]*)\" "
    r"(?P<full>ssh-\S+ \S+)")


@dataclass
class Dialer:
    """One dialer, as the listen end can see it."""

    fingerprint: str = ""       # SHA256:... -- the dialer's identity
    name: str = ""              # the name attached to the key
    port: int = 0               # the forwarded port on this machine
    peer: str = ""              # where the dialer is
    peer_port: int = 0
    key_type: str = ""
    last_seen: float = 0.0
    alive: bool = False         # the socket is open right now

    @property
    def label(self) -> str:
        """What to call this dialer in the panel."""
        return self.name or self.fingerprint or f"port {self.port}"


@dataclass
class Registry:
    """The dialers the listen end can see, and when it last looked.

    The registry is a SNAPSHOT, not a ledger: it is rebuilt from the
    log and the socket table every time it is read, so it cannot drift
    away from the truth the way a hand-maintained list does.

    The log is only ever APPENDED to, so it is read from the last
    offset that was read before.  Reading the whole file every time
    would work too, and would be simpler, but the log grows without
    bound and a panel that re-reads a megabyte twice a second is a
    panel that eats a machine.
    """

    # The name of the environment variable that carries the dialer's
    # name, from the key list.
    NAME_VAR = "LJT_NAME"

    first_port: int = 10002
    count: int = 20
    log_path: str = ""
    keys_by_fingerprint: dict = field(default_factory=dict)
    _offset: int = 0
    _pending: dict = field(default_factory=dict)   # fingerprint -> Dialer
    _seen: dict = field(default_factory=dict)       # fingerprint -> Dialer

    # ------------------------------------------------------------- the log
    def read_log(self) -> list:
        """The new lines in the log since the last read.

        The lines are read as bytes and decoded with errors="replace":
        a Windows console code page is not valid UTF-8, and a strict
        decode would raise on a line that has nothing to do with us.

        The file is read from the LAST OFFSET, but the offset is
        never allowed to run past the end of the file: the log is
        written by a process that may re-open it, and a file that has
        been replaced is shorter than the offset says, and reading
        from an offset past the end of a new file returns NOTHING.
        So the offset is clamped, and a file that shrank is read from
        the beginning.
        """
        if not self.log_path or not os.path.isfile(self.log_path):
            return []
        try:
            size = os.path.getsize(self.log_path)
            if size < self._offset:
                # the file was replaced or truncated
                self._offset = 0
            with open(self.log_path, "rb") as fh:
                fh.seek(self._offset)
                data = fh.read()
                self._offset = fh.tell()
        except OSError:
            return []
        if not data:
            return []
        return data.decode("utf-8", "replace").splitlines()

    def learn(self, lines: list) -> None:
        """Learn from a list of log lines.  The same as absorb()."""
        self.absorb(lines)

    def absorb(self, lines: list) -> None:
        """Read the log, and learn about the dialers in it.

        A session is a KEY followed by the PORT it asked for.  The
        lines are in order, and one session's lines are contiguous, so
        a key line followed by a forward line is a dialer.
        """
        for line in lines:
            m = _ACCEPTED_KEY.search(line)
            if m:
                fp = m.group("fingerprint")
                d = Dialer(
                    fingerprint=fp,
                    peer=m.group("peer"),
                    peer_port=int(m.group("peerport")),
                    key_type=m.group("type"),
                    last_seen=time.time(),
                )
                # A session that is KNOWN is kept even before it asks
                # for a port: the accept line is the identity, and a
                # session that has authenticated and not yet asked for
                # a port is still a dialer that is here.
                self._pending[fp] = d
                self._seen.setdefault(fp, d)
                continue

            m = _FORWARD.search(line)
            if m and self._pending:
                # The most recent key wins: the forward belongs to the
                # session that just authenticated.
                fp = list(self._pending)[-1]
                d = self._pending[fp]
                d.port = int(m.group("port"))
                d.last_seen = time.time()
                self._seen[fp] = d
                continue

            m = _KEY_OPTION_FULL.search(line)
            if m and m.group("var") == self.NAME_VAR:
                # The name belongs to a KEY.  The accept line gives
                # the FINGERPRINT, so the name is stored against the
                # fingerprint of the key that is named here, and the
                # two are joined when the key is used.
                fp = _fingerprint_of(m.group("full"))
                if fp:
                    self.keys_by_fingerprint[fp] = m.group("value")
                continue

    # ------------------------------------------------- the socket table
    def live_ports(self) -> dict:
        """The forwarded ports that are open RIGHT NOW, and their pids.

        The socket table is the truth about a port: a dialer that is
        not there has no socket, whatever the log said a minute ago.
        """
        return _listening(self.first_port, self.first_port + self.count)

    def snapshot(self) -> list:
        """The dialers, as they are RIGHT NOW.

        A dialer is in the list when its port is open.  A port that
        the log mentioned but that is not listening is a dialer that
        has gone: it is not shown as a live row, because the panel's
        job is to say what can be reached.
        """
        live = self.live_ports()
        out = []
        claimed = set()
        for fp, d in self._seen.items():
            d.alive = d.port in live
            if not d.alive:
                continue
            if d.port in claimed:
                # Two sessions asked for the SAME port, and only one of
                # them got it: the second was told "forward success"
                # and given nothing.  The socket table has one owner
                # for the port, so only one dialer can be on it.
                #
                # Which one?  The socket table says the PORT, not the
                # session, so the two are joined by the port and the
                # first one to claim it in the log is the one that
                # asked first.  The other dialer is not shown as being
                # on a port it does not have -- it will ask for
                # another one.
                continue
            claimed.add(d.port)
            # attach the name, if the key list had one
            if not d.name:
                d.name = self.keys_by_fingerprint.get(fp, "")
            out.append(d)
        out.sort(key=lambda d: d.port)
        return out

    def ports_in_use(self) -> set:
        """The ports that are taken, from the socket table."""
        return set(self.live_ports().keys())


def banner_of(port: int, host: str = "127.0.0.1", timeout: float = 8.0) -> str:
    """The SSH banner on that port, or "".

    The banner is the first thing an SSH server sends, before any
    key exchange: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.13".  It is
    enough to tell whether SOMETHING is there.

    It does NOT tell you who is there -- the banner is the same for
    every host with the same sshd build.  For that, the host key is
    needed, and the host key needs the key exchange that a plain
    socket cannot do.
    """
    import socket

    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return ""
    try:
        s.settimeout(timeout)
        data = b""
        while len(data) < 64 and b"\n" not in data:
            chunk = s.recv(64 - len(data))
            if not chunk:
                break
            data += chunk
        return data.decode("ascii", "replace").strip()
    except OSError:
        return ""
    finally:
        try:
            s.close()
        except OSError:
            pass


def host_key_fingerprint(port: int, host: str = "127.0.0.1",
                         timeout: float = 12.0) -> str:
    """The SHA256 fingerprint of the host key on that port, or "".

    This is the real identity: the banner says what software is
    there, and the host key says WHICH machine.  Two dialers on the
    same network both answer with the same banner.

    `ssh-keyscan` does the whole handshake and prints the key, and
    `ssh-keygen -lf` turns it into the fingerprint that the sshd's
    own log prints, so the two can be compared.

    On WINDOWS, ssh-keyscan.exe is not on PATH for an ordinary shell
    and lives in the OpenSSH folder under System32, so the path is
    looked up rather than assumed.
    """
    import subprocess

    scan = _ssh_keyscan_path()
    gen = _ssh_keygen_path()
    if not scan or not gen:
        return ""
    try:
        r = subprocess.run([scan, "-T", "10", "-p", str(port), host],
                           capture_output=True, text=True,
                           errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    keys = [l for l in (r.stdout or "").splitlines()
            if l and not l.startswith("#")]
    if not keys:
        return ""
    try:
        r2 = subprocess.run([gen, "-lf", "-"], input=keys[0],
                            capture_output=True, text=True,
                            errors="replace", timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    out = (r2.stdout or "").strip()
    parts = out.split()
    return parts[1] if len(parts) >= 2 else ""


def _ssh_keyscan_path() -> str:
    """The ssh-keyscan binary, or ""."""
    import shutil

    if sys.platform == "win32":
        for p in (r"C:\Windows\System32\OpenSSH\ssh-keyscan.exe",
                  r"C:\Program Files\OpenSSH\ssh-keyscan.exe"):
            if os.path.isfile(p):
                return p
    found = shutil.which("ssh-keyscan")
    return found or ""


def _ssh_keygen_path() -> str:
    """The ssh-keygen binary, or ""."""
    import shutil

    if sys.platform == "win32":
        for p in (r"C:\Windows\System32\OpenSSH\ssh-keygen.exe",
                  r"C:\Program Files\OpenSSH\ssh-keygen.exe"):
            if os.path.isfile(p):
                return p
    found = shutil.which("ssh-keygen")
    return found or ""


def _fingerprint_of(key_text: str) -> str:
    """The SHA256 fingerprint of a public key TEXT.

    sshd prints the fingerprint, not the key, so the two have to be
    brought into the same form before they can be compared.  This is
    the same computation ssh-keygen -lf does, done here so that the
    listen end does not have to shell out for every line.
    """
    import base64
    import hashlib

    parts = key_text.split()
    if len(parts) < 2:
        return ""
    try:
        blob = base64.b64decode(parts[1])
    except Exception:
        return ""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _listening(first: int, last: int) -> dict:
    """The ports in the range that are listening, and the pid of each.

    On Windows this asks the OS through PowerShell, because there is
    no netstat parse worth trusting and Get-NetTCPConnection gives
    the owning process with it.  On Linux /proc is read directly:
    the socket table is the inode, and the pid that holds it is the
    one with that inode.
    """
    if sys.platform == "win32":
        return _listening_windows(first, last)
    return _listening_linux(first, last)


def _listening_windows(first: int, last: int) -> dict:
    script = (
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.LocalPort -ge {first} -and $_.LocalPort -le {last} }} | "
        "ForEach-Object { '{0} {1}' -f $_.LocalPort, $_.OwningProcess }")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-Command", script],
                       capture_output=True, text=True, errors="replace",
                       timeout=60)
    out = {}
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            out[int(parts[0])] = int(parts[1])
    return out


def _listening_linux(first: int, last: int) -> dict:
    """The listening ports in the range, from /proc/net/tcp.

    The hex in /proc/net/tcp is the port in HOST byte order, so
    10002 is 0x2712 and not 0x1227.  Getting that wrong is the
    classic way to read a socket table that says nothing.
    """
    import glob

    # the inode of each listening socket
    inodes = {}
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                next(fh, None)
                for line in fh:
                    f = line.split()
                    if len(f) < 10 or f[3] != "0A":     # 0A = LISTEN
                        continue
                    port = int(f[1].split(":")[1], 16)
                    if first <= port <= last:
                        inodes[f[9]] = port
        except OSError:
            continue
    if not inodes:
        return {}

    out = {}
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            target = os.readlink(fd)
        except OSError:
            continue
        if not target.startswith("socket:["):
            continue
        inode = target[8:-1]
        if inode in inodes:
            pid = int(fd.split("/")[2])
            out[inodes[inode]] = pid
    return out
