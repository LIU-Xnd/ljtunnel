"""The firewall rule the listen end needs.

WHY A RULE IS NEEDED
-------------------
Windows blocks inbound connections to a port it has not been told
about, and it does it SILENTLY: the connection times out, with no
error on either side. The listen end's sshd is listening on 10001 and
the dialer cannot reach it, and nothing says why.

WHICH PORTS
-----------
    10001   this end's sshd -- where the DIALERS log in
    10002+  the forwarded ports -- where OTHER PEOPLE log in, to reach
            a dialer

Both are inbound on this machine, so both need to be open. The rule
covers the whole forwarded range, because a dialer can be on any port
in it and the rule is one thing rather than one per dialer.

WHY IT IS NOT IN THE MSI
------------------------
Two reasons, and the second is the one that matters:

  - the WiX Firewall extension's <File> element has to point at a
    file that is IN the package. sshd.exe is not: it is the system's
    own OpenSSH, at C:\\Program Files\\OpenSSH\\sshd.exe, and the
    package does not install it.
  - the MSI is a per-user install, and adding a firewall rule is an
    administrator action. A per-user install does not have that.

So the rule is a command, and the app shows it and offers it for
copying. tools/open_firewall.ps1 is the same thing as a script, for
the person who would rather run one.
"""
from __future__ import annotations

import subprocess
import sys

RULE_NAME = "ljtunnel"

# The port this end's own sshd listens on, and the first forwarded
# port. The range covers every dialer the panel can hold.
SSHD_PORT = 10001
FIRST_FORWARD_PORT = 10002
FORWARD_PORT_COUNT = 20

LAST_FORWARD_PORT = FIRST_FORWARD_PORT + FORWARD_PORT_COUNT - 1

# The sshd the user-level instance runs. The rule is on the PROGRAM as
# well as the ports, so it is not about a path that could move.
SSHD_PROGRAM = r"C:\Program Files\OpenSSH\sshd.exe"


def is_admin() -> bool:
    """Is this process elevated?"""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def port_spec() -> str:
    """The ports, as netsh wants them.

    BOTH the sshd port and the forwarded range. 10001 is where the
    DIALER connects to this end, so it is inbound here too -- leaving
    it out is the bug that makes the dialer time out with no message.

    A range is one entry where a list would be many, and the rule is
    one thing rather than one per dialer.
    """
    if FIRST_FORWARD_PORT == LAST_FORWARD_PORT:
        return f"{SSHD_PORT},{FIRST_FORWARD_PORT}"
    return f"{SSHD_PORT},{FIRST_FORWARD_PORT}-{LAST_FORWARD_PORT}"


def netsh_command() -> str:
    """The command that adds the rule.

    Rendered, not run, when the shell is not elevated. It is a plain
    command so a person can paste it into an elevated shell -- which
    is the only way it can be done.
    """
    return (
        f'netsh advfirewall firewall add rule name="{RULE_NAME} inbound" '
        f'dir=in action=allow protocol=TCP localport={port_spec()} '
        f'program="{SSHD_PROGRAM}"'
    )


def remove_command() -> str:
    return f'netsh advfirewall firewall delete rule name="{RULE_NAME} inbound"'


def rule_exists() -> bool:
    """Is the rule already there?"""
    if sys.platform != "win32":
        return False
    r = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule",
         f"name={RULE_NAME} inbound"],
        capture_output=True, text=True, errors="replace")
    out = r.stdout or ""
    return str(SSHD_PORT) in out or RULE_NAME in out


def add_rule() -> tuple:
    """Add the rule. Returns (ok, message).

    Needs an elevated shell. Without one it says so, and gives the
    command to run -- because "access denied" with nothing else is not
    an answer a person can act on.
    """
    if sys.platform != "win32":
        return True, "not Windows: no firewall rule needed"

    if not is_admin():
        return False, (
            "the firewall rule needs an administrator shell.\n"
            "  run this in a terminal running as administrator:\n"
            "    " + netsh_command())

    r = subprocess.run(netsh_command().split(), capture_output=True,
                       text=True, errors="replace")
    if r.returncode == 0:
        return True, f"the rule is in: {port_spec()}"
    return False, (r.stdout + r.stderr).strip() or "the rule did not go in"


def remove_rule() -> tuple:
    """Take the rule away again."""
    if sys.platform != "win32":
        return True, "not Windows: no firewall rule to remove"
    if not is_admin():
        return False, (
            "removing the rule needs an administrator shell.\n"
            "  run this in a terminal running as administrator:\n"
            "    " + remove_command())
    r = subprocess.run(
        ["netsh", "advfirewall", "firewall", "delete", "rule",
         f"name={RULE_NAME} inbound"],
        capture_output=True, text=True, errors="replace")
    if r.returncode == 0:
        return True, "the rule is gone"
    return False, (r.stdout + r.stderr).strip() or "the rule did not go"


def describe() -> dict:
    """What the listen end needs, for the panel to show."""
    return {
        "rule_name": RULE_NAME,
        "ports": port_spec(),
        "sshd_port": SSHD_PORT,
        "first_forward_port": FIRST_FORWARD_PORT,
        "last_forward_port": LAST_FORWARD_PORT,
        "admin": is_admin(),
        "installed": rule_exists(),
        "command": netsh_command(),
    }


if __name__ == "__main__":
    ok, msg = add_rule()
    print(msg)
    sys.exit(0 if ok else 1)
