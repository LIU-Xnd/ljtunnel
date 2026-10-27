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

So the rule is a COMMAND, and the app runs it -- with the UAC prompt
in front of it, which the person answers.

THE UAC PROMPT
--------------
The rule is added by asking Windows to run the command AS AN
ADMINISTRATOR: ShellExecuteEx with the "runas" verb.  Windows puts
up the UAC prompt, the person answers it, and the command runs with
administrator rights.

That is the whole trick, and it is why this needs no shell: the
elevation is a property of HOW the process is started, not of the
program that is started.  The person sees a prompt that says
"netsh", they say yes, and the rule goes in.

WHAT THE PROMPT DOES NOT DO
---------------------------
It does not tell the person what is about to happen.  The prompt
names the PROGRAM, and the program here is netsh -- so the prompt
says "netsh", which tells a person nothing.

So the elevation runs a VISIBLE COMMAND PROMPT instead, carrying the
rule as its command line.  The prompt says "Windows PowerShell" or
"cmd", the person still says yes, and the netsh command runs inside
it.  A hidden window would be a prompt the person cannot read, and a
person who cannot read what they are agreeing to should not be
agreeing to it.

THE ELEVATED PROCESS IS DETACHED
--------------------------------
ShellExecuteEx starts a NEW process.  It is not a child, so its exit
code is not ours to read, and the call returns as soon as the
process is STARTED -- before the rule is in.

So the result is reported through a FILE: the elevated command writes
whether it worked into it, and this process reads that file
afterwards.  A file is the only thing both processes can see, and it
survives the elevated process going away.
"""
from __future__ import annotations

import os
import subprocess
from . import quiet
import sys
import tempfile
import time

from .elevate import ERROR_CANCELLED, POWERSHELL, is_admin
from .elevate import shell_execute_runas as _shell_execute_runas

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


import tempfile
import time

from .elevate import ERROR_CANCELLED, POWERSHELL, is_admin
from .elevate import shell_execute_runas as _shell_execute_runas
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


def netsh_add_body() -> str:
    """The PowerShell that adds the rule.

    IT IS A CMDLET, NOT netsh.  netsh says "the specified value is
    invalid" for a dozen different reasons -- a wrong argument, a
    port that is not a port, and NOT BEING AN ADMINISTRATOR -- so
    the thing that went wrong cannot be told from the message.

    New-NetFirewallRule says what went wrong: "Access is denied"
    with the exception type beside it.  So the rule is added with
    the cmdlet, and the netsh command stays for a person to run by
    hand, where the Windows firewall console can show them what the
    rules are.

    THE OLD RULE GOES FIRST.  New-NetFirewallRule does not replace
    a rule with the same name -- it ADDS another one.  So pressing
    the button twice leaves two rules, and pressing it five times
    leaves five, and the firewall console shows a list of identical
    entries that all do the same thing.  So the rule is taken away
    and then put in, and the button is safe to press twice.

    The quoting is simple here: the cmdlet's arguments are
    PowerShell's own, a single-quoted string is a string, and a path
    with spaces in it is one.
    """
    # THE REMOVAL MUST NOT BE SILENT.
    #
    # With -ErrorAction SilentlyContinue a removal that FAILS is
    # swallowed, the script carries on, and the new rule is added
    # beside the old one.  Press the button twice and there are two
    # rules; press it five times and there are five.  They all do the
    # same thing and the firewall console shows a list of identical
    # entries.
    #
    # So the removal is checked, and a removal that did not happen
    # STOPS the script: no new rule is added, and the answer says
    # why.
    #
    # Remove-NetFirewallRule with -DisplayName takes EVERY rule with
    # that name, so this also cleans up what earlier versions left
    # behind.
    #
    # IT THROWS, IT DOES NOT EXIT.  An `exit` in the middle of the
    # body skips the writing of the answer file, so the caller gets
    # no explanation at all -- it just finds nothing there.  A
    # `throw` is caught by the script around the body, and the
    # answer file IS written, with the reason in it.
    return (
        "try { "
        f"Remove-NetFirewallRule -DisplayName '{RULE_NAME}' "
        "-ErrorAction Stop; "
        "} catch { "
        "throw ('could not remove the old rule: ' + $_.Exception.Message); "
        "}; "
        f"New-NetFirewallRule -DisplayName '{RULE_NAME}' "
        f"-Direction Inbound -Action Allow -Protocol TCP "
        f"-LocalPort {port_spec()} "
        f"-Program '{SSHD_PROGRAM}' "
        f"-Enabled True"
    )


def netsh_delete_body() -> str:
    """The PowerShell that removes the rule.

    IT REPORTS WHAT WENT WRONG.  With -ErrorAction
    SilentlyContinue a removal that failed is swallowed, and the
    caller is told the rule is gone when it is not.  So the error
    is caught and the exit code says so.
    """
    return (
        "try { "
        f"Remove-NetFirewallRule -DisplayName '{RULE_NAME}' "
        "-ErrorAction Stop; "
        "} catch { "
        "throw ('could not remove the rule: ' + $_.Exception.Message); "
        "}"
    )


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
    """Is the rule already there?

    The cmdlet, not netsh.  The rule is added with
    New-NetFirewallRule, which names it by its DISPLAY NAME, and
    netsh's "show rule" looks at a different name -- so the two do
    not agree about whether the rule is there.
    """
    if sys.platform != "win32":
        return False
    r = quiet.run_hidden(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         f"(Get-NetFirewallRule -DisplayName '{RULE_NAME}' "
         "-ErrorAction SilentlyContinue | Measure-Object).Count"],
        capture_output=True, text=True, errors="replace", timeout=60)
    try:
        return int((r.stdout or "0").strip()) > 0
    except ValueError:
        return False


# ------------------------------------------------------------- the elevation

import tempfile
import time

from .elevate import ERROR_CANCELLED, POWERSHELL, is_admin
from .elevate import shell_execute_runas as _shell_execute_runas
def _result_file() -> str:
    """Where the elevated process leaves its answer."""
    return os.path.join(tempfile.gettempdir(), "ljt_fw_result.txt")


def elevated_script(body: str, result_path: str = "") -> str:
    """The PowerShell script that does the work, as TEXT.

    It is written to a FILE and run with -File, not passed as a
    -Command argument.  That is the whole reason.

    A -Command argument is one string in one pair of double quotes,
    and everything in it has to survive that: a double quote in it
    ends the argument, and netsh needs double quotes around the
    program path because the path has spaces in it.  So the two
    requirements are in direct conflict, and one of them has to go.

    A FILE has neither problem.  The script is a file, PowerShell
    reads it as PowerShell, and the quoting inside it is the quoting
    PowerShell wants: single quotes for a string, and a double quote
    inside one written as two.

    The script writes its answer into a file and exits: the caller
    reads that file, because the elevated process is detached and its
    exit code is not the caller's to read.

    THE RESULT PATH GOES IN HERE, NOT IN THE ENVIRONMENT.  An
    elevated process does not inherit the environment of the process
    that started it: the elevation goes through the shell's runas
    handler, which builds a fresh environment block.  So a variable
    set here is not there over there, and the answer would be written
    nowhere.
    """
    if result_path:
        # A path can hold a single quote, so the quoting has to
        # survive one: a single quote inside a PowerShell
        # single-quoted string is written as two of them.
        safe = result_path.replace("'", "''")
        out = f"'{safe}'"
    else:
        out = "$env:LJT_FW_RESULT"

    # The output is CAPTURED, not just the exit code: netsh says
    # what went wrong on its output, and "exit=1" with nothing else
    # is not an answer a person can act on.
    #
    # The answer is written as ASCII.  The output of netsh is in the
    # CONSOLE's encoding -- GBK on a Chinese Windows -- and writing
    # those bytes as if they were UTF-8 is what makes them
    # unreadable.  ASCII keeps the exit code and turns the
    # un-encodable characters into '?', which is enough: the exit
    # code is the answer, and the text is the explanation.
    # $LASTEXITCODE is only set by an EXTERNAL command.  The body
    # here is an external command (netsh), so it is set -- but a
    # body that is not one leaves it empty, and an empty code is not
    # a zero.  So it is read and then defaulted:
    #
    #     if ($null -eq $r) { $r = 0 }
    #
    # And the answer is a line that starts with "exit=", so the
    # reader can find the code without knowing anything about the
    # rest of it.
    # A `throw` INSIDE the body is caught here, and the answer file
    # is still written -- with the reason in it.  So a failure the
    # body reports is a failure the caller can read, and the work
    # that was NOT done is not done.
    return (
        "$ErrorActionPreference = 'Continue'\n"
        "$o = ''\n"
        "$r = 0\n"
        "try {\n"
        f"  $o = & {{ {body} }} 2>&1 | Out-String\n"
        "  $r = $LASTEXITCODE\n"
        "} catch {\n"
        "  $o = $_.Exception.Message\n"
        "  $r = 1\n"
        "}\n"
        "if ($null -eq $r) { $r = 0 }\n"
        f"('exit=' + $r + ' ' + $o.Trim()) | Out-File -FilePath {out} "
        "-Encoding ascii\n"
        "exit $r\n"
    )


def _run_elevated(body: str, timeout: float = 90.0) -> tuple:
    """Run BODY as an administrator and wait for its answer.

    Returns (ok, message).

    The person sees the UAC prompt and answers it.  The elevated
    process writes what happened into a file, and this reads it back.
    """
    if sys.platform != "win32":
        return True, "not Windows: no firewall rule needed"

    result = _result_file()
    try:
        if os.path.isfile(result):
            os.remove(result)
    except OSError:
        pass

    # THE PATH IS IN THE SCRIPT, NOT IN THE ENVIRONMENT.
    #
    # An elevated process does NOT inherit the environment of the
    # one that started it: the elevation goes through the shell's
    # runas handler, which builds a fresh environment block.  So a
    # variable set here is not there over there, and the elevated
    # script would write to an empty path and fail.
    #
    # The path goes into the SCRIPT instead, where it cannot be
    # lost.  And it is a path, so it is quoted -- and a Windows path
    # can hold a single quote, so the quoting has to survive that.
    script = elevated_script(body, result)

    # The script goes into a FILE, and PowerShell is told to run the
    # file.  The file is what makes the quoting work: a -Command
    # argument is one string in one pair of double quotes, and netsh
    # needs double quotes around the program path because the path
    # has spaces in it.  Those two requirements cannot both be met
    # in one string.
    script_path = os.path.join(tempfile.gettempdir(), "ljt_fw_script.ps1")
    try:
        with open(script_path, "w", encoding="ascii", errors="replace",
                  newline="\n") as fh:
            fh.write(script)
    except OSError as e:
        return False, f"the script could not be written: {e}"

    arguments = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass '
                 f'-File "{script_path}"')

    code = _shell_execute_runas(POWERSHELL, arguments)
    if code == ERROR_CANCELLED:
        _clean_up(script_path)
        return False, "the UAC prompt was declined -- the rule is not in"
    if code != 0:
        _clean_up(script_path)
        return False, (f"the elevation did not happen (error {code}).\n"
                       "  run this in a terminal running as administrator:\n"
                       "    " + netsh_command())

    # The process was started.  Wait for the file: the answer is in
    # it, and the exit code is not ours to read.
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.isfile(result):
            time.sleep(0.2)          # let the write land
            try:
                with open(result, "r", encoding="ascii",
                          errors="replace") as fh:
                    text = fh.read().strip()
            except OSError:
                text = ""
            if text:
                # The file has the exit code on its first line and
                # whatever the command said on the ones after it.
                # The first line is "exit=N", and whatever the
                # command said is after it.
                first = text.splitlines()[0] if text.splitlines() else ""
                ok = first.strip() == "exit=0"
                _clean_up(script_path)
                if ok:
                    return True, "the rule is in"
                return False, ("the elevated command said: "
                               + text[:250].strip())
        time.sleep(0.3)

    _clean_up(script_path)
    return False, ("the elevated command did not report back.\n"
                   "  run this in a terminal running as administrator:\n"
                   "    " + netsh_command())


def _clean_up(script_path: str) -> None:
    """Take the script file away."""
    try:
        os.remove(script_path)
    except OSError:
        pass


def add_rule() -> tuple:
    """Add the rule. Returns (ok, message).

    The person is asked to confirm it: Windows puts up the UAC prompt
    and they answer it.  Without the elevation it says so, and gives
    the command to run -- because "access denied" with nothing else is
    not an answer a person can act on.
    """
    if sys.platform != "win32":
        return True, "not Windows: no firewall rule needed"

    if is_admin():
        # Already elevated: there is no prompt to show, so the rule
        # is added directly.
        r = quiet.run_hidden(netsh_command().split(), capture_output=True,
                           text=True, errors="replace")
        if r.returncode == 0:
            return True, f"the rule is in: {port_spec()}"
        return False, (r.stdout + r.stderr).strip() or "the rule did not go in"

    ok, msg = _run_elevated(netsh_add_body())
    if ok:
        return True, f"the rule is in: {port_spec()}"
    return False, msg


def remove_rule() -> tuple:
    """Take the rule away again."""
    if sys.platform != "win32":
        return True, "not Windows: no firewall rule to remove"
    if is_admin():
        r = quiet.run_hidden(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
             f"Remove-NetFirewallRule -DisplayName '{RULE_NAME}' "
             f"-ErrorAction SilentlyContinue"],
            capture_output=True, text=True, errors="replace", timeout=60)
        if r.returncode == 0:
            return True, "the rule is gone"
        return False, (r.stdout + r.stderr).strip() or "the rule did not go"

    ok, msg = _run_elevated(netsh_delete_body())
    if ok:
        return True, "the rule is gone"
    return False, msg


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
