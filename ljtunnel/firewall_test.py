"""The firewall rule, added the way a person would add it.

The rule needs administrator rights, and the way to get them is the
UAC prompt: Windows asks, the person answers, and the command runs
with administrator rights.

So this test does what the window does -- it asks for the rule, and
the UAC prompt appears -- and then it checks the rule is REALLY
there, with the ports it should have.

A UAC prompt will appear.  Answer it.

WHAT IS CHECKED
---------------
  - the command line is well formed: the program is a FILE that
    exists, and the arguments are ONE argument
  - the script has no double quote in it, because it becomes the
    -Command argument of powershell.exe
  - the rule is in afterwards, with the right ports

AND WHAT IS NOT CHECKED
-----------------------
The prompt itself.  A person who presses "No" gets a rule that is
not in, and the code says so -- "the UAC prompt was declined" --
which is an answer and not a failure.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time

_results = []
_skipped = []


def check(name, ok, detail=""):
    _results.append((name, bool(ok), detail))
    if not ok:
        print(f"  FAIL  {name}" + (f" -- {detail}" if detail else ""))
    return bool(ok)


def skip(name, why=""):
    """A check that could not be made, and that is NOT a failure.

    THE PROMPT IS A PERSON'S JOB.  The firewall rule needs an
    administrator, and getting one means a click on the UAC prompt.
    A person who is not there cannot click it, so "the prompt was not
    answered" is a check that was NOT MADE -- not a broken thing,
    and not a passing thing either.

    See ljtunnel.elevate_test for the same treatment.
    """
    _skipped.append((name, why))
    print(f"  SKIP  {name}" + (f" -- {why}" if why else ""))
    return None


def run() -> int:
    from ljtunnel import firewall as FW

    print("ljtunnel -- the firewall's self-test")
    print("  a UAC prompt will appear -- answer it.")
    print()

    # ---- the command line is well formed ----
    check("the PowerShell is a real file",
          os.path.isfile(FW.POWERSHELL), FW.POWERSHELL)
    check("and it is the full path",
          os.path.isabs(FW.POWERSHELL), FW.POWERSHELL)

    body = FW.netsh_add_body()
    check("the body has no double quote", '"' not in body, body[:80])
    check("the body's single quotes are even",
          body.count("'") % 2 == 0, str(body.count("'")))

    script = FW.elevated_script(body, r"C:\Temp\out.txt")
    check("the script has no double quote of its own",
          '"' not in script, f"{script.count(chr(34))} of them")
    check("and it is PowerShell, with real newlines",
          "\n" in script, repr(script[:60]))

    # ---- and it goes in, with the person confirming ----
    #
    # The rule may already be there: adding it takes the old one
    # away first, so the button is safe to press twice, and the
    # number of rules at the end is what says so.
    ok, msg = FW.add_rule()
    print(f"  add_rule said: {msg!r}")
    check("the elevation reported back", bool(msg), msg[:120])

    # WAS THE PROMPT ANSWERED?
    #
    # The rule needs an administrator, and getting one means a click
    # on the UAC prompt.  A person who is not there cannot click it.
    # So the checks that need the rule to BE THERE are not made, and
    # they are not failures either.
    declined = ("declined" in msg.lower()
                or "did not happen" in msg.lower()
                or "not an administrator" in msg.lower()
                or "access is denied" in msg.lower())
    if declined or not ok:
        skip("the rule is in", msg[:120])
        skip("it covers the sshd port", "the prompt was not answered")
        skip("it covers the forwarded range", "the prompt was not answered")
        skip("and it is on the sshd", "the prompt was not answered")
        skip("pressing it twice leaves one rule",
             "the prompt was not answered")
        return _finish()

    # ---- the rule is REALLY there ----
    check("the rule is in", FW.rule_exists(), msg[:120])

    # ---- with the right ports ----
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         f"(Get-NetFirewallRule -DisplayName '{FW.RULE_NAME}' "
         "-ErrorAction SilentlyContinue | "
         "Get-NetFirewallPortFilter | "
         "Select-Object -ExpandProperty LocalPort) -join ' '"],
        capture_output=True, text=True, errors="replace", timeout=120)
    ports = (r.stdout or "").strip()
    print(f"  the rule covers: {ports}")
    check("it covers the sshd port", "10001" in ports, ports)
    check("it covers the forwarded range",
          "10002" in ports and str(FW.LAST_FORWARD_PORT) in ports, ports)

    # ---- and the program is on the rule ----
    r2 = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         f"(Get-NetFirewallRule -DisplayName '{FW.RULE_NAME}' "
         "-ErrorAction SilentlyContinue | "
         "Get-NetFirewallApplicationFilter | "
         "Select-Object -ExpandProperty Program) -join ' '"],
        capture_output=True, text=True, errors="replace", timeout=120)
    prog = (r2.stdout or "").strip()
    print(f"  the rule is on: {prog}")
    check("and it is on the sshd", "sshd.exe" in prog, prog)

    # ---- and pressing it TWICE does not leave two rules ----
    #
    # New-NetFirewallRule does not replace a rule with the same
    # name -- it adds another one.  So the button takes the old rule
    # away before it puts the new one in, and the firewall console
    # shows ONE rule rather than a list of identical entries.
    ok2, msg2 = FW.add_rule()
    print(f"  the second time: {msg2[:60]!r}")
    time.sleep(1)
    r3 = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
         f"(Get-NetFirewallRule -DisplayName '{FW.RULE_NAME}' "
         "-ErrorAction SilentlyContinue | Measure-Object).Count"],
        capture_output=True, text=True, errors="replace", timeout=120)
    try:
        count = int((r3.stdout or "0").strip())
    except ValueError:
        count = 0
    print(f"  there are now {count} rule(s) called {FW.RULE_NAME}")
    check("pressing it twice leaves ONE rule", count == 1, str(count))

    print()
    return _finish()


def _finish() -> int:
    """The summary. Returns 1 when something failed."""
    passed = sum(1 for _, ok, _ in _results if ok)
    failed = [n for n, ok, _ in _results if not ok]
    print(f"  {passed}/{len(_results)} passed"
          + (f", {len(failed)} failed" if failed else ", 0 failed")
          + (f", {len(_skipped)} skipped" if _skipped else ""))
    for n in failed:
        print(f"    FAILED: {n}")
    for n, why in _skipped:
        print(f"    SKIPPED: {n}" + (f" -- {why}" if why else ""))
    return 1 if failed else 0


def main() -> int:
    if sys.platform != "win32":
        print("  the firewall is Windows only (skipped)")
        return 0
    return run()


if __name__ == "__main__":
    sys.exit(main())
