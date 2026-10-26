"""Does the app start ITSELF as an administrator?

The window needs administrator rights for exactly one thing: the
firewall rule.  So the app asks to be an administrator ONCE, at the
start, and the firewall button needs no prompt of its own afterwards.

This test asks the question directly: does the elevation start a
process that IS an administrator?

A UAC prompt will appear.  Answer it.  The elevated copy writes what
it found into a file, and this reads it back.
"""
from __future__ import annotations

import os
import pathlib
import sys
import time

_results = []


def check(name, ok, detail=""):
    _results.append((name, bool(ok), detail))
    if not ok:
        print(f"  FAIL  {name}" + (f" -- {detail}" if detail else ""))
    return bool(ok)


def run() -> int:
    from ljtunnel import elevate

    root = str(pathlib.Path(__file__).resolve().parent.parent)
    sys.path.insert(0, root)

    temp = pathlib.Path(os.environ["TEMP"])
    marker = temp / "ljt_elevated_marker.txt"
    errfile = temp / "ljt_elevated_marker.err"
    probe = temp / "ljt_elevated_probe.py"

    for f in (marker, errfile):
        if f.is_file():
            f.unlink()

    # ---- the parts ----
    check("the elevation is available",
          hasattr(elevate, "shell_execute_runas"))
    check("the launcher is found", bool(elevate._installed_launcher()),
          elevate._installed_launcher() or "(not found)")
    check("the interpreter without a console is found",
          bool(elevate._pythonw()), elevate._pythonw() or "(not found)")
    check("this process is not an administrator", not elevate.is_admin())

    # ---- the probe: it writes what it is, and what went wrong ----
    probe.write_text(
        "import sys, traceback\n"
        "try:\n"
        f"    sys.path.insert(0, {root!r})\n"
        "    from ljtunnel import elevate\n"
        f"    with open(r'{marker}', 'w') as fh:\n"
        "        fh.write('admin' if elevate.is_admin() else 'not-admin')\n"
        "except Exception:\n"
        f"    with open(r'{errfile}', 'w') as fh:\n"
        "        fh.write(traceback.format_exc())\n",
        encoding="utf-8", newline="\n")

    # ---- the relaunch ----
    print("  a UAC prompt will appear -- answer it.")
    code = elevate.shell_execute_runas(elevate._pythonw(), f'"{probe}"')
    check("the elevated process was started", code == 0, f"code {code}")

    deadline = time.time() + 60
    while time.time() < deadline:
        if marker.is_file() or errfile.is_file():
            break
        time.sleep(0.5)

    if marker.is_file():
        text = marker.read_text(encoding="utf-8").strip()
        check("the elevated copy IS an administrator", text == "admin", text)
    elif errfile.is_file():
        check("the elevated copy IS an administrator", False,
              errfile.read_text(encoding="utf-8", errors="replace")[:200])
    else:
        check("the elevated copy IS an administrator", False,
              "it wrote nothing -- was the prompt declined?")

    for f in (marker, errfile, probe):
        try:
            f.unlink()
        except OSError:
            pass

    passed = sum(1 for _, ok, _ in _results if ok)
    failed = [n for n, ok, _ in _results if not ok]
    print(f"  {passed}/{len(_results)} passed"
          + (f", {len(failed)} failed" if failed else ", 0 failed"))
    for n in failed:
        print(f"    FAILED: {n}")
    return 1 if failed else 0


def main() -> int:
    if sys.platform != "win32":
        print("  the elevation is Windows only (skipped)")
        return 0
    print("ljtunnel -- the elevation's self-test")
    return run()


if __name__ == "__main__":
    sys.exit(main())
