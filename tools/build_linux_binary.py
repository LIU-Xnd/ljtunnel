"""Build a single-file Linux binary for the far side.

THE POINT IS A MACHINE THAT CANNOT BE REACHED.  It may have no
Python, no conda and no pip, and it still has to be able to run the
dialer -- which is the side that dials out.  So the binary has to
carry its own interpreter.

BUILD IT ON THE MACHINE IT WILL RUN ON.  A PyInstaller binary links
against the glibc of the system that built it, and glibc only ever
goes forwards: a binary built on Ubuntu 20.04 runs on 20.04 and
anything newer, but one built on 24.04 will not run on 20.04.

Usage:
    python tools/build_linux_binary.py
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "tools" / "freeze_entry.py"
DIST = ROOT / "dist" / "linux"


def log(msg: str) -> None:
    print(msg, flush=True)


def _find_pyinstaller() -> "str | None":
    """The pyinstaller to run.

    It is usually not on PATH when the interpreter is named by its
    full path -- which is how a build is usually run, and how this one
    was run.  A conda env keeps its scripts in the env's own bin
    directory, so that is looked in as well.

    AND IT MUST BE THE ONE THAT BELONGS TO THE INTERPRETER RUNNING
    THE SCRIPT.  `shutil.which("pyinstaller")` finds whatever is on
    PATH, which is not necessarily the one in the environment the
    script is running under -- and a mismatch there produces a
    bundle that is missing things.
    """
    found = shutil.which("pyinstaller")
    if found:
        return found
    bindir = Path(sys.executable).resolve().parent
    for name in ("pyinstaller", "pyinstaller.exe"):
        cand = bindir / name
        if cand.is_file():
            return str(cand)
    return None


def main() -> int:
    if platform.system() != "Linux":
        raise SystemExit(
            "a Linux binary has to be built on Linux: it links against the "
            "glibc of the machine that builds it"
        )
    if not _find_pyinstaller():
        raise SystemExit("pyinstaller is not installed -- pip install pyinstaller")

    import ljtunnel
    log(f"ljtunnel: {ljtunnel.__version__}")
    log(f"python  : {sys.version.split()[0]}  ({platform.platform()})")

    DIST.mkdir(parents=True, exist_ok=True)
    work = ROOT / "build" / "pyinstaller"
    if work.exists():
        shutil.rmtree(work)

    cmd = [
        _find_pyinstaller(),
        "--onefile",              # one file, not a directory of them
        "--name", "ljtunnel",
        "--distpath", str(DIST),
        "--workpath", str(work),
        "--specpath", str(work),
        "--noconfirm",
        "--clean",
        # tkinter is the WINDOW, and the window is not part of the far
        # side -- the far side is the dialer.  Excluding it keeps the
        # binary smaller and pulls in no X11 libraries.
        "--exclude-module", "tkinter",
        "--exclude-module", "unittest",
        "--exclude-module", "pydoc",
        # THE PACKAGE IS IN THE TREE, AND THE TREE IS ON THE PATH.
        #
        # The package is usually installed as an EDITABLE install,
        # which puts a finder in site-packages rather than the
        # package itself.  PyInstaller does not follow those finders,
        # so it does not see the package and the frozen binary comes
        # out with no `ljtunnel` in it:
        #
        #     ModuleNotFoundError: No module named 'ljtunnel'
        #
        # The tree is on the path as well, so the package is found
        # where it really is.
        "--paths", str(ROOT),
        str(ENTRY),
    ]
    log("")
    log("=== pyinstaller ===")
    r = subprocess.run(cmd, cwd=str(ROOT))
    if r.returncode != 0:
        raise SystemExit(f"pyinstaller failed ({r.returncode})")

    out = DIST / "ljtunnel"
    if not out.is_file():
        raise SystemExit(f"no binary at {out}")
    out.chmod(0o755)
    log("")
    log(f"=== {out}  ({out.stat().st_size:,} bytes) ===")
    described = subprocess.run(["file", str(out)], capture_output=True,
                               text=True).stdout.strip()
    log(f"  file: {described or '(no file command)'}")

    # ---- and it RUNS, with nothing on PATH ----
    #
    # A frozen binary that needs something from the system it was
    # built on is not a frozen binary.  And `env -i` is how that is
    # checked: an empty environment, so anything the binary finds is
    # something it carried with it.
    #
    # The PATH matters: with an empty environment there is no PATH,
    # and a command the binary runs -- `ssh`, `ssh-keygen` -- cannot
    # be found.  So the test gives it a PATH and nothing else.
    log("")
    log("=== the binary, with an empty environment ===")
    check = subprocess.run(
        ["env", "-i", f"PATH=/usr/bin:/bin", str(out), "--help"],
        capture_output=True, text=True, timeout=120)
    log(f"  the exit code: {check.returncode}")
    for line in (check.stdout or "").splitlines()[:8]:
        log(f"    {line}")
    if check.returncode != 0:
        log(f"  stderr: {(check.stderr or '')[:400]}")
        raise SystemExit("the binary does not run")
    if "dialer" not in (check.stdout or ""):
        raise SystemExit("the binary does not have the dialer in it")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
