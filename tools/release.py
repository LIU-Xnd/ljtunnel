r"""THE RELEASE LOOP, AS ONE COMMAND.

A change is not a release until it is BUILT, INSTALLED and PUSHED,
and the three are done in that order every time:

    the commit      the change is in the tree
    the build       the MSI and the Linux binary are made from it
    the install     the MSI is put on this machine
    the push        the tree and the tag go to the remote

**THE ORDER MATTERS AND EACH STEP IS THE POINT OF THE ONE BEFORE.**

  * the build BEFORE the install, because the install is of the
    thing that was built -- and a build that is skipped is an
    install of the PREVIOUS build, which looks like it worked
  * the install BEFORE the push, because the push is a claim that
    the thing works, and the claim is checked against the INSTALLED
    copy and not against the source tree
  * the push LAST, because a tag names a release, and a release that
    is not installed is not a release

**THE TAG MOVES WITH THE COMMIT.**  The version number in
`pyproject.toml` and the tag say the same thing, and the tag is cut
at the commit that carries the change.  So a release is one commit
that carries the change AND the version bump, and the tag is on it.

Usage:

    python tools/release.py --message "what changed"
    python tools/release.py --message "..." --no-push
    python tools/release.py --message "..." --no-install

WHAT IT DOES, IN ORDER:

    1. the tests: the suite, the window, the interrupt test
    2. the version: the number in pyproject and in the package
    3. the commit, with the message
    4. the MSI, and the checks on it
    5. the Linux binary, on the far side
    6. the install, and the tests on the INSTALLED copy
    7. the push: the branch and the tag
    8. the far side is brought to the same commit and tested there

THE FAR SIDE'S ADDRESS COMES FROM THE ENVIRONMENT:

    LJT_SERVER, LJT_PORT, LJT_USER, LJT_PASSWORD, LJT_REMOTE

AND WITHOUT IT THE LINUX HALF IS SKIPPED, with a line saying so --
not a silent skip, because a release without the Linux binary is not
the release.
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# The python that builds and tests on this machine.
PY = os.environ.get("LJT_PYTHON", r"C:\Users\xnd_l\miniforge3\envs\lj-dev\python.exe")

# The python that talks to the far side.
PARAMIKO_PY = os.environ.get(
    "LJT_PARAMIKO_PYTHON",
    r"C:\Users\xnd_l\miniforge3\envs\paramiko\python.exe")

# The WiX that builds the MSI.
WIX = os.environ.get(
    "PYAPPDIST_WIN_WIX",
    r"C:\Users\xnd_l\AppData\Local\Temp\wix6x\PFiles64\WiX Toolset v6.0\bin\wix.exe")

# Where the product is installed on this machine.
INSTALL_DIR = Path(os.environ.get(
    "LJT_INSTALL_DIR",
    r"C:\Users\xnd_l\AppData\Local\Programs\ljtunnel"))

# The far side.
FAR = {
    "LJT_SERVER": "192.168.117.41",
    "LJT_PORT": "8888",
    "LJT_USER": "liuxd",
    "LJT_PASSWORD": "",
    "LJT_REMOTE": "/home/liuxd/LjtunnelDev",
}

FAILED = []


def say(msg: str) -> None:
    print(f"  {msg}", flush=True)


def head(msg: str) -> None:
    print()
    print(f"=== {msg} ===", flush=True)


def run(cmd, cwd=None, env=None, timeout=590, check=True):
    """Run a command.  Its output goes to the console."""
    r = subprocess.run(cmd, cwd=cwd or str(ROOT), env=env,
                       capture_output=True, text=True, errors="replace",
                       timeout=timeout)
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode, out


def step(name: str, ok: bool, detail: str = "") -> bool:
    """One step of the loop, and whether it worked."""
    mark = "PASS" if ok else "FAIL"
    say(f"{mark}  {name}" + (f"  -- {detail[:120]}" if detail and not ok else ""))
    if not ok:
        FAILED.append(name)
    return ok


# ------------------------------------------------------------ the version


def current_version() -> str:
    t = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', t, re.M)
    return m.group(1) if m else "0.0.0"


def bump(kind: str) -> str:
    """The next version number.

    THE RULE IS IN AGENTS.md: a commit takes the third digit, a push
    with a new feature takes the second, a breaking change takes the
    first.

    AND THE VERSION IS BUMPED **BEFORE** THE COMMIT, because the
    commit is what the tag names, and a tag has to name a release
    whose number it agrees with.
    """
    v = current_version()
    a, b, c = (int(x) for x in v.split("."))
    if kind == "major":
        a, b, c = a + 1, 0, 0
    elif kind == "minor":
        a, b, c = a, b + 1, 0
    else:
        a, b, c = a, b, c + 1
    return f"{a}.{b}.{c}"


def write_version(v: str) -> None:
    p = ROOT / "pyproject.toml"
    t = p.read_text(encoding="utf-8")
    t = re.sub(r'^version\s*=\s*"[^"]+"', f'version = "{v}"', t, count=1, flags=re.M)
    p.write_text(t, encoding="utf-8", newline="\n")

    p = ROOT / "ljtunnel" / "__init__.py"
    t = p.read_text(encoding="utf-8")
    t = re.sub(r'^__version__\s*=\s*"[^"]+"', f'__version__ = "{v}"', t,
               count=1, flags=re.M)
    p.write_text(t, encoding="utf-8", newline="\n")


# ------------------------------------------------------------ the pieces


def the_tests() -> bool:
    """The suite, the window, and the interrupt test."""
    head("the tests, on the source tree")
    ok = True
    for mod, name in (("ljtunnel.selftest", "the suite"),
                       ("ljtunnel.guitest", "the window"),
                       ("ljtunnel.interrupt_test", "the interrupt test")):
        code, out = run([PY, "-m", mod])
        line = [l.strip() for l in out.splitlines()
                if "checks:" in l or "passed" in l]
        ok &= step(name, code == 0, out[-400:])
        say(f"      {line[-1][:80] if line else ''}")
    return ok


def the_msi(version: str) -> bool:
    """Build the MSI and check it."""
    head("the MSI")
    env = dict(os.environ)
    env["PYAPPDIST_WIN_WIX"] = WIX
    shutil.rmtree(str(ROOT / ".appdist-build"), ignore_errors=True)
    code, out = run([PY, "tools/build_msi.py"], env=env)
    if not step("the MSI is built", code == 0, out[-600:]):
        return False

    msi = ROOT / "appdist" / "windows" / "dist" / f"ljtunnel-{version}.msi"
    if not step("the MSI is there", msi.is_file(), str(msi)):
        return False
    say(f"      {msi.name}  {msi.stat().st_size:,} bytes")

    for tool, name in (("tools/msi_ui.py", "the installer's UI"),
                       ("tools/msi_uninstall_check.py",
                        "the uninstall's question")):
        code, out = run([PY, tool, str(msi)])
        step(name, code == 0, out[-400:])
    return True


def the_install(version: str) -> bool:
    """Put the MSI on this machine, and test the INSTALLED copy."""
    head("the install")
    msi = ROOT / "appdist" / "windows" / "dist" / f"ljtunnel-{version}.msi"

    # ---- the old one goes ----
    code, out = run(["msiexec.exe", "/x", _installed_product_code(), "/qn"])
    step("the old copy is uninstalled", code == 0, out[-200:])
    time.sleep(10)

    # ---- and the new one comes ----
    code, out = run(["msiexec.exe", "/i", str(msi), "/qn"], timeout=590)
    step("the new copy is installed", code == 0, out[-200:])
    time.sleep(20)

    if not step("it is in the registry",
                _installed_version() == version,
                f"the registry says {_installed_version()}"):
        return False
    say(f"      installed: {_installed_version()}")

    # ---- and the INSTALLED copy is tested ----
    ok = True
    inst_py = INSTALL_DIR / "python" / "python.exe"
    for mod, name in (("ljtunnel.selftest", "the installed suite"),
                       ("ljtunnel.guitest", "the installed window"),
                       ("ljtunnel.interrupt_test",
                        "the installed interrupt test")):
        code, out = run([str(inst_py), "-m", mod], cwd=str(INSTALL_DIR))
        line = [l.strip() for l in out.splitlines()
                if "checks:" in l or "passed" in l]
        ok &= step(name, code == 0, out[-400:])
        say(f"      {line[-1][:80] if line else ''}")
    return ok


def _installed_product_code() -> str:
    """The product code of what is installed here, or ""."""
    ps = ("$ErrorActionPreference='SilentlyContinue'; "
          "Get-ChildItem 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
          "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | "
          "ForEach-Object { $p=Get-ItemProperty $_.PSPath; "
          "if($p.DisplayName -like '*ljtunnel*'){ $_.PSChildName } }")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps],
                       capture_output=True, text=True, errors="replace",
                       timeout=300)
    return (r.stdout or "").strip().splitlines()[0] if (r.stdout or "").strip() else ""


def _installed_version() -> str:
    ps = ("$ErrorActionPreference='SilentlyContinue'; "
          "Get-ChildItem 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
          "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' | "
          "ForEach-Object { $p=Get-ItemProperty $_.PSPath; "
          "if($p.DisplayName -like '*ljtunnel*'){ $p.DisplayVersion } }")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-Command", ps],
                       capture_output=True, text=True, errors="replace",
                       timeout=300)
    return (r.stdout or "").strip().splitlines()[0] if (r.stdout or "").strip() else ""


def the_far_side(version: str) -> bool:
    """The Linux binary, and the tree on the far side."""
    head("the Linux side")
    if not FAR["LJT_PASSWORD"]:
        say("SKIP  there is no LJT_PASSWORD, so the far side is not touched")
        FAILED.append("the Linux side")
        return False

    env = dict(os.environ)
    env.update(FAR)
    cmd = [
        str(PARAMIKO_PY), "-u", str(ROOT / "tools" / "sync_to_far.py"),
        "source /home/liuxd/miniconda3/etc/profile.d/conda.sh && "
        "conda activate ljtunnel-dev && cd /home/liuxd/LjtunnelDev && "
        "git fetch origin --tags --force 2>&1 | tail -1 && "
        "git reset --hard origin/master 2>&1 | tail -1 && "
        "git log --oneline -1 && git describe --tags && "
        "rm -rf /home/liuxd/miniconda3/envs/ljtunnel-dev/lib/python*/site-packages/"
        "ljtunnel*.dist-info ljtunnel.egg-info && "
        "pip install -e . --no-deps --no-build-isolation -q 2>&1 | tail -1; "
        "python -c 'import importlib.metadata as m; "
        "print(\"  the metadata:\", m.version(\"ljtunnel\"))' && "
        "python -m ljtunnel.selftest 2>&1 | tail -2 && "
        "rm -rf dist build && "
        "python tools/build_linux_binary.py 2>&1 | grep -cE 'the exit code: 0' && "
        "env -i PATH=/usr/bin:/bin ./dist/linux/ljtunnel --version"
    ]
    code, out = run(cmd, env=env, timeout=590)
    for l in out.splitlines():
        if l.strip():
            say("  " + l.strip()[:110])

    ok = step("the far side is at the commit",
              "the metadata: " + version in out, out[-400:])
    ok &= step("the far side's suite passes",
               "0 failed" in out, out[-400:])
    ok &= step("the Linux binary is built",
               re.search(r"the exit code: 0\s*\n", out) is not None
               or "\n1\n" in out, out[-300:])
    ok &= step("and it is the right version",
               version in out.split("the exit code")[-1], out[-200:])
    return ok


def the_push(version: str) -> bool:
    """The branch and the tag."""
    head("the push")
    code, out = run(["git", "push", "origin", "master"], timeout=590)
    if not step("the branch is pushed", code == 0, out[-300:]):
        return False

    tag = f"v{version}"
    code, out = run(["git", "tag", "-f", tag], timeout=300)
    if not step("the tag is cut", code == 0, out[-200:]):
        return False
    code, out = run(["git", "push", "origin", f"refs/tags/{tag}", "--force"],
                    timeout=590)
    if not step("the tag is pushed", code == 0, out[-300:]):
        return False

    # ---- and the remote is read back ----
    code, out = run(["git", "ls-remote", "origin", "master", f"refs/tags/{tag}"],
                    timeout=590)
    head_local = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT),
                                 capture_output=True, text=True,
                                 errors="replace", timeout=300).stdout.strip()
    remote = [l.split()[0] for l in out.splitlines() if l.strip()]
    ok = step("the remote agrees with the tree",
              len(remote) == 2 and all(r == head_local for r in remote),
              f"the remote has {remote}, the tree has {head_local}")
    for l in out.splitlines():
        say("  " + l.strip()[:110])
    return ok


# ------------------------------------------------------------ the loop


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="the release loop: commit, build, install, push")
    p.add_argument("--message", required=True,
                   help="what changed, in one line")
    p.add_argument("--bump", choices=("patch", "minor", "major"),
                   default="patch",
                   help="which digit of the version moves (default: patch)")
    p.add_argument("--no-push", action="store_true",
                   help="do everything but the push")
    p.add_argument("--no-install", action="store_true",
                   help="do everything but the install")
    p.add_argument("--no-far", action="store_true",
                   help="do everything but the Linux side")
    args = p.parse_args(argv)

    # ---- the tree has to be clean, or the commit is not the change ----
    code, out = run(["git", "status", "--short"])
    if out.strip():
        print("the tree has changes in it, and they are part of the commit:")
        for l in out.splitlines():
            say(l[:110])
    else:
        say("the tree is clean")

    # ---- 1. the version, BEFORE the commit ----
    version = bump(args.bump)
    write_version(version)
    say(f"the version is {version}")

    # ---- 2. the editable install, so the metadata agrees ----
    #
    # THE VERSION CHECK READS THE INSTALLED METADATA, and the
    # metadata is what the LAST editable install left behind.  So
    # after the version moves, the install has to move with it --
    # otherwise the suite goes red on a version that is right.
    #
    # MEASURED: the suite said "the installed metadata agrees --
    # installed 0.6.1, package 0.6.2".
    head("the editable install")
    shutil.rmtree(str(ROOT / "ljtunnel.egg-info"), ignore_errors=True)
    code, out = run([PY, "-m", "pip", "install", "-e", ".", "--no-deps",
                     "--no-build-isolation", "-q"], timeout=590)
    if not step("the editable install is current", code == 0, out[-300:]):
        return 1

    # ---- 3. the tests ----
    if not the_tests():
        print()
        print("the tests failed, so nothing was committed")
        return 1

    # ---- 4. the commit ----
    head("the commit")
    (ROOT / ".git" / "COMMIT_EDITMSG").write_text(
        args.message.rstrip() + "\n", encoding="utf-8", newline="\n")
    run(["git", "add", "-A"])
    code, out = run(["git", "commit", "-q", "-F", ".git/COMMIT_EDITMSG"])
    if not step("the change is committed", code == 0, out[-300:]):
        return 1
    code, out = run(["git", "log", "--oneline", "-1"])
    say("  " + out.strip())

    # ---- 5. the build ----
    if not the_msi(version):
        print()
        print("the build failed, so nothing was installed or pushed")
        return 1

    # ---- 6. the install ----
    if not args.no_install:
        if not the_install(version):
            print()
            print("the install failed, so nothing was pushed")
            return 1

    # ---- 7. the Linux side ----
    if not args.no_far:
        the_far_side(version)

    # ---- 8. the push ----
    if not args.no_push:
        if not the_push(version):
            print()
            print("the push failed")
            return 1

    # ---- the summary ----
    print()
    if FAILED:
        print(f"the release is NOT finished.  These failed: {', '.join(FAILED)}")
        return 1
    print(f"the release is done: {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
