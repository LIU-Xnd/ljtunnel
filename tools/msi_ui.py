#!/usr/bin/env python3
"""Switch an MSI's installer UI set and check it for error 2819.

Two subcommands, because they answer two different questions:

``switch``
    Point a generated ``.wxs`` at a different stock WiX UI set. Used when
    the default set has no page the user needs -- ``WixUI_Minimal`` has
    no folder page, ``WixUI_InstallDir`` does. Also adds the property
    the folder page binds to.

``check``
    Read a built MSI and report whether it would raise error 2819
    ("Control [3] on dialog [2] needs a property linked to it").

``launcher``
    Check a Windows launcher: its PE subsystem, and whether the
    installed copy opens its window when started with no arguments.
    A ``gui = true`` launcher has no console, so "it printed nothing"
    is indistinguishable from "it did nothing".

Why ``check`` has to exist
--------------------------
2819 only fires when the installer actually SHOWS the page with the
offending control. A silent install (``msiexec /i ... /qn``) never
shows it and always succeeds, so "it installed" proves nothing about
the UI. The check asks the same question the installer asks, by
reading the MSI's own Control and Property tables.

Requires ``msilib``, which was removed in Python 3.13 -- run it with
Python 3.12 or earlier.

Usage:
    python msi_ui.py switch <file.wxs> [--ui WixUI_InstallDir]
                                       [--dir-id INSTALLFOLDER]
    python msi_ui.py check  <file.msi>
    python msi_ui.py launcher <exe> [--expect-window TITLE]
"""
from __future__ import annotations

import argparse
import sys
import warnings
from pathlib import Path

# The properties Windows Installer and the stock WiX UI sets create at
# RUN TIME. A control bound to one of these is fine -- the package is
# not supposed to define them.
RUNTIME_PROPERTIES = {
    "LicenseAccepted",              # the licence page's checkbox
    "FileInUseProcess",             # the FilesInUse list
    "WIXUI_EXITDIALOGOPTIONALCHECKBOX",
    "WIXUI_INSTALLDIR_VALID",
    "WIXUI_DONTVALIDATEPATH",
    "WixUI_InstallMode",
    "WixAppFolder",
    "ApplicationFolderName",
    "MsiLogFileLocation",
    "ARPINSTALLLOCATION",
}


def switch(wxs: Path, ui: str, dir_id: str) -> bool:
    """Point the .wxs at `ui`, and define the property its pages need.

    Returns True if the file changed.
    """
    text = wxs.read_text(encoding="utf-8")

    # 1. the UI set itself
    old_ui = '<ui:WixUI Id="WixUI_Minimal" />'
    new_ui = f'<ui:WixUI Id="{ui}" />'
    changed = False

    if f'<ui:WixUI Id="{ui}"' not in text:
        if old_ui not in text:
            raise SystemExit(
                f"{wxs}: expected {old_ui!r} and found no <ui:WixUI> element "
                f"for {ui!r} -- the generator's output shape changed"
            )
        text = text.replace(old_ui, new_ui, 1)
        changed = True

    # 2. the property the folder page binds to.
    #
    # The stock WixUI_InstallDir set's "Destination Folder" page has a
    # PathEdit control bound to WIXUI_INSTALLDIR, and the set does NOT
    # define that property -- the package has to. Without it the
    # installer stops with error 2819 (wixtoolset/issues#818).
    #
    # The value is the directory's Id, NOT a reference to it. A value
    # like "[INSTALLFOLDER]" is a property reference, which wix warns
    # about (WIX1077) and the installer does not resolve -- the page
    # would show the literal text.
    prop = f'<Property Id="WIXUI_INSTALLDIR" Value="{dir_id}" />'
    if 'Id="WIXUI_INSTALLDIR"' not in text:
        anchor = f"    {new_ui}\n"
        if anchor not in text:
            raise SystemExit(f"{wxs}: cannot find where to put the property")
        text = text.replace(anchor, anchor + f"    {prop}\n", 1)
        changed = True

    if changed:
        wxs.write_text(text, encoding="utf-8")
    return changed


def check(msi: Path) -> int:
    """Report whether the MSI would raise error 2819. 0 = clean."""
    warnings.filterwarnings("ignore")
    try:
        import msilib
    except ImportError:
        print("msilib is not available in this Python (it was removed in "
              "3.13).\nRun this check with Python 3.12 or earlier.",
              file=sys.stderr)
        return 2

    db = msilib.OpenDatabase(str(msi), msilib.MSIDBOPEN_READONLY)

    def rows(sql):
        view = db.OpenView(sql)
        view.Execute(None)
        out = []
        while True:
            rec = view.Fetch()
            if rec is None:
                break
            out.append(rec)
        return out

    props = {r.GetString(1) for r in rows("SELECT `Property` FROM `Property`")}

    print(f"=== {msi} ===")
    print(f"  properties defined: {len(props)}")

    bad = []
    checked = 0
    for r in rows("SELECT `Dialog_`,`Control`,`Property` FROM `Control`"):
        dialog, control, prop = r.GetString(1), r.GetString(2), r.GetString(3)
        if not prop or prop.startswith("_") or prop in RUNTIME_PROPERTIES:
            continue
        checked += 1
        if prop not in props:
            bad.append((dialog, control, prop))

    print(f"  controls bound to a package property: {checked}")

    # the folder page, if there is one
    folder = [r.GetString(3) for r in rows(
        "SELECT `Dialog_`,`Control`,`Property` FROM `Control` "
        "WHERE `Dialog_` = 'InstallDirDlg' AND `Control` = 'Folder'")]
    if folder:
        p = folder[0]
        state = "defined" if p in props else "MISSING"
        print(f"  InstallDirDlg/Folder -> {p}: {state}")
        if p not in props and not any(b[1] == "Folder" for b in bad):
            bad.append(("InstallDirDlg", "Folder", p))

    if bad:
        print()
        print("*** error 2819 waiting to happen ***")
        for d, c, p in bad:
            print(f"    Control {c} on dialog {d} needs a property linked to it")
        print()
        print("  Fix: add <Property Id=\"%s\" Value=\"<directory id>\" /> "
              "to the .wxs" % bad[0][2])
        return 1

    print("  ok: no 2819")
    return 0


def _pe_subsystem(path: Path) -> int:
    """The PE subsystem: 2 = GUI (no console), 3 = console.

    The offset to the PE header is at 0x3c; the subsystem field is at
    pe + 0x5c.
    """
    data = path.read_bytes()
    pe = int.from_bytes(data[0x3C:0x40], "little")
    return int.from_bytes(data[pe + 0x5C:pe + 0x5E], "little")


def launcher(exe: Path, expect_window: str | None) -> int:
    """Check a Windows launcher: its subsystem, and whether it opens a
    window when started with no arguments.

    The no-argument path is the one the Start Menu shortcut uses, and
    it is not the same path as an explicit subcommand.
    """
    import subprocess
    import time

    if not exe.is_file():
        print(f"{exe}: not there")
        return 1

    subsys = _pe_subsystem(exe)
    kind = "GUI (no console)" if subsys == 2 else "console"
    print(f"=== {exe} ===")
    print(f"  subsystem: {subsys} ({kind})")

    if expect_window is None:
        print("  (no --expect-window given; not launching it)")
        return 0

    print(f"  launching with no arguments, looking for a window titled "
          f"{expect_window!r} ...")
    subprocess.Popen([str(exe)])

    deadline = time.time() + 30
    found = ""
    while time.time() < deadline:
        time.sleep(1.0)
        # List the visible window titles. Asking PowerShell for the
        # process by name and then reading its title is two round trips
        # and races the window creation; one listing is enough.
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-Process | Where-Object { $_.MainWindowTitle -ne '' } | "
             "ForEach-Object { $_.MainWindowTitle }"],
            capture_output=True, text=True)
        titles = [t.strip() for t in out.stdout.splitlines() if t.strip()]
        if expect_window in titles:
            found = expect_window
            break

    if found:
        print(f"  ok: the window {found!r} opened")
        return 0
    print(f"  FAIL: no window titled {expect_window!r} appeared")
    print("  A GUI launcher (subsystem 2) has no console: if the program")
    print("  prints usage instead of opening its window, the output goes")
    print("  nowhere and the process exits silently.")
    return 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("switch", help="point a .wxs at a different UI set")
    s.add_argument("wxs", type=Path)
    s.add_argument("--ui", default="WixUI_InstallDir")
    s.add_argument("--dir-id", default="INSTALLFOLDER",
                   help="the directory the folder page moves")

    c = sub.add_parser("check", help="check a built MSI for error 2819")
    c.add_argument("msi", type=Path)

    l = sub.add_parser("launcher", help="check a Windows launcher")
    l.add_argument("exe", type=Path)
    l.add_argument("--expect-window", default=None,
                   help="window title to look for after launching it")

    args = ap.parse_args(argv)
    if args.cmd == "switch":
        changed = switch(args.wxs, args.ui, args.dir_id)
        print(f"{'changed' if changed else 'already'}  {args.wxs}")
        return 0
    if args.cmd == "launcher":
        return launcher(args.exe, args.expect_window)
    return check(args.msi)


if __name__ == "__main__":
    raise SystemExit(main())
