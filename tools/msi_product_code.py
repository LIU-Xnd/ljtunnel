"""Make the MSI's ProductCode a function of its UpgradeCode and version.

THE PROBLEM.  pyappdist generates a RANDOM ProductCode on every
build.  The ProductCode is what Windows Installer matches an install
against: a package whose ProductCode is already installed is not a
reinstall, it is a DIFFERENT PRODUCT, and the install is refused:

    Exit code 67: another version of this product is already
    installed

and from the other side, uninstalling the previous build of the same
version says:

    Exit code 69: cannot uninstall, another product is installed

So every rebuild of the same version produced a package that could
not be installed over the previous one, and the way out -- uninstall
by the OLD package -- was gone, because the old package had been
overwritten.

THE FIX.  The ProductCode is DERIVED from the UpgradeCode and the
version, so it is the same for the same version every time, and
different for a different version -- which is what makes the upgrade
work.

THE DERIVATION IS A UUID, and not a hand-built one.

    uuid.uuid5(NAMESPACE, upgrade_code + version)

A UUID5 is a HASH of a name in a namespace, so it is:
  - the same for the same name, on every machine, forever
  - different for a different name
  - a valid GUID, which Windows Installer will accept

A hand-built one -- putting the version's numbers into the
UpgradeCode's fields -- is the obvious thing and it does not work:
the fields have fixed widths, and the version's numbers do not fit
them.  0.5.0 needs two digits where the field has one, so the GUID
comes out malformed and Windows Installer refuses it.

The namespace is a fixed one, so the derivation does not change
between builds of this tool.  A DIFFERENT namespace would give
different codes for the same version, which is the bug being fixed.
"""
from __future__ import annotations

import re
import uuid
from pathlib import Path


# THE NAMESPACE.  It is fixed, so the derivation does not change
# between builds of this tool -- a different namespace would give
# different codes for the same version, which is the bug being
# fixed.
NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00cf4fc964ff")


def derive_product_code(upgrade_code: str, version: str) -> str:
    """The ProductCode for this upgrade code and this version."""
    upgrade_code = upgrade_code.strip().strip("{}")
    # the version is padded to four numbers, because "0.5" and
    # "0.5.0" are the same version and must give the same code
    nums = version.strip().split(".")
    while len(nums) < 4:
        nums.append("0")
    name = upgrade_code + "." + ".".join(nums)
    return "{" + str(uuid.uuid5(NAMESPACE, name)).upper() + "}"


def set_product_code(wxs: Path) -> bool:
    """Put the derived ProductCode into the .wxs.

    Returns True when it went in.
    """
    text = wxs.read_text(encoding="utf-8")

    m = re.search(r'UpgradeCode="([^"]+)"', text)
    if not m:
        return False
    upgrade_code = m.group(1)

    m = re.search(r'Version="([^"]+)"', text)
    if not m:
        return False
    version = m.group(1)

    code = derive_product_code(upgrade_code, version)

    # ---- the Package element's ProductCode ----
    #
    # THE OLD ONE IS REMOVED FIRST, and the new one goes in once.
    # Doing it in two steps -- remove, then insert -- put the
    # attribute in TWICE, and an element with the same attribute
    # twice is not an element the compiler will take.
    new = re.sub(r'\s+ProductCode="[^"]*"', "", text, count=1)

    # and it goes in right after the Name
    new, n = re.subn(r'(<Package\b[^>]*?\bName="[^"]*")',
                     r'\1 ProductCode="%s"' % code, new, count=1)
    if n == 0:
        return False
    if new.count("ProductCode=") != 1:
        return False

    # ---- AND THE SAME VERSION MUST BE ALLOWED TO REPLACE ITSELF ----
    #
    # <MajorUpgrade> WITHOUT AllowSameVersionUpgrades says no to a
    # package of the SAME version as the one that is installed:
    #
    #     Exit code 67: another version of this product is already
    #     installed
    #
    # And the uninstall of the installed one says:
    #
    #     Exit code 69: cannot uninstall, another product is
    #     installed
    #
    # So rebuilding the same version and installing it over the
    # previous build was impossible.  With the attribute it is a
    # repair, which is what it is.
    #
    # AllowDowngrades stays off: a downgrade is a mistake, and the
    # package says so with a message.
    if "MajorUpgrade" in new and "AllowSameVersionUpgrades" not in new:
        new = re.sub(r'<MajorUpgrade\b',
                     '<MajorUpgrade AllowSameVersionUpgrades="yes" ',
                     new, count=1)

    wxs.write_text(new, encoding="utf-8", newline="\n")
    return True


def check(wxs: Path) -> bool:
    """Is the ProductCode the derived one?"""
    if not wxs.is_file():
        return False
    text = wxs.read_text(encoding="utf-8")
    m = re.search(r'UpgradeCode="([^"]+)"', text)
    m2 = re.search(r'Version="([^"]+)"', text)
    m3 = re.search(r'ProductCode="([^"]+)"', text)
    if not (m and m2 and m3):
        return False
    try:
        want = derive_product_code(m.group(1), m2.group(1))
    except ValueError:
        return False
    return m3.group(1) == want
