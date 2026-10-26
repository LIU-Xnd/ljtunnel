r"""THE OLD PACKAGE'S METADATA MUST NOT SURVIVE THE UPGRADE.

**THE dist-info DIRECTORY IS NAMED AFTER THE VERSION.**  So an
upgrade that leaves the old one behind gives two:

    ljtunnel-0.5.0.dist-info/
    ljtunnel-0.5.1.dist-info/

and `importlib.metadata.version("ljtunnel")` finds ONE of them --
the first, which is the old one -- and says the package is the
version that was just replaced.  MEASURED, on the installed copy:

    the distribution: 0.5.0
    the fallback:     0.5.1

and the suite's version check goes red on the installed copy while
it is green in the source tree.  The product works; the METADATA is
wrong about it.

**IT IS NOT A CUSTOM ACTION'S JOB.**  The first version of this
tried one, and it broke EVERY install with

    Error 1721: There is a problem with this Windows Installer
    package.  A program required for this install to complete could
    not be run.

and the reasons are worth writing down:

1. **THE `Directory` ATTRIBUTE OF A `<CustomAction>` PUTS THE ACTION
   IN THAT DIRECTORY**, and the action cannot be started in a
   directory that does not exist.  With the site-packages directory
   as the working directory, a FRESH install fails: the directory
   is made by `InstallFiles`, and the action ran before it.

2. **WITH THE PROGRAM'S OWN DIRECTORY AS THE WORKING DIRECTORY, IT
   RUNS, AND STILL FAILS.**  The action type a `<CustomAction>` with
   a `Directory` gets includes
   `msidbCustomActionTypeDirectoryChange` -- "run this again
   whenever a directory changes" -- and that type wants a
   COMPONENT's directory, and the installer has not made it yet at
   that point in the sequence.

3. **AND THE ACTION HAS TO RUN BEFORE `InstallFiles`,** or it takes
   the NEW metadata away with the old one.

So the action cannot be placed where it needs to be.  And it does
not need to be: `RemoveExistingProducts` does the work, and it does
it properly -- the dist-info directory IS a component of the old
package, so the upgrade removes it with the rest of the old
package.

**SO WHAT IS LEFT IS THE CHECK.**  The install has to leave ONE
metadata directory and not two, and the check is that.  It is run
against the INSTALLED copy, because that is where the two would be.
"""
from __future__ import annotations

import glob
import os
import re


# The metadata directories, in an installed copy.
def installed_metadata_dirs(program_dir: str) -> list:
    """Every ljtunnel-*.dist-info in an installed copy."""
    pattern = os.path.join(program_dir, "python", "Lib", "site-packages",
                            "ljtunnel-*.dist-info")
    return sorted(glob.glob(pattern))


def check_installed(program_dir: str) -> tuple:
    """(the count, the directories).  One is what it has to be."""
    dirs = installed_metadata_dirs(program_dir)
    return len(dirs), dirs


def find_program_directory(text: str) -> str:
    """The id of the directory the program goes in, or "".

    The id is pyappdist's own, and it is a hash of the path, so it
    changes when the bundle changes.  So it is LOOKED UP by the
    directory's name -- the name is in the wxs, and the name is what
    the path means.

    It is the directory under "Programs" whose name is the
    program's own: the one the launcher goes in.  The one under
    LocalAppData is the CONFIGURATION directory, which is a
    different thing -- and it has the SAME NAME, so the one under
    "Programs" is the one that is wanted.
    """
    programs = ""
    for m in re.finditer(r'<Directory\s+Id="([^"]+)"\s+Name="([^"]*)"',
                         text):
        if m.group(2) == "Programs":
            programs = m.group(1)
            break
    if not programs:
        return ""

    at = text.find(f'Id="{programs}"')
    if at < 0:
        return ""
    for m in re.finditer(r'<Directory\s+Id="([^"]+)"\s+Name="([^"]*)"',
                         text[at:]):
        if m.group(2) == "ljtunnel":
            return m.group(1)
    return ""


if __name__ == "__main__":
    import sys

    for path in sys.argv[1:]:
        n, dirs = check_installed(path)
        print(f"  {path}: {n} metadata directory(ies)")
        for d in dirs:
            print("   ", d)
