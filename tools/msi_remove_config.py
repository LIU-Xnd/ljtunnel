"""Add "remove the configuration" to the uninstall, and make it a CHOICE.

THE PROBLEM.  Uninstalling ljtunnel leaves the state directory
behind: the two key pairs, the key list, the records, the sshd config
and the log.  They are in %LOCALAPPDATA%\\ljtunnel, and nothing in
the install owns that directory -- it is per-user data, not program
files -- so the uninstaller does not touch it.

That is the RIGHT default.  The keys are the identity of a tunnel:
a machine that cannot be reached is identified by the key it logs in
with, and the listen end's key list names the machines it trusts.
Removing them by default would mean that reinstalling ljtunnel on
one side silently breaks every tunnel that used it.

BUT IT IS ALSO A CHOICE.  A person who is uninstalling because the
machine is being given away does not want the private keys left on
it, and they should not have to go and delete a directory by hand
to find out where it is.

SO THE UNINSTALLER ASKS.

THE QUESTION IS THE EXIT DIALOG'S OWN CHECKBOX
----------------------------------------------
The stock WixUI sets end with an ExitDialog, and it has a checkbox
on it that is HIDDEN unless a property gives it a value:

    <Property Id="WIXUI_EXITDIALOGOPTIONALCHECKBOX" Value="1" />
    <Property Id="WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT"
              Value="the text beside the box" />

MEASURED, by reading the built MSI's own Control table:

    OptionalCheckBox | WIXUI_EXITDIALOGOPTIONALCHECKBOX | CheckBox
    OptionalText    |                                 | Text

So the checkbox appears, it says what it says, and it writes
WIXUI_EXITDIALOGOPTIONALCHECKBOX.

AND THE CHOICE IS THE PROPERTY.  The uninstall asks, and the answer
is read by the action that removes the directory.

WHY NOT A DIALOG OF OUR OWN
---------------------------
A custom dialog would have to live in a custom UI set: WiX v4
refuses a `<Dialog>` as a child of `<Package>`, of `<Fragment>` and
of `<ui:WixUI>`, and it refuses a `<UI>` element altogether:

    The Package element contains an unexpected child element 'UI'

and the dialogs of the stock sets are inside the UI extension, where
they cannot be reached.  So the way to add a page is to COPY
WixUI_InstallDir.wxs into the project and edit the copy, which is a
large file to carry and to keep in step with the WiX it came from.

THE STOCK CHECKBOX IS BETTER THAN THAT: it is the same control the
installer already draws, in the same style, and it needs nothing
copied.

THE SHAPES ARE WiX v4's, and each one cost a probe to find:

  - a `<Condition>` ELEMENT does not go inside `<Component>`,
    `<Directory>`, `<RemoveFolder>` or `<Custom>`.  It goes in a
    sequence, as a child of the element it guards -- and only for
    the elements that take one.

  - for `<Custom>` the condition is an ATTRIBUTE:
        <Custom Action="..." After="..." Condition='X = "1"' />

  - a component with no KeyPath cannot have an automatically
    generated GUID: "Components using a Directory as a KeyPath ...
    cannot use an automatically generated guid".  So the GUID is
    written down.

  - an XML comment cannot hold `--` inside it: the sequence ends the
    comment.  So the dashes in the prose are colons.
"""
from __future__ import annotations

from pathlib import Path

# The property the condition reads.  It is the stock checkbox's own
# property, because that is the checkbox the question is asked with.
PROPERTY = "WIXUI_EXITDIALOGOPTIONALCHECKBOX"

# The property that gives the checkbox its value, and so makes it
# appear at all.
SHOW = "WIXUI_EXITDIALOGOPTIONALCHECKBOX"

# The property that holds the text beside the box.
TEXT = "WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT"

# What the box says.
LABEL = "Remove the configuration and the keys"

# The directory, relative to LocalAppData.  The per-user folder is
# where the state directory lives; see ljtunnel.paths.state_dir().
STATE_SUBPATH = "ljtunnel"

# The GUID of the component that removes the directory.  It cannot be
# generated, because the component has no KeyPath.
REMOVE_GUID = "9C1B4A0E-5D77-4E38-9E2F-6B1D3A7C5E90"

# ---- the fragments that go into the .wxs ------------------------------

# The properties that make the stock checkbox appear, and say what it
# says.
PROPERTY_FRAGMENT = """    <!-- THE QUESTION ON THE UNINSTALL PAGE.  The stock WixUI
         ExitDialog has a checkbox that is hidden unless a property
         gives it a value, and this gives it one.  So the person is
         asked, and the answer is the property the removal reads. -->
    <Property Id="{show}" Value="1" />
    <Property Id="{text}" Value="{label}" />
"""

# The directory, and the component that removes it when the person
# says so.
DIRECTORY_FRAGMENT = """      <!-- THE CONFIGURATION DIRECTORY.  It holds the key
           pairs, the key list, the records and the log.  It is
           per-user data, so the uninstaller does not own it: the
           uninstaller ASKS before taking it away.  The keys are
           the identity of a tunnel, so keeping them is the
           default. -->
      <Directory Id="dir_ljtunnel_state" Name="{sub}">
        <Component Id="cmp_remove_ljtunnel_state" Guid="{guid}">
          <RemoveFolder Id="rm_ljtunnel_state" On="uninstall" />
        </Component>
      </Directory>
"""

# The action that takes the directory away.
#
# It is DEFERRED to the SYSTEM context: the files in the directory
# are the user's, and the uninstall may be run by an administrator
# who is not that user, so the removal has to be able to reach into
# the user's own directory.
#
# `cmd.exe /c rd /s /q` removes a directory with everything in it,
# and says nothing about it.
CUSTOM_ACTION_FRAGMENT = """    <!-- THE ACTION THAT REMOVES THE CONFIGURATION.  It takes the
         state directory away, with everything in it.
         It runs in the PARENT of that directory, NOT in the
         directory itself: Windows will not remove the directory a
         process is standing in, so `rd` run from inside it deletes
         the contents and leaves the empty directory behind.  That
         is what it did, and the test showed it: the files were gone
         and the directory was still there.
         It is deferred to the SYSTEM context, because the files in
         it are the user's and the uninstall may be run by an
         administrator who is not that user. -->
    <CustomAction Id="ca_rm_ljtunnel_state"
                  Directory="LocalAppDataFolder"
                  ExeCommand="cmd.exe /c rd /s /q &quot;[dir_ljtunnel_state]&quot;"
                  Execute="deferred"
                  Impersonate="no" />
"""

# The feature the removal component belongs to.
#
# EVERY COMPONENT NEEDS A PARENT FEATURE, or the build fails:
#
#     Found orphaned Component 'cmp_remove_ljtunnel_state'.  If this
#     is a Package, every Component must have at least one parent
#     Feature.
#
# The feature is a level 1 with nothing in it: the component removes
# a directory, and there is nothing to install.  It is never installed
# and never advertised; it exists so the component has a parent.
FEATURE_FRAGMENT = """    <Feature Id="ft_remove_state" Title="Remove the configuration"
             Level="1" Display="expand">
      <ComponentRef Id="cmp_remove_ljtunnel_state" />
    </Feature>
"""

# Where the removal is scheduled.  The condition is an ATTRIBUTE of
# the Custom element: WiX v4 does not take a Condition element inside
# one.
SEQUENCE_FRAGMENT = """  <!-- AND THE CONFIGURATION GOES WHEN THE PERSON SAYS SO. -->
  <InstallExecuteSequence>
    <Custom Action="ca_rm_ljtunnel_state" After="RemoveFiles" Condition=\'{prop} = "1"\' />
  </InstallExecuteSequence>
"""


def _insert_before(text: str, marker: str, fragment: str) -> str:
    """Put FRAGMENT before MARKER."""
    i = text.find(marker)
    if i < 0:
        return text
    return text[:i] + fragment + text[i:]


def add_remove_configuration(wxs: Path,
                             state_dir_name: str = STATE_SUBPATH) -> bool:
    """Add the removal to the .wxs.  Returns True when it went in.

    The .wxs is pyappdist's, and it is regenerated on every build, so
    this runs every time.  It is therefore IDEMPOTENT: a .wxs that
    already has the property is left alone.
    """
    text = wxs.read_text(encoding="utf-8")

    # The idempotence test is about OUR OWN marker.  The stock
    # property is not a marker: the UI extension's own dialogs put it
    # in the .wxs already, so testing for it would say the removal is
    # there when it is not.
    if "ca_rm_ljtunnel_state" in text:
        return False

    # ---- the question ----
    marker = "    <StandardDirectory"
    if marker not in text:
        return False
    text = _insert_before(text, marker, PROPERTY_FRAGMENT.format(
        show=SHOW, text=TEXT, label=LABEL))

    # ---- the directory and its component ----
    #
    # pyappdist's .wxs ALREADY declares the LocalAppData root:
    #
    #     <StandardDirectory Id="LocalAppDataFolder">
    #
    # so the state directory goes inside it, as a child.  That is the
    # right place: the state directory IS %LOCALAPPDATA%\\ljtunnel.
    marker = '      <Directory Id="dir_programs" Name="Programs">'
    if marker not in text:
        return False
    text = _insert_before(
        text, marker,
        DIRECTORY_FRAGMENT.format(sub=state_dir_name, guid=REMOVE_GUID))

    # ---- the action that removes it ----
    marker = "    <StandardDirectory"
    if marker not in text:
        return False
    text = _insert_before(text, marker, CUSTOM_ACTION_FRAGMENT)

    # ---- the feature the component belongs to ----
    #
    # The closing tag of the package is "  </Package>", at two
    # spaces.  There is no </Product>: in WiX v4 the element is
    # called Package.
    marker = "  </Package>"
    if marker not in text:
        return False
    text = _insert_before(text, marker, FEATURE_FRAGMENT)

    # ---- and the sequence ----
    #
    # pyappdist's .wxs has no execute sequence of its own, so one is
    # added with the removal in it.
    if "<InstallExecuteSequence>" in text:
        text = _insert_before(text, "  </InstallExecuteSequence>",
                              SEQUENCE_FRAGMENT.format(prop=PROPERTY))
    else:
        text = _insert_before(text, "  </Package>",
                              SEQUENCE_FRAGMENT.format(prop=PROPERTY))

    wxs.write_text(text, encoding="utf-8", newline="\n")
    return True


def check(wxs: Path) -> bool:
    """Is the removal in the .wxs?"""
    if not wxs.is_file():
        return False
    text = wxs.read_text(encoding="utf-8")
    return ("ca_rm_ljtunnel_state" in text
            and "RemoveFolder" in text
            and "dir_ljtunnel_state" in text
            and "ft_remove_state" in text)
