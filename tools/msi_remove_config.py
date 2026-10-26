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


# THE PROPERTY THAT HOLDS THE ANSWER.
#
# IT IS NOT THE CHECKBOX'S OWN PROPERTY, and that is the whole
# difficulty.
#
# The stock ExitDialog's checkbox writes into
# WIXUI_EXITDIALOGOPTIONALCHECKBOX, and it only APPEARS if that
# property has a value.  So the value that makes it appear and the
# value that says the person ticked it are the same property, and
# they cannot be the same thing:
#
#   - if the property is set to 1 so the box shows, the condition
#     `WIXUI_EXITDIALOGOPTIONALCHECKBOX = "1"` is ALWAYS TRUE, and
#     the configuration is removed on EVERY uninstall.  MEASURED:
#     that is exactly what happened.
#
#   - if the property is not set, the box does not show at all.
#
# SO THE ANSWER IS COPIED INTO A PROPERTY OF OUR OWN, in the UI
# sequence, just after the dialog that asks the question.  The
# condition then reads OUR property, which is empty until the person
# ticks the box.
# THE PROPERTY THE CONDITION READS IS THE CHECKBOX'S OWN.
#
# The stock ExitDialog's checkbox writes "1" into it when it is
# ticked, and leaves it EMPTY when it is not.  So the condition
#
#     WIXUI_EXITDIALOGOPTIONALCHECKBOX = "1"
#
# is true exactly when the person ticked the box.
#
# And it is NOT given a value in the package, because the box's
# VISIBILITY is decided by the TEXT property, not by this one.  Give
# this one a value and the condition is always true.
CHECKED = "WIXUI_EXITDIALOGOPTIONALCHECKBOX"

# The property the condition reads.
PROPERTY = CHECKED

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
PROPERTY_FRAGMENT = """    <!-- THE QUESTION ON THE UNINSTALL PAGE.

         THE STOCK ExitDialog's CHECKBOX IS SHOWN WHEN THE TEXT
         PROPERTY HAS A VALUE, and the TEXT property is what the box
         says.  Its own property is the one the box WRITES, and it is
         EMPTY until the box is ticked.

         So only the text property is set here.  Setting the
         checkbox's own property as well is the mistake: it is set to
         1 so the box appears, and then the condition that reads it
         is ALWAYS TRUE, and the configuration goes on every
         uninstall.  MEASURED: that is exactly what happened, and the
         trace named the action.

         The condition therefore reads the checkbox's own property,
         which is empty when the box is not ticked and "1" when it
         is. -->
    <Property Id="{text}" Value="{label}" />
"""

# The directory, and the component that removes it when the person
# says so.
# THE CONFIGURATION DIRECTORY.
#
# IT IS DECLARED AND NOT FILLED.  There is no <RemoveFolder> in it,
# because a <RemoveFolder On="uninstall"> removes the directory on
# EVERY uninstall, and the whole point is that it is removed only
# when the person says so.
#
# There is no way to put a condition on a <RemoveFolder> in WiX v4:
# a <Condition> ELEMENT is not accepted inside a <Component> or
# inside a <RemoveFolder>, and neither takes a Condition attribute.
# So the directory is removed by the CUSTOM ACTION, which does take
# a condition -- and the directory is declared here so that the
# action has a directory to work in and the installer knows the
# path.
DIRECTORY_FRAGMENT = """      <!-- THE CONFIGURATION DIRECTORY.  It holds the key
           pairs, the key list, the records and the log.  It is
           per-user data, so the uninstaller does not own it: the
           uninstaller ASKS before taking it away.  The keys are
           the identity of a tunnel, so keeping them is the
           default.
           There is no RemoveFolder here on purpose: it cannot be
           conditioned, so it would remove the directory on EVERY
           uninstall.  The custom action removes it, and that one
           CAN be conditioned. -->
      <Directory Id="dir_ljtunnel_state" Name="{sub}">
        <Component Id="cmp_remove_ljtunnel_state" Guid="{guid}">
          <RegistryKey Root="HKCU" Key="Software\\ljtunnel">
            <RegistryValue Name="StateDirectory" Type="string"
                           Value="{sub}" KeyPath="yes" />
          </RegistryKey>
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
# THE ACTION, SCHEDULED.
#
# IT IS AN UNINSTALL-TIME ACTION.  Scheduled in the install sequence
# it runs on EVERY install, and it takes the configuration away in
# the middle of installing the program that made it -- and when it
# fails, which it does when the directory is in use, the whole
# install fails with:
#
#     Error 1722: a program run as part of the setup did not finish
#     as expected
#
# MEASURED: that is what the install said, and the trace named the
# action.
#
# SO THE CONDITION SAYS "THE PACKAGE IS BEING REMOVED" AS WELL AS
# "THE PERSON SAID YES".  Both have to be true.
#
# AND THE FRAGMENT DOES NOT BRING ITS OWN <InstallExecuteSequence>
# ELEMENT: pyappdist's .wxs already has one, and two of them
# nested is not a sequence.
# THE SEQUENCE, AND THE TWO ACTIONS.
#
# FIRST THE ANSWER IS COPIED.  The checkbox writes into the stock
# property, and the removal has to read a property of our own, so
# the value is copied into it.
#
# `SetProperty` with a value of "[PropertyName]" copies one
# property into another, and it is a built-in action, so it needs no
# code and no elevation.
#
# AND IT IS SCHEDULED IN THE UI SEQUENCE, AFTER the dialog that asks
# the question -- the UI sequence is the one that runs the dialogs,
# and it runs them before the execute sequence does its work.
#
# THEN THE CONFIGURATION GOES, when the copied property says so AND
# the package is being removed.
#
# IT IS AN UNINSTALL-TIME ACTION.  Scheduled in the install sequence
# without the REMOVE condition it runs on EVERY install, and it
# takes the configuration away in the middle of installing the
# program that made it -- and when it fails, which it does when the
# directory is in use, the whole install fails with:
#
#     Error 1722: a program run as part of the setup did not finish
#     as expected
SEQUENCE_FRAGMENT = """    <!-- THE CONFIGURATION GOES WHEN THE PERSON SAYS SO, AND
         WHEN THE PACKAGE IS BEING REMOVED. -->
    <Custom Action="ca_rm_ljtunnel_state" After="RemoveFiles"
            Condition=\'{prop} = "1" AND REMOVE = "ALL"\' />
"""


# The copy of the answer, and the sequence it goes in.
COPY_FRAGMENT = """    <!-- THE ANSWER IS COPIED OUT OF THE CHECKBOX'S OWN PROPERTY
         AND INTO ONE OF OUR OWN, just after the dialog that asks
         the question.  The removal reads ours. -->
    <SetProperty Id="sp_copy_checked" Value="[{source}]" Before="RemoveFiles"
                 Sequence="Execute" />
"""

UI_SEQUENCE_FRAGMENT = """  <!-- THE QUESTION IS ASKED, AND THEN THE ANSWER IS COPIED.
       The UI sequence runs the dialogs, and it runs them before the
       execute sequence does its work. -->
  <InstallUISequence>
    <SetProperty Id="sp_copy_checked" Value="[{source}]" After="ExitDialog" />
  </InstallUISequence>
"""



def _insert_after(text: str, marker: str, fragment: str) -> str:
    """Put the fragment in after the line the marker names."""
    at = text.find(marker)
    if at < 0:
        return text
    at = text.find("\n", at)
    if at < 0:
        return text
    return text[:at + 1] + fragment + text[at + 1:]


def _marker_for_standard_directory(text: str, name: str) -> str:
    """The line that starts the <StandardDirectory> with this id."""
    import re

    pattern = r'^[ \t]*<StandardDirectory Id="' + re.escape(name) + r'">\s*$'
    for m in re.finditer(pattern, text, re.M):
        return m.group(0).rstrip("\n")
    return ""


def _marker_for_directory(text: str, name: str) -> str:
    """The line that starts the <Directory> with this name, or "".

    THE ID IS A HASH.  pyappdist makes the directory ids out of the
    paths, so they change when the bundle changes.  So the directory
    is found by its NAME, and the line that starts it is the marker.
    """
    import re

    pattern = r'^[ \t]*<Directory Id="[^"]+" Name="' + re.escape(name) + r'">\s*$'
    for m in re.finditer(pattern, text, re.M):
        return m.group(0).rstrip("\n")
    return ""


def _package_id_is_not(text: str, prop: str) -> bool:
    """The Package's Id is not this property.

    THE PACKAGE'S `Id` IS THE PACKAGE CODE -- the GUID that says
    WHICH FILE THIS IS -- and it is derived with a different
    namespace than the ProductCode.  So it must never be the same
    as a property, and a check that looks for a property by name
    has to make sure it is not finding the Package's own Id.
    """
    import re

    m = re.search(r"<Package\b[^>]*>", text)
    if not m:
        return True
    pkg = m.group(0)
    return f'Id="{prop}"' not in pkg


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
        text=TEXT, label=LABEL))

    # ---- the directory and its component ----
    #
    # pyappdist's .wxs ALREADY declares the LocalAppData root:
    #
    #     <StandardDirectory Id="LocalAppDataFolder">
    #
    # so the state directory goes inside it, as a child.  That is the
    # right place: the state directory IS %LOCALAPPDATA%\\ljtunnel.
    # ---- the state directory, inside the LOCALAPPDATA ROOT ----
    #
    # THE STATE DIRECTORY IS %LOCALAPPDATA%\\ljtunnel, and pyappdist
    # already declares the LocalAppData root:
    #
    #     <StandardDirectory Id="LocalAppDataFolder">
    #
    # so the directory goes inside it.  The marker is the root's own
    # line, found by its NAME -- the ids are hashes and they change
    # when the bundle changes, so a marker with a hard-coded id
    # worked by luck and stopped working after a clean rebuild.
    #
    # MEASURED: that is what happened.
    marker = _marker_for_standard_directory(text, "LocalAppDataFolder")
    if not marker:
        return False
    # AFTER the root's own line, so the state directory is a CHILD of
    # it -- %LOCALAPPDATA%\ljtunnel -- and not a sibling.
    text = _insert_after(text, marker,
                         DIRECTORY_FRAGMENT.format(sub=state_dir_name,
                                                  guid=REMOVE_GUID))

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
    # pyappdist's .wxs already has an <InstallExecuteSequence>, and
    # the action goes INSIDE it.  A fragment that brought its own
    # element would give two nested ones, which is not a sequence.
    # ---- the sequence ----
    #
    # The closing tag is found by ITS OWN NAME and not by its
    # indentation: the .wxs is regenerated on every build and the
    # indentation is not a promise.
    at = text.rfind("</InstallExecuteSequence>")
    if at >= 0:
        # the action goes INSIDE the sequence that is already there
        line_start = text.rfind("\n", 0, at) + 1
        indent = text[line_start:at]
        text = (text[:line_start] + indent + SEQUENCE_FRAGMENT.format(
            prop=CHECKED).lstrip() + text[at:])
    else:
        # there is no sequence of its own, so one is made
        text = _insert_before(text, "  </Package>",
                              "  <InstallExecuteSequence>\n"
                              + SEQUENCE_FRAGMENT.format(prop=CHECKED)
                              + "  </InstallExecuteSequence>\n")

    # ---- and no copy of the answer is needed ----
    #
    # The checkbox's own property IS the answer: it is empty when the
    # box is not ticked and "1" when it is.  So the condition reads
    # it directly, and there is nothing to copy and no SetProperty
    # to get wrong.

    wxs.write_text(text, encoding="utf-8", newline="\n")
    return True


def check(wxs: Path) -> bool:
    """Is the removal in the .wxs?"""
    if not wxs.is_file():
        return False
    text = wxs.read_text(encoding="utf-8")
    # NOT "RemoveFolder": there must NOT be one, because it cannot be
    # conditioned and so it would remove the configuration on every
    # uninstall.
    return ("ca_rm_ljtunnel_state" in text
            and "RemoveFolder" not in text
            and "dir_ljtunnel_state" in text
            and "ft_remove_state" in text
            and CHECKED in text
            # and the checkbox's own property is NOT given a value:
            # the box shows because of the TEXT property, and giving
            # this one a value makes the condition always true
            and f'Id="{CHECKED}"' in text
            # and the checkbox's own property is NOT given a value
            and f'<Property Id="{CHECKED}" Value=' not in text
            # and the checkbox's property is not the Package's Id
            # (the Package's Id is the package code, and the two
            # codes are derived with different namespaces)
            and _package_id_is_not(text, CHECKED))
