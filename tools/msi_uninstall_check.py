r"""THE UNINSTALL ASKS ABOUT THE CONFIGURATION, AND THE ANSWER IS HONOURED.

THE CONFIGURATION IS PER-USER DATA, and the uninstaller does not own
it, so the uninstall ASKS.  The keys are the identity of a tunnel,
and removing them by default would silently break every tunnel that
used this machine.

This is the check that the question is really in the built MSI, and
that the answer is what decides whether the configuration goes.

WHAT IS READ FROM THE MSI:

    the Control table      the checkbox and the property it writes
    the Property table     the TEXT property that makes it appear
    the sequence           the CONDITION on the removal

**AND THE CONDITION IS THE WHOLE POINT.**  It has to read the
checkbox's own property, which is EMPTY until the box is ticked and
is "1" when it is.  So:

    WIXUI_EXITDIALOGOPTIONALCHECKBOX = "1" AND REMOVE = "ALL"

**AND THE CHECKBOX'S OWN PROPERTY MUST NOT BE GIVEN A VALUE IN THE
PACKAGE.**  The box is SHOWN by the TEXT property, not by its own
one, so giving it a value would make the condition ALWAYS true and
the configuration would go on every uninstall.  MEASURED: that is
exactly what happened, and the trace named the action.

SO THIS CHECKS BOTH HALVES:

    the condition reads the checkbox's own property
    the package does not give that property a value
"""
from __future__ import annotations

import re
from pathlib import Path

# The property the checkbox writes, and the one that makes it show.
CHECKBOX = "WIXUI_EXITDIALOGOPTIONALCHECKBOX"
TEXT = "WIXUI_EXITDIALOGOPTIONALCHECKBOXTEXT"

# The action that removes the configuration.
ACTION = "ca_rm_ljtunnel_state"


def _rows(db, query):
    """The rows of a query, as lists of strings."""
    import msilib

    try:
        v = db.OpenView(query)
        v.Execute(None)
    except Exception:
        return []
    out = []
    while True:
        rec = v.Fetch()
        if rec is None:
            break
        vals = []
        for i in range(1, 12):
            try:
                vals.append(rec.GetString(i))
            except Exception:
                vals.append("")
        out.append(vals)
    return out


def check(msi_path) -> list:
    """The checks.  Each one is (the name, whether it holds)."""
    import msilib

    msi = Path(msi_path)
    if not msi.is_file():
        return [("the MSI is there", False, str(msi))]

    try:
        db = msilib.OpenDatabase(str(msi), msilib.MSIDBOPEN_READONLY)
    except Exception as e:
        return [("the MSI can be read", False, str(e))]

    out = []

    # ---- the checkbox is there, and it writes its own property ----
    bound = ""
    for vals in _rows(db, "SELECT Control, Property FROM Control"):
        if vals[0] == "OptionalCheckBox":
            bound = vals[1] or ""
    out.append(("the uninstall page has the checkbox", bound == CHECKBOX,
                f"it writes {bound or '(nothing)'}"))

    # ---- the text that makes it appear ----
    text_value = ""
    for vals in _rows(db, "SELECT Property, Value FROM Property"):
        if vals[0] == TEXT:
            text_value = vals[1] or ""
    out.append(("the checkbox says what it does", text_value != "",
                 text_value[:60]))

    # ---- and the checkbox's own property is NOT given a value ----
    own_value = None
    for vals in _rows(db, "SELECT Property, Value FROM Property"):
        if vals[0] == CHECKBOX:
            own_value = vals[1]
    out.append(("the checkbox's own property starts empty",
                own_value is None, repr(own_value)))

    # ---- the condition on the removal ----
    condition = ""
    for vals in _rows(db, "SELECT Action, Condition FROM InstallExecuteSequence"):
        if vals[0] == ACTION:
            condition = vals[1] or ""
    out.append(("the removal is there", condition != "", condition[:80]))
    out.append(("and it waits for the answer",
                f'{CHECKBOX} = "1"' in condition, condition[:80]))
    out.append(("and it only runs on a removal",
                'REMOVE = "ALL"' in condition, condition[:80]))

    return out


def main(argv=None) -> int:
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: python tools/msi_uninstall_check.py <the msi>")
        return 2

    msi = argv[0]
    print(f"=== {msi} ===")
    results = check(msi)
    for name, ok, detail in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}"
              + (f"  ({detail})" if detail and not ok else ""))

    passed = sum(1 for _, ok, _ in results if ok)
    print()
    print(f"  {passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
