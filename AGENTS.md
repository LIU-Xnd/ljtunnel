# AGENTS.md — conventions for this repo

## The README describes the software as it is now

**Do not describe retired versions.** When a version is superseded, its
description is removed from the README rather than kept for history.
The git history and the tags are where the history lives.

No "v1.x was ..." paragraph, no "the old way was ..." notes, no
"previously it did ..." asides. If a behaviour is gone, it is simply
not there.

## Versioning

The number in `pyproject.toml`, the fallback `__version__` in
`ljtunnel/__init__.py`, the installed distribution metadata and the
git tag must all agree. `python -m ljtunnel.selftest` checks the first
three and fails if they differ, so bump all of them in the same
commit.

- a commit → patch number (`0.1.0` → `0.1.1`)
- a push with a new feature → minor number (`0.1.x` → `0.2.0`)
- a push with a breaking change → major number (`0.x` → `1.0.0`)

Tag the release and push the tag with the branch.

## WHO INITIATES THE FORWARDING

The **dialer** initiates it, not the listen end. `ssh -R` is run BY the
dialer, connecting OUT to the listen end's sshd. The listen end never
dials out.

This is easy to get wrong, and wrong looks reasonable: the listen end
is the one that holds the port, so it is tempting to make it connect
to the dialers. But the dialer is by definition the machine that
cannot be reached, and it is the one that initiates.

So the listen end's job is: run its sshd, keep the key list, ASSIGN a
port per dialer, and show what is up.

## The sshd is a USER-LEVEL one, and the system's is not touched

Both ends run their own sshd as an ordinary user, with their own host
key, their own config and their own port.

- the system's sshd service, its config and its port 22 are never
  involved
- `sshd.stop()` kills the pid in **our** pid file, never anything else
- the pid file is the ONLY handle. On Linux sshd forks: the process
  that was started writes the pid file and exits, and the LISTENER is
  a different process whose title is `sshd: /usr/sbin/sshd -f ...`.
  A `pkill -f ljtunnel_sshd_config` does not find it.

## The two ends have different sshd settings, and the difference matters

| | listen end | dialer end |
|---|---|---|
| ListenAddress | 0.0.0.0 | 127.0.0.1 |
| GatewayPorts | clientspecified | -- |
| AllowTcpForwarding | remote | no |

`GatewayPorts clientspecified` is what makes the forwarded port
reachable from the network. Without it the port binds to loopback and
nobody off the machine can connect.

The dialer end listens on loopback only and accepts no forwarding. It
is on a machine that cannot be reached; exposing its sshd to the
network would be the opposite of the point.

## The firewall rule needs an administrator shell, and that is fine

Adding a Windows firewall rule is an administrator action. A
non-elevated shell gets "access denied" (拒绝访问) and nothing else.

**The failure is SILENT from the far end.** With the rule missing, the
listen end's sshd is listening on 0.0.0.0:10001, the port shows up in
`Get-NetTCPConnection`, and the dialer still TIMES OUT. Nothing says
"firewall".

So the rule is RENDERED, not silently required: the window shows the
exact `netsh` command, says it needs an administrator shell, and offers
it for copying. Do not try to work around it by elevating the app --
`IsUserAnAdmin()` is the check, and when it is False the honest answer
is the command.

**A user-level sshd is NOT covered by OpenSSH's own firewall rule.**
The rule that ships with OpenSSH for Windows is scoped to ports
22, 10000, 20000 -- a user-level sshd on 10001 is not in it. The
program path matches; the PORT list does not, and the port list is
what the firewall uses.

The rule is NOT in the MSI: the WiX Firewall extension's `<File>`
element has to point at a file IN the package, and `sshd.exe` is the
system's own OpenSSH. It is also a per-user install, and the rule
needs an administrator.

## Platform

Windows is a supported target, and it is where the bugs live.

- `UsePrivilegeSeparation` is WINDOWS ONLY, and DEPRECATED on OpenSSH
  8.2+ -- every Linux start prints a warning about it if it is there
- Linux sshd has no `-E`. `-e` sends the log to stderr; the command is
  `sshd -f <config> -D -e` with stdout+stderr going to the log file.
  Passing `-E` on Linux makes the process exit and write no log, which
  looks exactly like "it did not start" with no explanation
- on Windows the socket options `SO_EXCLUSIVEADDRUSE` and
  `SO_REUSEADDR` are MUTUALLY EXCLUSIVE -- setting both gives
  WSAEINVAL
- `SO_EXCLUSIVEADDRUSE` is what makes "is this port free" true rather
  than optimistic: without it Windows lets a second process bind a port
  that is already being listened on, and that process silently never
  receives anything
- a Windows console code page is not valid UTF-8 -- decode a child's
  output with `errors="replace"`
- `os.kill(pid, 0)` is a probe on POSIX but SIGNALISES on Windows; use
  `tasklist` there

## The window has no console, and that is not an edge case

The Windows launcher is built on `pythonw.exe` (PE subsystem 2), so it
has no console. Anything printed to stdout or stderr goes nowhere and
the process appears to do nothing.

- **With no arguments the window opens.** The Start Menu shortcut runs
  the launcher with no arguments, so that IS the default path. The
  console launcher still prints the usage.
- **A crash has to be shown in a message box.** A traceback to stderr
  from a pythonw process is invisible.

How to tell whether there is a console, on Windows:

```python
buffer = (ctypes.c_ulong * 8)()
count = kernel32.GetConsoleProcessList(buffer, len(buffer))
has_console = count > 0
```

`AttachConsole(ATTACH_PARENT_PROCESS)` is the tempting wrong answer:
it succeeds precisely when the process has NO console of its own and
can attach to the parent's -- the opposite of the question.

## The window closing takes the server down

The sshd is a child of the window's process, so it would die with the
process -- but the window can close while the process lives on, and a
server left running in that gap keeps the port and answers the next
launch with the old state. `_on_close()` stops it.

## The self-test must not be blind

A test that cannot fail proves nothing. When a check is added, break
the thing it checks and confirm the suite goes red. The checks that
read the source (the dialer's settings, the port check) exist because
the running behaviour is hard to observe.

The suite runs on the machine it is on and needs no network and no
administrator shell. The cross-machine test is a separate script,
because it needs two machines and a port the firewall lets through.

## The MSI installer

`tools/build_msi.py` produces
`appdist/windows/dist/ljtunnel-<version>.msi`. It bundles a Python
runtime, so the installer works on a machine with nothing on it.

The general procedure is written up as a skill:
`python-package-release` -> `references/msi-installer-ui.md`, with
`scripts/msi_ui.py` to switch the UI set and to check a built MSI.

- **A silent install does not prove the UI works.** Error 2819 only
  fires when the installer actually shows the folder page, so
  `msiexec /i ... /qn` succeeding says nothing about it. Check the
  MSI's Control and Property tables instead.
- **The build tree is `.appdist-build/`** and holds a whole Python
  runtime. It is gitignored, and it must stay that way.
- **The runtime is reused when it is there.** The marker file
  `.pyappdist-runtime.json` has to travel with the tree, or the build
  goes to the network for it -- and the network to
  raw.githubusercontent.com fails intermittently on this machine.

## The state directory is the product's state

Everything a tunnel is lives in one directory: the config, the keys,
the pid, the log. Two ends of the same tunnel are told apart by their
directory, and "stop everything this tunnel started" is one directory
walk.

The keys are PRIVATE and must never be committed. The state directory
is outside the repository, so it cannot be.

## No secrets, and no addresses, in the repository

No private keys, no tokens, no passwords, and no internal addresses in
commits, code, docs or commit messages. The address the listen end
prints is read at RUN TIME -- the same machine changes address when it
changes network, and a written-down one is wrong exactly when it
matters.
