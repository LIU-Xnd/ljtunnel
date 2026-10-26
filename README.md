# ljtunnel

An ssh reverse-forward tunnel with two ends. It lets a machine that
**cannot be reached** offer its own sshd to a machine that **can**, with
no inbound port on the unreachable side.

```
machine A (reachable)                  machine B (unreachable)
  ljtunnel listen                         ljtunnel dialer
  sshd on 10001          <---             ssh -R 10002 -> local 10001
  10002 -> dialer 1
  10003 -> dialer 2
```

A person on the network connects to `A:10002` and lands on **B's** own
sshd. Nothing inbound ever touched B.

## The two ports

| port | what |
|---|---|
| 10001 | this end's own sshd -- where the **dialers** log in |
| 10002-10021 | the forwarded ports -- where **other people** log in, to reach a dialer |

Both are on the listen end's machine, and they are different things.
A dialer asking to forward 10002 is not reaching the listen end's
sshd; it is asking the listen end to open 10002 and send whatever
arrives to the dialer.

## Use

On the reachable machine, open the window and press **Start**. It
shows the address to use.

**Record the dialer.** Fill in the form -- its name, where it is, who
logs in, its public key, a note if there is anything worth writing
down -- and press **Save**. The record is kept, the key goes into the
listen end's key list so the dialer is let in, and the window prints
the command that dialer runs.

**Show the command** puts that command on the clipboard, ready to be
pasted into a terminal on the other machine. **Copy** does the same
for a row that is already in the panel.

The name goes on the *key*, so a dialer cannot call itself something
it is not.

On the unreachable machine, run the command the window gives you:

```bash
ljtunnel dialer --listen-host <the reachable machine> \
                --listen-port 10001 \
                --user <your name> \
                --access-key "ssh-ed25519 ..."
```

That command carries the access key, so it is one step: the dialer
takes the key, puts it in its own key list, and the end user can log
in.

Then, from anywhere:

```bash
ssh -i <the access key> -p <the dialer's port> <your name>@<the reachable machine>
```

## A RECORD and a DIALER

The panel shows two different things, and they are not the same
thing:

| | what it is | when it is there |
|---|---|---|
| **RECORD** | what somebody filled in: the name, the address, the user, the key, the note | as long as the record is kept |
| **DIALER** | what is actually there: a key that authenticated and asked for a port, and that port is open | while the port is open |

A record with no live dialer is a box that has not been set up yet --
and it still prints its command, because the command is what sets it
up. A live dialer with no record is one whose key was in the list
before the records existed.

**Nobody assigns a port.** The dialer finds its own: it asks for the
first port in the range, and if that one is taken it asks for the
next -- so the same command works on every box, and ten dialers end
up on ten different ports with no coordination.

The client cannot be believed about this. A dialer that asks for a
port which is already taken is told `forward success` and gets **no
socket**, and on Windows the second dialer even takes the port away
from the first. So the dialer checks the **host key** behind the port
before it says it is up: that is the only thing there that cannot be
faked, because it is what the key exchange is built on.

The listen end does the same check the other way round, so it can say
*which* machine is behind a port and not just that something is.

## Stopping it

**Ctrl-C stops it, cleanly.** The sshd is stopped, the port is
released, and the window goes away -- so the next launch does not
find a port that is busy for no reason anybody can see.

On Windows the console sends a program in its own process group a
BREAK rather than a Ctrl-C, and a BREAK is what the program handles.
Either way it is the same shutdown.

## The records

The records are one JSON file in the state directory:
`ljtunnel_records.json`. It is written through a temporary file and
renamed, so a crash in the middle does not leave a file that cannot
be read.

A file that cannot be read is treated as no records, not as a crash:
the records are a convenience, and the program works without them.

## The keys

Two identities, two relationships:

| key | whose | where the public half goes |
|---|---|---|
| `id_rsa_ljtunnel` | the dialer machine | the listen end's key list |
| `id_rsa_ljtunnel_access` | the end user | each dialer's key list |

Neither end's sshd trusts its own key.

## The sshd is a user-level one

Both ends run their **own** sshd, as an ordinary user, with their own
host key, their own config and their own port. The system's sshd
service is not involved, is not touched, and keeps its own port.

That matters because the machine that cannot be reached will not have
root, and a service cannot be started by a person without it.

The state lives in one directory:

| | Windows | Linux |
|---|---|---|
| state | `%LOCALAPPDATA%\ljtunnel` | `~/.local/state/ljtunnel` |
| config | `ljtunnel_sshd_config` | the same |
| host key | `ljtunnel_host_ed25519` | the same |
| key list | `ljtunnel_authorized_keys` | the same |
| machine key | `id_rsa_ljtunnel` | the same |
| access key | `id_rsa_ljtunnel_access` | the same |
| pid | `ljtunnel_sshd.pid` | the same |
| log | `ljtunnel_sshd.log` | the same |

## The firewall

Windows blocks inbound traffic to a port it has not been told about,
and it does it **silently**: the connection times out, with no error on
either side. The listen end needs an inbound rule for `10001` and for
the forwarded range.

Adding a firewall rule is an administrator action, so the app **asks
to be an administrator when it starts**. Windows puts up the UAC
prompt, you answer it, and the app is an administrator for as long as
it is open -- so the firewall button needs no prompt of its own
afterwards.

Press **No** and the app carries on without the elevation. The
firewall button then asks for it by itself, for that one step. So
declining is not a dead end.

The rule is added with `New-NetFirewallRule`, and not with `netsh`:
netsh says "the specified value is invalid" for a dozen different
reasons -- including *not being an administrator* -- so the thing
that went wrong cannot be told from the message. The cmdlet says
"access is denied" with the exception type beside it.

Until the rule is in, the dialers time out with no message at all.

If you would rather do it by hand:

```powershell
powershell -ExecutionPolicy Bypass -File tools/open_firewall.ps1
```

from a terminal running as administrator.

## Commands

```
ljtunnel listen      the reachable end -- the window on Windows
ljtunnel dialer      the unreachable end
ljtunnel key         print this end's public key
```

## Install

The listen end is a desktop application:

```
appdist/windows/dist/ljtunnel-<version>.msi
```

It bundles a Python runtime, so it works on a machine with nothing on
it. The dialer end is a script and needs Python 3.9 or later.

## Tests

```bash
python -m ljtunnel.selftest      # the checks that need one machine
python -m ljtunnel.guitest        # the window, without showing it
python -m ljtunnel.interrupt_test # Ctrl-C, really interrupted
python -m ljtunnel.elevate_test   # the UAC prompt, really answered
python -m ljtunnel.firewall_test  # the rule, really added
```

The last two put a UAC prompt on your screen. They are separate from
the self-test on purpose: a suite that raises a prompt every time it
runs is a suite that gets skipped.

The interrupt test sends a real console event to a real process and
checks the port afterwards, because a program that is killed with the
port still held is the failure that matters.

The cross-machine test is separate: it needs two machines and a port
the firewall lets through. It is the real proof -- the listen end on
one machine, the dialer end on another, and a connection to the
forwarded port landing on the **dialer's** sshd, with nobody adding
a dialer to the panel.

```bash
LJT_FAR_HOST=... LJT_FAR_PORT=... LJT_FAR_USER=... \
LJT_FAR_PASSWORD=... python tools/crossmachine_form.py
```

It fills in the form, takes the command from the **clipboard**, runs
it on the far machine, and watches the dialer arrive by itself.

## The user in the command

The command names the **reachable end's** user, not the dialer's own.
The dialer opens an ssh session to the reachable end, and the
reachable end's sshd refuses a user that does not exist on it -- so
the name is a user of the machine the command is going to reach.

Leave the field empty and it is your own user on the reachable end.
