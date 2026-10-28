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

**Add the dialer.** Paste its **public key** into the one box and
press **Add**. That is the whole input.

The name is not typed in. It is **on the key** -- the key's comment --
and the window reads it from there, so the dialer names itself:

```
this end's key for the reachable end:
    ssh-ed25519 AAAA... ljtunnel-box-a
```

The key goes into the listen end's key list, so the dialer is let in,
and the window prints the command that dialer runs.

**Show the command** puts that command on the clipboard, ready to be
pasted into a terminal on the other machine. **Copy** does the same
for a row that is already in the panel.

The name goes on the *key*, so a dialer cannot call itself something
it is not.

On the unreachable machine, run the command the window gives you:

```bash
ljtunnel dialer --listen-host <the reachable machine> \
                --listen-port 10001 \
                --user <your name on the reachable end> \
                --access-key "ssh-ed25519 ..."
```

That command carries the access key, so it is one step: the dialer
takes the key, puts it in its own key list, and the end user can log
in.

**It is the same command for every dialer.** The dialer finds its own
port, and it knows its own account -- the one it is run as. So the
command does not name an account on the dialer, and it cannot be
wrong.

To name it on the panel, give the dialer a name when it starts:

```bash
ljtunnel dialer --name box-a --listen-host ... 
```

and it puts that on its own key, and the window shows it.

Then, from anywhere:

```bash
ssh -i <the access key> -p <the dialer's port> \
    <your name on the DIALER>@<the reachable machine>
```

The name there is the dialer's, not the reachable end's. The dialer
says which one in its log:

```
  a person connects through the forwarded port as: liuxd
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

## How the dialers are found

The panel shows the dialers that are up, and it finds them by itself:
nobody types a port into it and nobody says a dialer has arrived.

**It asks the forwarded port who is there.**  Behind every forwarded
port there is the dialer's own sshd, and the host key that answers
there is the dialer's identity -- it cannot be faked, because it is
what the key exchange is built on.  The listen end looks that key up
in its own key list, and the name on the key it finds is the
dialer's name.

**And the dialer's host key is its machine key.**  So the key behind
a forwarded port is the key the dialer logged in with, and the listen
end already knows it.  One key, two jobs.

**The socket table says which ports are open**, and that needs no
log at all -- which matters, because on Windows the sshd's sessions
do not log to the listener's pipe, so the log cannot say who
connected.

A port that is open but whose key is not in the list is still shown,
by its fingerprint.  That is a dialer whose key was added before
the records existed.

## The other shape: a web page, not a shell

The tunnel's other use is offering a WEB PAGE from a machine that
cannot be reached.  The dialer end runs a small http server instead of
an sshd, and the reachable end's forwarded port lands on it.

```bash
ljtunnel dialer --listen-host <the reachable end> --user <its account> \
    --name box-a --http-server --http-directory /path/to/serve
```

**THERE IS NO SSHD ON THAT END, AND NO SHELL AND NO ACCOUNT.**  The
token in the URL is what lets somebody in:

```
http://<the reachable end>:<the forwarded port>/<the token>/
```

**THE TOKEN IS THE FIRST SEGMENT OF THE PATH**, and it is not the file
that is served: a request for `/<token>/some/file.html` serves
`some/file.html`, and the token is only the gate.  So the token is not
a file name that has to be in every link.

**AND IT IS COMPARED IN CONSTANT TIME**, so the time it takes does not
say how much of it was guessed right.

**AND THE TOKEN IS KEPT**, in the state directory, so the URL does not
change every time the dialer is restarted.  `--http-token` gives it
one by hand; without it a random one is made the first time.

| | |
|---|---|
| `--http-server` | serve a directory instead of running an sshd |
| `--http-directory` | what to serve |
| `--http-port` | where to listen (default 10001) |
| `--http-token` | the token, if you want a particular one |

**IT SERVES AND NOTHING ELSE.**  There is no upload, no delete and no
directory making -- the server answers GET and HEAD and refuses the
rest.  A file server that writes is a different program with a
different set of rules about who may write what, and there is one
that does that (`rclone serve webdav`), and this is not it.

**AND IF YOU WANT TO WRITE THROUGH THE TUNNEL**, run `rclone serve
webdav` on the far side and forward its port instead:

```bash
rclone serve webdav /path/to/serve --addr 127.0.0.1:10001
```

## The stale host keys

A person connects to a dialer through a forwarded port, and the ssh
client remembers the host key it saw there.  That memory is in the
user's own `known_hosts`.

**And a dialer that is set up again makes a new host key** -- the
machine key is the host key, and a fresh install is a fresh key.  So
the memory goes stale and the ssh client says:

```
Host key for [localhost]:10002 has changed and you have requested strict checking.
Host key verification failed.
```

The ssh client is right: the key really did change.  But the dialer is
the same box being set up again, and the person cannot be asked to type
a command to fix it.

**So the tunnel's own entries are cleaned, every time it starts.**  The
window has a **Clean the known hosts** button for it as well.

Only the tunnel's ports are touched, and only for the names the tunnel
is reached by: `localhost` and `127.0.0.1`, ports `10001` to `10021`.
**The rest of the `known_hosts` is left alone** -- it holds every host
the person has ever connected to.

The entries are removed by `ssh-keygen -R`, which is what wrote them.

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
declining is not a dead end. **Be an administrator** asks again, for
the person who declined and wants it after all.

### You may not see the prompt

Windows puts the UAC prompt on the **secure desktop**: it takes the
screen over, the prompt is on top of it, and it is gone when you
answer. A person who is not watching for it may miss it entirely.

And the consent for an administrator is cached for a short while, so
the second prompt may not come either. The prompt may not appear
**and** the elevation still works. So the thing to check is not
whether a prompt appeared but whether the work got done: the rule is
in, or it is not.

The window says which it is, on the **rights** line: `administrator`
or `not an administrator`.

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

| what | how |
|---|---|
| the window | `ljtunnel listen` |
| the command a new dialer runs | the **Show the command** button |
| take the stale host keys away | the **Clean the known hosts** button |



```
ljtunnel listen      the reachable end -- the window on Windows
ljtunnel dialer      the unreachable end
ljtunnel key         print this end's machine key, for the other end's key list
ljtunnel forget      remove this end's configuration: the keys, the records,
                     the config and the log
```

`forget` is how the far side gets rid of its configuration, where
there is no installer to ask.  It stops the tunnel, removes the state
directory, and says that the firewall rule is a machine-wide thing
and stays.  The firewall rule is removed by the window's own button.

**On Windows the uninstaller asks the same question.**  The keys are
the identity of a tunnel, so removing them by default would break
every tunnel that used this machine; so they are kept, and the
uninstall page has a box on it for the person who wants them gone.

## Install

The listen end is a desktop application:

```
appdist/windows/dist/ljtunnel-<version>.msi
```

It bundles a Python runtime, so it works on a machine with nothing on
it.

**THE UNINSTALL ASKS ABOUT THE CONFIGURATION.**  The keys, the
records, the config and the log are per-user data, and the keys are
the identity of a tunnel -- so removing them by default would
silently break every tunnel that used this machine.  So the
uninstall page has a checkbox:

```
[ ] Remove the configuration and the keys
```

Ticked, the whole state directory goes.  Unticked, it stays, and
the next install picks up where this one left off.


**The dialer end can be a single file with nothing on it either.**
The far side is often a machine with no Python, no conda and no pip,
so the binary carries its own interpreter:

```
dist/linux/ljtunnel
```

Build it on the machine it will run on, or an older one: it links
against the glibc of the system that built it, and glibc only ever
goes forwards.  On server41:

```
/home/liuxd/miniconda3/envs/ljtunnel-dev/bin/python tools/build_linux_binary.py
```

The whole dispatcher is frozen, not one subcommand, so `key`,
`dialer` and `forget` are all in it.  And it runs with an empty
environment:

```
env -i PATH=/usr/bin:/bin ./ljtunnel --version
```

**AND IT IS TESTED ACROSS THE WIRE AS THE BINARY.**  The frozen
binary is what the unreachable machine actually runs, so the
cross-machine test uses it -- not the source tree:

```
LJT_FAR_HOST=... LJT_FAR_PORT=... LJT_FAR_USER=... \
LJT_FAR_PASSWORD=... LJT_EXPECT_VERSION=... \
python tools/crossmachine_frozen.py
```

The version comes from the environment and is not written down in
the test, so a release does not make the test fail for a reason
that has nothing to do with the product.

**THE FAR SIDE DELETES ITS CONFIGURATION WITH `ljtunnel forget`.**
There is no installer there, so the question is asked on the
keyboard instead:

```
ljtunnel forget
```

It shows what is in the state directory and asks before removing it,
because the keys are the identity of a tunnel.  The answer "no"
leaves everything alone.  It stops the sshd first, so nothing is
left holding a port.

The firewall rule is NOT removed by it: that is a machine-wide thing
the tunnel asked for, and the person who asked for it may want it to
stay.

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

## There are TWO users, and they are on different machines

This is the thing to get right, and it is easy to get wrong because
one command carries both.

**The dialer logs in to the reachable end.** It opens an ssh session
to the reachable end and asks for a reverse forward. That session is
made as an account on the **reachable end**, so the command's
`--user` is that account. Leave the field empty and it is your own
user on the reachable end.

**A person connects through the forwarded port.** The forwarded port
goes to the **dialer's** own sshd, so the account they give is one on
the **dialer**. That is the `user on the dialer` field, and it ends
up in the command as `--local-user`.

They are different accounts on different machines, and a name from
one is not a name on the other:

```
xnd_l@127.0.0.1: Permission denied (publickey,keyboard-interactive).
```

That is what it looks like when the name is the reachable end's and
the connection landed on the dialer. The key was fine.

Leave `user on the dialer` empty and the dialer's own account is
used. The dialer says which one in its log:

```
  a person connects through the forwarded port as: liuxd
```

And a person connects like this, from the reachable end:

```
ssh -i <the listen end's access key> -p 10002 <the dialer's user>@<the reachable end>
```
