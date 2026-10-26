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
| 10002 | the first forwarded port -- where **other people** log in, to reach a dialer |

Both are on the listen end's machine, and they are different things.
A dialer asking to forward 10002 is not reaching the listen end's
sshd; it is asking the listen end to open 10002 and send whatever
arrives to the dialer.

## Use

On the reachable machine, open the window and press **Start**. It
shows the ports, the address to use, and the command each dialer runs.

On the unreachable machine, run the command the window gives you:

```bash
ljtunnel dialer --listen-host <the reachable machine> \
                --listen-port 10001 \
                --forward-port 10002 \
                --user <your name> \
                --access-key "ssh-ed25519 ..."
```

That command carries the access key, so it is one step: the dialer
takes the key, puts it in its own key list, and the end user can log
in.

Then, from anywhere:

```bash
ssh -i <the access key> -p 10002 <your name>@<the reachable machine>
```

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

Adding a firewall rule is an administrator action, so the window shows
the command and offers it for copying. To run it yourself:

```powershell
powershell -ExecutionPolicy Bypass -File tools/open_firewall.ps1
```

from a terminal running as administrator.

Until the rule is in, the dialers time out with no message at all.

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
python -m ljtunnel.selftest    # the checks that need one machine
python -m ljtunnel.guitest      # the window, without showing it
```

The cross-machine test is separate: it needs two machines and a port
the firewall lets through.
