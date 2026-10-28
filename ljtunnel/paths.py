"""Where everything lives.

The state of a tunnel is a directory, not a set of files scattered
around: the config, the keys, the pid, the log. Putting it in one
place means "stop everything this tunnel started" is one directory
walk, and it means two ends of the same tunnel can be told apart by
their directory rather than by a flag.
"""
from __future__ import annotations

import os
import sys

APP_NAME = "ljtunnel"


def state_dir() -> str:
    """Where this end keeps its config, keys, pid and log.

    Windows: %LOCALAPPDATA%/ljtunnel
    Linux:   ~/.local/state/ljtunnel

    Not the user's home directly: a directory of several files with
    private keys in it wants to be somewhere that is not on the
    Desktop.
    """
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    else:
        base = os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state")
    return os.path.join(base, APP_NAME)


def current_user() -> str:
    """The account this end runs as.

    **THE ENVIRONMENT IS NOT ALWAYS THERE.**  MEASURED: the frozen
    binary is run with `env -i`, which clears the environment, and
    then USERNAME and USER are both gone and the dialer said

        cannot tell who the user is; pass --local-user

    and did not start at all.  So the account is asked of the SYSTEM
    when the environment does not say.
    """
    who = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    if who:
        return who

    # ---- THE HOME PATH'S NAME ----
    #
    # MEASURED: `env -i HOME=/home/liuxd` has no USERNAME and no
    # USER, and `getpass.getuser()` fails with "No module named
    # 'pwd'" -- it is a Unix module.  But the HOME PATH IS THERE, and
    # its last part is the account's name:
    #
    #     /home/liuxd   ->   liuxd
    #
    # So that is where the answer comes from when the environment
    # does not say.
    home = os.environ.get("HOME") or os.environ.get("USERPROFILE") or ""
    if home:
        who = os.path.basename(home.rstrip("\\/"))
        if who:
            return who

    # ---- and the system, as a last resort ----
    try:
        import getpass
        who = getpass.getuser()
    except Exception:
        pass
    if who:
        return who
    try:
        import pwd
        who = pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        pass
    return who


def ensure_dir(path: str) -> str:
    """Make the directory, and its permissions as tight as they go.

    A private key in a world-readable directory is a private key in
    the open. On Windows the ACL is inherited from the parent, and
    %LOCALAPPDATA% is per-user, so it is already private; on Linux the
    mode has to be set.
    """
    os.makedirs(path, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def sshd_config() -> str:
    """The sshd config this end runs."""
    return os.path.join(state_dir(), "ljtunnel_sshd_config")


def host_key() -> str:
    """This end's own host key -- the identity clients see."""
    return os.path.join(state_dir(), "ljtunnel_host_ed25519")


def authorized_keys() -> str:
    """The keys allowed to log in to this end's sshd."""
    return os.path.join(state_dir(), "ljtunnel_authorized_keys")


def client_key() -> str:
    """The key this end uses to log in to the OTHER end.

    Named id_rsa_ljtunnel because that is what it is for: the ssh
    client's identity, distinct from the host key, and not the user's
    own ~/.ssh/id_rsa, which this must never touch.
    """
    return os.path.join(state_dir(), "id_rsa_ljtunnel")


def access_key() -> str:
    """The key a PERSON uses to reach a dialer.

    Separate from the machine key on purpose. The machine key is the
    dialer's own identity -- it is what the dialer logs in to the
    listen end with, and it lives on the dialer. This one is the
    end user's identity, and it lives on the end user's machine.

    Two identities for two different relationships: the listen end
    trusts the dialer, and the dialer trusts the person.
    """
    return os.path.join(state_dir(), "id_rsa_ljtunnel_access")


def known_hosts() -> str:
    """The ssh client's memory of the host keys it has seen.

    THIS IS THE USER'S OWN FILE, and not the tunnel's.  A person who
    connects to a dialer through a forwarded port goes through the
    ssh CLIENT, and the client remembers the host key it saw -- in
    the user's own known_hosts.

    And that memory goes STALE: a dialer that is set up again makes
    a new host key, and the old one is remembered, and the ssh client
    then says

        Host key for [localhost]:10002 has changed and you have
        requested strict checking.

    which is the ssh client being RIGHT and being unhelpful at the
    same time.  So the entries for the tunnel's ports are cleaned
    when the tunnel starts.
    """
    if sys.platform == "win32":
        base = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    else:
        base = os.environ.get("HOME") or os.path.expanduser("~")
    return os.path.join(base, ".ssh", "known_hosts")


def http_token() -> str:
    """The file the http server's token is kept in.

    **THE TOKEN IS KEPT, SO IT DOES NOT CHANGE EVERY TIME.**  A token
    that changes on every run is a token the person has to fetch again
    every time, and a URL that works today and not tomorrow is a
    thing nobody trusts.

    So the token is made once and written down here, and it is read
    back on the next run.
    """
    return os.path.join(state_dir(), "http_token")


def pid_file() -> str:
    return os.path.join(state_dir(), "ljtunnel_sshd.pid")


def log_file() -> str:
    return os.path.join(state_dir(), "ljtunnel_sshd.log")


def dialer_log() -> str:
    return os.path.join(state_dir(), "ljtunnel_dialer.log")


def start_record() -> str:
    """Where the app writes down how it started.

    "elevated" or "plain".  The difference between the two is
    invisible from the outside -- the window looks the same -- and
    it is the difference between the firewall rule going in with a
    prompt and the firewall rule going in without one.
    """
    return os.path.join(state_dir(), "ljtunnel_start.txt")
