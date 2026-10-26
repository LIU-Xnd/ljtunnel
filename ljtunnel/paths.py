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
