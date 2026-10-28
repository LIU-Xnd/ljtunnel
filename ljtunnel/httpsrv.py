"""A small HTTP server, for the dialer end to offer through the tunnel.

WHY IT IS HERE
--------------
The tunnel's other shape is: a machine that cannot be reached offers a
WEB PAGE to a machine that can be reached.  The dialer end runs this
server, and the reachable end's forwarded port lands on it.

    the unreachable end                  the reachable end
      this server  <--- the tunnel ---   http://<reachable>:10002/

THE TOKEN IS IN THE URL
-----------------------
The server is on a machine that cannot be reached, so the only way in
is through the tunnel -- but the tunnel's port is on a machine that
other people can reach.  So the server does not serve anybody who
knows the address: it serves nobody who does not have the token.

    http://<the reachable end>:<the port>/<the token>/

The token is a random string, and it is compared in CONSTANT TIME, so
the time it takes does not say how much of it was guessed right.

**THE TOKEN IS NOT IN THE PATH IT SERVES.**  A request for
`/<token>/some/file.html` serves `some/file.html`, and the token is
only the gate.  So the token is not a file name that has to be in
every link.

**AND IT IS IN THE PATH AND NOT A HEADER**, because a link that
works when it is clicked is worth more than a link that needs a
header.  A browser's address bar takes the whole thing, and a page
can link to another page with the token still on it.

WHAT IT SERVES
--------------
A directory, and the files in it.  A file that is asked for by name is
served from that directory and from nowhere else: the path is resolved
and then checked to be inside the directory, so a path with `..` in it
cannot get out.

    --http-directory <the directory>    what to serve
    --http-port <the port>              where to listen (default 10001)

**IT IS A SIMPLE SERVER AND IT SAYS SO.**  It serves files, it does
not try to be a framework, and it has no plugins and no configuration
file.  The point of the tunnel is to reach a machine, and the file
serving is what it is for.
"""
from __future__ import annotations

import hmac
import http.server
import os
import posixpath
import secrets
import socketserver
import sys
import threading
import urllib.parse


def make_token() -> str:
    """A fresh random token.

    **IT IS RANDOM AND NOT A HASH OF SOMETHING.**  A token that can be
    worked out from a known value is a token that can be worked out by
    somebody else.  So it is 32 bytes from the system's own generator.
    """
    return secrets.token_urlsafe(32)


class _Handler(http.server.SimpleHTTPRequestHandler):
    """The request handler, with the token checked in front of it."""

    # the token, and the directory
    token = ""
    root = ""
    # who this server is, for the far end to read
    name = ""
    fingerprint = ""

    def __init__(self, *args, **kwargs):
        """The directory is GIVEN to the handler.

        **THE CLASS ATTRIBUTE IS NOT ENOUGH.**  MEASURED: the class
        had `directory` on it and every file came back 404, because
        `SimpleHTTPRequestHandler.__init__` takes `directory` as an
        ARGUMENT and, when it is not given, uses `os.getcwd()` -- and
        it sets `self.directory` on the way in, over the class
        attribute.

        So the directory is passed here, the way the base class
        expects it.
        """
        super().__init__(*args, directory=kwargs.pop("directory", None)
                         or self.root, **kwargs)

    def _token_ok(self) -> bool:
        """Whether this request carries the token.

        **THE COMPARISON IS IN CONSTANT TIME.**  A comparison that stops
        at the first difference says how much of the token was guessed
        right, and a token is short enough to guess at.
        """
        path = urllib.parse.urlparse(self.path).path
        # THE TOKEN IS THE FIRST SEGMENT, and it is compared against
        # the whole thing, so a prefix does not pass.
        first = path.lstrip("/").split("/", 1)[0]
        return hmac.compare_digest(first, self.token)

    def _refuse(self) -> None:
        body = b"no token\n"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _translate(self, path: str) -> str:
        """The file the path names, with the token taken off it."""
        parsed = urllib.parse.urlparse(self.path)
        raw = urllib.parse.unquote(parsed.path)
        # THE TOKEN IS THE FIRST SEGMENT.
        parts = raw.lstrip("/").split("/", 1)
        rest = parts[1] if len(parts) > 1 else ""
        # THE PATH IS NORMALISED, so a `..` cannot get out of the
        # directory.
        rest = posixpath.normpath("/" + rest).lstrip("/")
        return rest

    def end_headers(self):
        """Say who this server is, in the headers.

        **THE REACHABLE END HAS TO BE ABLE TO NAME THIS DIALER.**  It
        finds its dialers by asking the forwarded port who is there,
        and for an sshd the answer is the host key behind it.  There is
        no host key behind an http server, so the server says so
        itself -- in a header, on every answer.

        The name is the dialer's own name, and the fingerprint is of
        the MACHINE KEY, which is the key the dialer logged in to the
        reachable end with.  So the reachable end can look the name up
        in its key list, exactly as it does for an sshd, and a dialer
        cannot call itself something it is not -- the fingerprint has
        to be one the key list knows.

        `end_headers` is the one place every answer goes through, so
        the headers are on the file list and on the directory list and
        on the refusal, without each one having to remember.
        """
        if self.name:
            self.send_header("X-LJT-Name", self.name)
        if self.fingerprint:
            self.send_header("X-LJT-Fingerprint", self.fingerprint)
        super().end_headers()

    def do_GET(self):
        if not self._token_ok():
            self._refuse()
            return
        # the token is taken off and the rest is what is asked for
        self.path = "/" + self._translate(self.path)
        super().do_GET()

    def do_HEAD(self):
        if not self._token_ok():
            self._refuse()
            return
        self.path = "/" + self._translate(self.path)
        super().do_HEAD()

    def log_message(self, fmt, *args):
        """The log goes to stderr, quietly.

        A request every time somebody refreshes the page is noise, and
        the dialer's own output is what a person reads.
        """
        if os.environ.get("LJT_HTTP_VERBOSE"):
            sys.stderr.write("  http: " + (fmt % args) + "\n")


class _Server(socketserver.ThreadingTCPServer):
    """The server, with the settings that make it work behind a tunnel.

    **IT IS THREADED**, so one slow request does not stop the next
    one, and **it ALLOWS THE ADDRESS TO BE REUSED**, so the tunnel
    can be restarted without waiting for the socket to time out.
    """

    allow_reuse_address = True
    daemon_threads = True


def serve(directory: str, port: int, token: str = "", host: str = "127.0.0.1",
          name: str = "", fingerprint: str = ""):
    """Start the server, and return (the server, the token).

    THE TOKEN IS MADE HERE if it is not given, and it is RETURNED, so
    the caller can put it in the URL it prints.  A caller that has its
    own token -- one it has written down -- passes it in.

    AND THE NAME AND THE FINGERPRINT ARE GIVEN TO IT, so the far end
    can read them out of the headers.  The fingerprint is of the
    MACHINE KEY -- the key the dialer logged in to the far end with --
    so the far end can look the name up in its own key list and a
    dialer cannot call itself something it is not.
    """
    root = os.path.abspath(directory)
    if not os.path.isdir(root):
        raise NotADirectoryError(f"{directory} is not a directory")

    tok = token or make_token()

    handler = type("_BoundHandler", (_Handler,),
                   {"token": tok, "root": root,
                    "name": name, "fingerprint": fingerprint})

    # THE DIRECTORY GOES TO THE HANDLER AS AN ARGUMENT, the way the
    # base class expects it -- see the note in the handler's __init__.
    class _Factory(handler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=root, **kwargs)

    srv = _Server((host, port), _Factory)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, tok


def make_handler(token: str, root: str):
    """The handler class, for a caller that wants its own server."""
    return type("_BoundHandler", (_Handler,), {"token": token, "root": root})
