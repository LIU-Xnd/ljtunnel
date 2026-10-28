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
import re
import secrets
import socketserver
import sys
import threading
import urllib.parse

from . import httptokens


def _walks_up(rel: str) -> bool:
    """Whether a relative path walks out of the directory.

    **A PATH THAT WALKS UP IS REFUSED, AND NOT BROUGHT BACK.**  The
    normaliser would turn `..` into the root itself, and the request
    would succeed -- against the wrong file.

    MEASURED: `PUT /<token>/../escape.txt` came back "it worked", and
    the file landed in the directory above.  The name was normalised
    first and the check was on the normalised name, so the check
    never fired.
    """
    parts = rel.replace("\\", "/").split("/")
    depth = 0
    for part in parts:
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
            continue
        depth += 1
    return False


def _multipart_files(body: bytes, boundary: bytes):
    """The files in a multipart body, as (name, bytes).

    **ONLY THE PART THAT IS NEEDED.**  The boundary, each part's
    headers, and the bytes -- and the bytes are found by looking for
    the NEXT boundary, so a file's contents are not searched for the
    boundary.
    """
    # THE PARTS ARE BETWEEN THE BOUNDARIES.
    parts = body.split(boundary)
    for part in parts[1:]:
        if part.startswith(b"--"):
            break
        part = part.lstrip(b"\r\n")
        head, _, data = part.partition(b"\r\n\r\n")
        if not _:
            continue
        # THE TRAILING CRLF BEFORE THE NEXT BOUNDARY IS NOT PART OF
        # THE FILE.
        if data.endswith(b"\r\n"):
            data = data[:-2]
        # THE FILE'S NAME IS IN THE HEADERS.
        name = ""
        for line in head.split(b"\r\n"):
            line = line.decode("utf-8", "replace")
            if line.lower().startswith("content-disposition"):
                nm = re.search(r'filename="([^"]*)"', line)
                if nm:
                    name = nm.group(1)
        if name:
            yield (name, data)


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
    # THE TOKENS.  A LIST, because there is more than one of them.
    tokens = ()
    # who this server is, for the far end to read
    name = ""
    fingerprint = ""
    # MAY SOMEBODY WRITE HERE?
    allow_edit = False

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

    def _given_token(self) -> str:
        """The token this request carries, or "".

        **THE TOKEN IS THE FIRST SEGMENT OF THE PATH**, and it is
        compared against the WHOLE thing, so a prefix does not pass.
        """
        path = urllib.parse.urlparse(self.path).path
        return path.lstrip("/").split("/", 1)[0]

    def _token_ok(self) -> bool:
        """Whether this request carries a token that is in the table.

        **THE COMPARISON IS IN CONSTANT TIME.**  A comparison that stops
        at the first difference says how much of the token was guessed
        right, and a token is short enough to guess at.

        **AND EVERY TOKEN IN THE TABLE IS COMPARED**, because the
        table holds ten of them by default and a person has to be able
        to use any of them.
        """
        given = self._given_token()
        if not given:
            return False
        for known in self.tokens:
            if hmac.compare_digest(given, known):
                return True
        return False

    def _refuse(self) -> None:
        body = b"no token\n"
        self.send_response(404)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _translate(self, path: str) -> str:
        """The file the path names, with the token taken off it.

        **THE PATH IS NOT NORMALISED HERE.**  MEASURED: it was, and the
        normaliser turned `..` into the root itself -- so a request
        that walked out of the directory was quietly brought back in,
        and the check on the normalised path never fired.

        So the raw path is kept here and the walk is checked on it in
        `_resolve`.
        """
        parsed = urllib.parse.urlparse(self.path)
        raw = urllib.parse.unquote(parsed.path)
        # THE TOKEN IS THE FIRST SEGMENT.
        parts = raw.lstrip("/").split("/", 1)
        rest = parts[1] if len(parts) > 1 else ""
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
        rel = self._translate(self.path)
        self.path = "/" + rel
        # AND THE DIRECTORY LIST IS THIS SERVER'S OWN, so it can have
        # an upload form in it.  The one in the base class is a plain
        # table of links.
        if self.allow_edit and not rel and not self.path.endswith("/"):
            self.send_response(301)
            self.send_header("Location", self.path + "/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.allow_edit and not rel:
            self._send_edit_list()
            return
        super().do_GET()

    def _send_edit_list(self):
        """The directory list, with an upload form in it.

        **THE UPLOAD FORM IS WHY THE SWITCH EXISTS.**  A browser that
        can be pointed at the server can then PUT a file into it, and
        a page that is only a list of links cannot.

        THE FORM POSTS TO THE SAME URL WITH A QUERY STRING, because a
        browser's form cannot send a PUT.
        """
        try:
            names = sorted(os.listdir(self.root))
        except OSError as e:
            self.send_error(500, str(e))
            return

        rows = []
        for n in names:
            full = os.path.join(self.root, n)
            if os.path.isdir(full):
                rows.append(f'<li><a href="{n}/">{n}/</a></li>')
            else:
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                rows.append(f'<li><a href="{n}">{n}</a> '
                            f'<span class="size">{size} bytes</span></li>')

        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>{self.root}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2em; }}
 h1 {{ font-size: 1.2em; }}
 ul {{ list-style: none; padding: 0; }}
 li {{ padding: .3em 0; border-bottom: 1px solid #eee; }}
 .size {{ color: #888; font-size: .85em; margin-left: .5em; }}
 form {{ margin: 1.5em 0; padding: 1em; border: 1px solid #ddd;
         border-radius: 4px; }}
 input[type=file] {{ margin: .5em 0; }}
 .bar {{ background: #f5f5f5; padding: .6em; border-radius: 3px;
         margin: 1em 0; font-size: .9em; }}
</style></head><body>
<h1>{self.root}</h1>
{"<div class='bar'>UPLOAD AND DELETE ARE ON. Anyone with the token can change what is here.</div>" if self.allow_edit else "<div class='bar'>This server is read-only.</div>"}
<ul>
{chr(10).join(rows)}
</ul>
<form method="post" enctype="multipart/form-data" action="?upload">
<input type="file" name="file" multiple>
<button type="submit">Upload</button>
</form>
</body></html>
"""
        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        """The upload form.

        **A BROWSER'S FORM CANNOT SEND A PUT**, so the form posts and
        the body is read out of the multipart encoding by hand.  It is
        the one part of the multipart format that is needed: the
        boundary, the headers of each part, and the bytes.
        """
        if not self.allow_edit:
            self._no_edit()
            return
        if not self._token_ok():
            self._refuse()
            return

        ctype = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in ctype:
            self.send_error(400, "expected a form")
            return
        m = re.search(r'boundary="?([^";]+)"?', ctype)
        if not m:
            self.send_error(400, "no boundary")
            return
        boundary = ("--" + m.group(1)).encode("ascii")

        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self.send_error(400, "bad length")
            return
        body = self.rfile.read(length) if length else b""

        saved = []
        for name, data in _multipart_files(body, boundary):
            # THE NAME IS THE FILE'S NAME, and it is taken apart and
            # checked like any other path.
            base = os.path.basename(name.replace("\\", "/"))
            if not base or base in (".", ".."):
                continue
            full = os.path.abspath(os.path.join(self.root, base))
            root_abs = os.path.abspath(self.root)
            if not full.startswith(root_abs + os.sep):
                continue
            try:
                with open(full, "wb") as fh:
                    fh.write(data)
                httptokens.set_owner(
                    self._relative(full), self._given_token())
                saved.append(base)
            except OSError:
                pass

        self.send_response(303)
        self.send_header("Location", self.path or "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_HEAD(self):
        if not self._token_ok():
            self._refuse()
            return
        self.path = "/" + self._translate(self.path)
        super().do_HEAD()

    # ---- THE WRITING SIDE ----

    def _resolve(self, path: str) -> str:
        """The real file a path names, or "".

        **THE PATH IS NORMALISED AND THEN CHECKED TO BE INSIDE THE
        DIRECTORY.**  Two things, and the second one is what matters:
        a path that normalises to something OUTSIDE the directory is
        not served, whatever it looks like.

        MEASURED: `..` in a path, and `..` percent-encoded, both
        asked for a file outside the directory.
        """
        rel = self._translate(path)
        # THE RELATIVE PATH IS CHECKED BEFORE IT IS JOINED.  A path
        # that walks UP is refused, and not silently brought back
        # inside -- MEASURED: `/..` normalised to the root itself, and
        # the file was written there, and the answer was "it worked".
        #
        # So the check is on the REQUESTED path, and the normalised
        # one is only used to build the file name.
        if _walks_up(rel):
            return ""
        # AND NOW IT IS NORMALISED, so a `.` or a doubled slash in the
        # path is harmless.
        rel = posixpath.normpath("/" + rel).lstrip("/")
        full = os.path.abspath(os.path.join(self.root, rel))
        # AND THE CHECK IS WITH THE SEPARATOR, so a directory whose
        # name STARTS with the root's name is not inside it:
        # /data/pub is not inside /data/pub2.
        base = os.path.abspath(self.root)
        if full != base and not full.startswith(base + os.sep):
            return ""
        return full

    def _relative(self, full: str) -> str:
        """The file's path relative to the root, with forward slashes.

        **IT IS THE SAME STRING EVERY TIME**, because the owner record
        is looked up by it -- so it is built from the FULL path and
        the root, and not from the request.
        """
        base = os.path.abspath(self.root)
        rel = os.path.abspath(full)
        if rel.startswith(base + os.sep):
            rel = rel[len(base) + 1:]
        return rel.replace(os.sep, "/")

    def _no_edit(self) -> None:
        """Say no, in the way a server says no."""
        body = b"this server is read-only\n"
        self.send_response(405)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Allow", "GET, HEAD")
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        """Put a file here.

        **THE BODY IS THE FILE, AND IT IS WRITTEN TO A TEMPORARY FILE
        AND THEN MOVED.**  A file that is written in place is a file
        that is half-written if the connection drops, and the point of
        the tunnel is that the far side is not reachable -- so a
        half-written file there is a file nobody can fix.

        MEASURED: the move is what makes it all-or-nothing.
        """
        if not self.allow_edit:
            self._no_edit()
            return
        if not self._token_ok():
            self._refuse()
            return

        full = self._resolve(self.path)
        if not full:
            self.send_error(403, "no")
            return
        if os.path.isdir(full):
            self.send_error(409, "that is a directory")
            return

        parent = os.path.dirname(full)
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as e:
            self.send_error(500, str(e))
            return

        # THE LENGTH, WHEN THERE IS ONE.  A request with no length is
        # a request with no body, and there is nothing to write.
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            self.send_error(400, "bad length")
            return

        tmp = full + ".ljt-part"
        try:
            with open(tmp, "wb") as fh:
                if length > 0:
                    fh.write(self.rfile.read(length))
                else:
                    # NO LENGTH: the body is read until the end of the
                    # request, which is what a chunked request is.
                    while True:
                        chunk = self.rfile.read(65536)
                        if not chunk:
                            break
                        fh.write(chunk)
            os.replace(tmp, full)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            self.send_error(500, str(e))
            return

        # AND THE FILE REMEMBERS WHO PUT IT THERE, so that only that
        # token can take it away again.
        httptokens.set_owner(self._relative(full), self._given_token())

        self.send_response(201 if not os.path.exists(full) else 204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_DELETE(self):
        """Delete a file or a directory.

        **ONLY THE TOKEN THAT PUT IT THERE CAN TAKE IT AWAY.**

        Everybody with a token can put a file in, and everybody with a
        token can take one out -- but only the person whose token put
        it there can take IT out.  So a person cannot delete
        somebody else's work by guessing a name.

        MEASURED: this is the rule that makes the table worth having.
        Without it, one token is one person, and one person cannot
        share a machine with anybody else.
        """
        if not self.allow_edit:
            self._no_edit()
            return
        if not self._token_ok():
            self._refuse()
            return

        full = self._resolve(self.path)
        if not full or full == os.path.abspath(self.root):
            # THE ROOT ITSELF IS NOT DELETABLE.  A request for the
            # root with a DELETE would take the whole directory away.
            self.send_error(403, "no")
            return
        if not os.path.exists(full):
            self.send_error(404, "no such thing")
            return

        # AND THE TOKEN HAS TO BE THE ONE THAT PUT IT THERE.
        rel = self._relative(full)
        owner = httptokens.owner_of(rel)
        given = self._given_token()
        if owner and not hmac.compare_digest(owner, given):
            self.send_error(403, "that is not yours to delete")
            return

        try:
            if os.path.isdir(full):
                import shutil
                shutil.rmtree(full)
            else:
                os.unlink(full)
        except OSError as e:
            self.send_error(500, str(e))
            return

        # AND THE OWNER RECORD GOES WITH IT.
        httptokens.clear_owner(rel)

        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_MKCOL(self):
        """Make a directory.  The WebDAV way.

        IT IS HERE because a WebDAV CLIENT sends it, and this is
        "like WebDAV but simpler" -- so the methods a client uses are
        the ones it knows.
        """
        if not self.allow_edit:
            self._no_edit()
            return
        if not self._token_ok():
            self._refuse()
            return

        full = self._resolve(self.path)
        if not full:
            self.send_error(403, "no")
            return
        if os.path.exists(full):
            self.send_error(405, "it is already there")
            return
        try:
            os.makedirs(full, exist_ok=True)
        except OSError as e:
            self.send_error(500, str(e))
            return
        self.send_response(201)
        self.send_header("Content-Length", "0")
        self.end_headers()

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
          name: str = "", fingerprint: str = "", allow_edit: bool = False,
          tokens=None):
    """Start the server, and return (the server, the token).

    THE TOKEN IS MADE HERE if it is not given, and it is RETURNED, so
    the caller can put it in the URL it prints.  A caller that has its
    own token -- one it has written down -- passes it in.

    AND THE NAME AND THE FINGERPRINT ARE GIVEN TO IT, so the far end
    can read them out of the headers.  The fingerprint is of the
    MACHINE KEY -- the key the dialer logged in to the far end with --
    so the far end can look the name up in its own key list and a
    dialer cannot call itself something it is not.

    AND `allow_edit` IS THE SWITCH BETWEEN A SERVER YOU CAN READ AND
    A SERVER YOU CAN WRITE TO.  It is OFF unless it is asked for.

    AND THE TOKENS ARE A LIST, because there is more than one of them
    and each one is a separate key to the same door.
    """
    root = os.path.abspath(directory)
    if not os.path.isdir(root):
        raise NotADirectoryError(f"{directory} is not a directory")

    # THE TOKENS ARE THE LIST, and the single `token` is the first of
    # it -- so a caller that has one token and a caller that has a
    # table both work.
    if tokens:
        toks = list(tokens)
    else:
        toks = [token or make_token()]
    tok = toks[0]

    handler = type("_BoundHandler", (_Handler,),
                   {"token": tok, "tokens": tuple(toks), "root": root,
                    "name": name, "fingerprint": fingerprint,
                    "allow_edit": allow_edit})

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
