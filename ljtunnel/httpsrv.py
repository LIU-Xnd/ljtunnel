"""A small HTTP server, for the dialer end to offer through the tunnel.

WHY IT IS HERE
--------------
The tunnel's other shape is: a machine that cannot be reached offers a
WEB PAGE to a machine that can be reached.  The dialer end runs this
server, and the reachable end's forwarded port lands on it.

    the unreachable end                  the reachable end
      this server  <--- the tunnel ---   http://<reachable>:10002/

THE TOKEN IS A COOKIE, AND NOT A PART OF THE URL
-------------------------------------------------
The server is on a machine that cannot be reached, so the only way in
is through the tunnel -- but the tunnel's port is on a machine that
other people can reach.  So the server does not serve anybody who
knows the address: it serves nobody who does not have the token.

    http://<the reachable end>:<the port>/?token=<the token>

The token is a random string, and it is compared in CONSTANT TIME, so
the time it takes does not say how much of it was guessed right.

**AND IT IS A COOKIE AFTER THE FIRST TIME, AND THAT IS THE POINT.**

MEASURED: with the token in the PATH, the server's own directory
listing links to `subdirectory/`, and clicking one dropped the token
-- so the next page said "no token".  A link that a person can click
and that keeps working is worth more than a link that needs the
secret pasted into it every time.

So the first request carries the token in the QUERY, the server says
`Set-Cookie`, and after that the token is in the COOKIE and the URL
is just the path.

**AND THE FIRST REQUEST IS ANSWERED WITH A REDIRECT**, so the token
goes out of the address bar and into the cookie jar, and the page the
person sees is a clean URL.

**AND THE COOKIE IS HTTP-ONLY AND SAME-SITE**, so a page on another
site cannot make the browser send it, and it does not go out in a
referrer.

**AND THE QUERY IS STILL ACCEPTED**, because a person may type the
URL again, and because the far end's own scan asks for the root with
no cookie and needs an answer.

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

import base64
import hmac
import http.server
import os
import posixpath
import secrets
import socketserver
import sys
import threading
import urllib.parse


# THE NAME OF THE COOKIE THE TOKEN IS IN.
#
# IT IS A NAME OF OUR OWN and not the word "token", because a cookie
# called "token" is a name another site can set too, and a page on
# another site could then make the browser send it.
COOKIE_NAME = "ljt_token"


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

    # **THE PROTOCOL IS 1.1, AND THAT IS NOT COSMETIC.**  MEASURED: with
    # the default 1.0 the server closes the connection after every
    # answer, so a client that keeps the connection open gets nothing
    # -- and a refusal that leaves the request's body on the
    # connection is then harmless, because there is no second request
    # to read it.
    #
    # **AND WITH 1.1 THE CONNECTION IS KEPT, SO THE LEFTOVERS MATTER.**
    # The body of a refused request is read and thrown away, so the
    # next request on that connection is a request and not the last
    # one's tail.
    protocol_version = "HTTP/1.1"
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

        **AND THE TOKEN CAN BE IN THREE PLACES, AND ALL THREE COUNT.**

        1. **THE COOKIE** -- and this is where it is after the first
           time.  The links the server itself writes are plain paths,
           so a click keeps the cookie and keeps working.

        2. **THE QUERY** -- `?token=...`.  This is how the person gets
           in the first time, and how the far end's own scan asks.

        3. **THE PATH** -- `/<token>/...`.  MEASURED: this is what it
           was, and the server's own directory listing links to
           `subdirectory/`, so clicking one dropped the token and the
           next page said "no token".  It is still accepted, because
           a URL that was printed and bookmarked works.
        """
        # 1. THE COOKIE.
        #
        # **AND IT IS COMPARED AGAINST THE TOKEN.**  MEASURED: the
        # cookie was only read and not compared, and the same was
        # true of the basic auth header -- and ANY of them was let in.
        _cookie = self._cookie_token()
        if _cookie and hmac.compare_digest(_cookie, self.token):
            return True

        # 2. THE BASIC AUTH HEADER.
        #
        # **AND THIS IS THE ONE THAT A PROGRAM USES.**  MEASURED: a
        # program with no cookie jar has to follow the redirect and
        # keep the cookie, and a program that wants to download ONE
        # file does not want a redirect at all -- it wants to say
        # who it is and get the file.
        #
        #     curl -u <the token>: http://<the reachable end>:<the port>/file
        #     wget --user=<the token> --password= http://<the reachable end>:<the port>/file
        #
        # **AND THE USER NAME IS THE TOKEN AND THE PASSWORD IS
        # EMPTY**, because there is one secret and not two, and a
        # password of nothing is what `curl -u token:` says.
        #
        # **AND THE HEADER IS COMPARED AGAINST THE TOKEN, AND NOT
        # TAKEN AS PROOF.**  MEASURED: it was not compared, and
        #
        #     curl -u wrongtoken: http://<host>:<port>/a/file
        #
        # answered 200 and gave the file.  ANY header with ANY user
        # name was let in.
        _basic = self._basic_token()
        if _basic and hmac.compare_digest(_basic, self.token):
            return True

        parsed = urllib.parse.urlparse(self.path)

        # 3. THE QUERY.
        q = urllib.parse.parse_qs(parsed.query)
        for value in q.get("token", []):
            if hmac.compare_digest(value, self.token):
                return True

        # 4. THE PATH.
        first = parsed.path.lstrip("/").split("/", 1)[0]
        if first and hmac.compare_digest(first, self.token):
            return True

        return False

    def _wants_html(self) -> bool:
        """Whether this client is a browser that can hold a cookie.

        **A BROWSER SAYS `Accept: text/html`.**  A program usually
        does not, and a program is the one that cannot hold a cookie
        and follow a redirect to a path with no token on it.
        """
        return "text/html" in (self.headers.get("Accept", "") or "")

    def _token_in_the_url(self) -> bool:
        """Whether the URL carries a token at all, right or wrong.

        **IT IS ABOUT THE PRESENCE AND NOT ABOUT THE VALUE.**  The
        question is "did the person try?", and a wrong token is a
        try.

        **AND IN THE PATH IT IS ABOUT HOW LONG IT IS.**  MEASURED: the
        first segment of the path was taken as a token, and so
        `/index.html` was a try -- and it answered 404 where it should
        have answered 401.

        So a first segment that is LONG is a try, and one that is
        short is a file name and not a try.  The token is made by
        `secrets.token_urlsafe`, so it is 43 characters, and a file
        name is not 43 characters.

        **AND A SEGMENT THAT LOOKS LIKE A TOKEN IS A TRY.**  MEASURED:
        the rule was the length, and it was wrong both ways -- a file
        called `index.html` is ten characters and was a try, and a
        token cut down to eight characters was not.

        So it is the SHAPE: the token is made by
        `secrets.token_urlsafe`, so it is letters, digits, `-` and
        `_` -- and a segment is a try when it is long enough AND it
        has none of the characters a file name has.  `index.html` has
        a dot in it and is not a try.
        """
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        if q.get("token"):
            return True
        first = parsed.path.lstrip("/").split("/", 1)[0]
        if len(first) < 8:
            return False
        return all(c.isalnum() or c in "-_" for c in first)

    def _basic_token(self) -> str:
        """The token in the Authorization header, or "".

        **THE HEADER IS BASIC, AND THE TOKEN IS THE USER NAME.**

        MEASURED: the whole point of it is that `curl` and `wget`
        both know how to send it, and neither of them knows how to
        keep a cookie across a redirect:

            curl -u <the token>: http://<host>:<the port>/a/file
            wget --user=<the token> --password= http://<host>:<the port>/a/file

        **AND THE COMPARISON IS IN CONSTANT TIME**, like every other
        comparison of the token.
        """
        raw = self.headers.get("Authorization", "")
        if not raw.lower().startswith("basic "):
            return ""
        try:
            decoded = base64.b64decode(raw[6:].strip()).decode(
                "utf-8", "replace")
        except (ValueError, TypeError):
            return ""
        # THE USER NAME IS THE TOKEN, and the password is empty.
        name, _, _password = decoded.partition(":")
        return name

    def _cookie_token(self) -> str:
        """The token in the cookie, or "".

        **THE COOKIE IS PARSED BY HAND, AND NOT BY http.cookies**, and
        the reason is that a cookie's value can be anything at all --
        including a value with a quote in it -- and the parser that
        ships with Python does not want a value it did not write.

        MEASURED: the token is made by `secrets.token_urlsafe`, so it
        is letters, digits, `-` and `_` -- and the parser is still
        written by hand so that a token made by somebody else (the
        `--http-token` one) does not have to be URL safe.
        """
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        for part in raw.split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME:
                return value.strip().strip('"')
        return ""

    def _refuse(self) -> None:
        """Say no, and say how to get in.

        **AND IT IS A 401 AND NOT A 404.**  MEASURED: the answer was
        404, which tells a program "there is nothing here" -- and a
        program that wanted the file had no way of knowing that the
        right thing to do was to say who it is.

        A 401 with a `WWW-Authenticate` header says "not yet, and
        here is how":

            curl -u <the token>: http://<host>:<the port>/a/file

        and `curl` and `wget` both know what to do with that.

        **AND THE 404 IS STILL THERE FOR A REQUEST WITH THE WRONG
        TOKEN.**  A wrong token is a wrong token, and saying "401, try
        again" would tell a person with a stale bookmark to try the
        same thing again.
        """
        # THE BODY IS READ HERE TOO -- see _no_write.
        self._drain_body()
        body = b"no token\n"
        # AND A REQUEST WITH A TOKEN THAT IS WRONG IS A 404, and not a
        # 401 -- because a 401 says "try again", and a wrong token
        # does not become right by trying again.
        #
        # **AND "GAVE SOMETHING" MEANS ANYWHERE.**  MEASURED: the
        # header and the cookie counted, and the query and the path
        # did not -- so a request for `/<a wrong token>/a/file` was
        # answered with a 401, which says "you did not try", and the
        # person DID try.
        if (self.headers.get("Authorization")
                or self._cookie_token()
                or self._token_in_the_url()):
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="ljtunnel"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _translate(self, path: str) -> str:
        """The file the path names, with the token taken off it.

        **AND THE TOKEN IS ONLY TAKEN OFF IF IT IS THERE.**  MEASURED:
        the first segment was always cut, because the token was always
        in the path.  Now the token is usually in the COOKIE and the
        path is just the path -- so cutting the first segment would
        cut the DIRECTORY NAME, and the page would be the wrong one.

        So the first segment is compared against the token, and it is
        only taken off if it IS the token.
        """
        parsed = urllib.parse.urlparse(self.path)
        raw = urllib.parse.unquote(parsed.path)
        parts = raw.lstrip("/").split("/", 1)
        first = parts[0] if parts else ""
        if first and hmac.compare_digest(first, self.token):
            # THE TOKEN IS IN THE PATH: take it off.
            rest = parts[1] if len(parts) > 1 else ""
        else:
            # IT IS NOT: the whole path is the path.
            rest = raw.lstrip("/")
        # THE PATH IS NORMALISED, so a `..` cannot get out of the
        # directory.
        was_dir = rest.endswith("/")
        rest = posixpath.normpath("/" + rest).lstrip("/")
        # AND THE TRAILING SLASH IS KEPT.
        #
        # MEASURED: it was dropped, and the base class answered a
        # directory without one with a 301 -- and the 301's Location
        # was the path WITHOUT the token, so following it said "no
        # token".  The trailing slash says "this is a directory", and
        # without it the server thinks the person asked for a file
        # with a directory's name.
        if was_dir and rest:
            rest += "/"
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

    def list_directory(self, path):
        """The directory listing, with the links the server can vouch for.

        **THE LINKS CARRY THE TOKEN IN THE QUERY, ALWAYS.**  MEASURED:
        the base class writes `subdirectory/`, and a click on it asked
        for `/subdirectory/` -- and the token was in the PATH, so the
        token was dropped and the answer was "no token".

        So the links are written here, and they carry the token in the
        QUERY.

        **AND THEY ALWAYS DO, EVEN WHEN THE COOKIE IS THERE.**  A
        program with no cookie jar has to be able to follow them, and
        it gets a 303 and a cookie when it follows one -- so it works,
        and the token does not stay in its address bar either.

        **AND A BROWSER DOES NOT SEE THE TOKEN IN THE ADDRESS BAR**,
        because the query on a link is answered with a 303 and a
        cookie, and the 303's Location is the plain path.
        """
        return self._listing_with_token(path)

    def _listing_with_token(self, path):
        """The directory listing, with `?token=` on every link.

        **AND THE LINKS ARE ABSOLUTE.**  MEASURED: they were relative
        -- `deeper/` -- and a browser resolved that against the page
        it was on, which is right, but a program that asked for it got
        `/deeper/`, and there was nothing there.  A link that starts
        with a slash is a link from the root, and both of them agree
        on what it means.
        """
        import html

        try:
            names = os.listdir(path)
        except OSError:
            self.send_error(404, "No permission to list directory")
            return None

        names.sort(key=lambda n: (not n.lower().startswith("."),
                                   n.lower()))
        display = html.escape(os.path.basename(os.path.abspath(path)) or "/")
        title = f"Directory listing for {display}"

        parts = [
            "<!DOCTYPE HTML>",
            '<html lang="en">',
            "<head>",
            '<meta charset="utf-8">',
            f"<title>{html.escape(title)}</title>",
            "</head>",
            "<body>",
            f"<h1>{html.escape(title)}</h1>",
            "<hr>",
            "<ul>",
        ]

        # AND THE PARENT, when there is one.
        #
        # **AND IT IS ".." AND NOT THE PATH.**  MEASURED: the parent
        # was worked out with posixpath on a WINDOWS path, and it came
        # out as
        #
        #     C%3A/Users/xnd_l/AppData/Local/Temp
        #
        # which is the whole path with the last part cut -- and the
        # root of the served directory is not the root of the disk.
        # The parent of a directory in a listing is always "..".
        # AND THE PATH OF THIS DIRECTORY, RELATIVE TO THE ROOT.
        #
        # **MEASURED: IT WAS THE DISK PATH.**  The link came out as
        #
        #     /C%3A/Users/xnd_l/AppData/Local/Temp/ljt-www-xxx/subdir/
        #
        # which is the whole disk path, and the server has no idea
        # what that is.  So the path is made relative to the root --
        # the root IS the served directory, and a URL says what is
        # served, not where it is on the disk.
        _here = path.replace(chr(92), "/")
        _root = self.root.replace(chr(92), "/")
        if _here.startswith(_root):
            _here = _here[len(_root):]
        if not _here.startswith("/"):
            _here = "/" + _here

        if path.rstrip("/") not in ("", "/"):
            _up = posixpath.dirname(_here.rstrip("/")) or "/"
            parts.append(f'<li><a href="{html.escape(self._link(_up))}">'
                         "..</a></li>")

        for name in names:
            full = os.path.join(path, name)
            link_name = _here.rstrip("/") + "/" + name
            display_name = name
            if os.path.isdir(full):
                # AND A DIRECTORY'S LINK ENDS IN A SLASH, and it is not
                # decoration.  MEASURED: without it the base class
                # answers a 301, and the 301's Location has no token
                # on it, so following it says "no token".
                link_name += "/"
                display_name = name + "/"
            parts.append(
                f'<li><a href="{html.escape(self._link(link_name))}">'
                f"{html.escape(display_name)}</a></li>")

        parts += ["</ul>", "<hr>", "</body>", "</html>"]

        encoded = "\n".join(parts).encode("utf-8", "surrogateescape")
        self.send_response(200)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(encoded)
        return None

    def _link(self, name: str) -> str:
        """The link to a name, with the token in it."""
        quoted = urllib.parse.quote(name)
        return f"{quoted}?token={urllib.parse.quote(self.token)}"

    def send_head(self):
        """The head of the answer, with the redirect's Location fixed.

        **AND THE REDIRECT'S LOCATION CARRIES THE TOKEN.**  MEASURED:
        the base class answers a directory whose path has no trailing
        slash with a 301, and the Location was the bare path -- with
        no token on it, so following it said "no token".
        """
        # AND THE PATH IS PUT BACK THE WAY IT WAS ASKED FOR, so the
        # base class sees what it expects.
        head = super().send_head()
        if head is None:
            return None
        # AND IF IT WAS A REDIRECT, THE TOKEN GOES ON THE LOCATION.
        code = getattr(self, "_headers_buffer", None)
        if (isinstance(code, list) and code
                and code[0].startswith("HTTP/1.1 301")):
            for i, line in enumerate(code):
                if line.lower().startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
                    if "token=" not in loc:
                        sep = "&" if "?" in loc else "?"
                        code[i] = (f"Location: {loc}{sep}token="
                                   f"{urllib.parse.quote(self.token)}\r\n")
                    break
        return head

    def do_GET(self):
        # AND THE TOKEN IN THE QUERY IS MOVED INTO THE COOKIE, AND THE
        # PAGE IS REDIRECTED.
        #
        # MEASURED: the token was in the PATH, and the server's own
        # directory listing links to `subdirectory/` -- so clicking one
        # dropped the token and the next page said "no token".
        #
        # So the token goes into the cookie and OUT of the address
        # bar, and the links are plain paths from then on.
        if self._take_token_out_of_the_url():
            return
        if not self._token_ok():
            self._refuse()
            return
        # the token is taken off and the rest is what is asked for
        self.path = "/" + self._translate(self.path)
        super().do_GET()

    def do_HEAD(self):
        if self._take_token_out_of_the_url():
            return
        if not self._token_ok():
            self._refuse()
            return
        self.path = "/" + self._translate(self.path)
        super().do_HEAD()

    def _take_token_out_of_the_url(self) -> bool:
        """Put the token in the cookie, and redirect.  True if it did.

        **AND IT ONLY HAPPENS WHEN THE TOKEN IS IN THE QUERY.**  A
        request that already has the cookie is left alone, and a
        request with the token in the PATH is not redirected -- the
        path form is what an old bookmark looks like, and a redirect
        would lose the path.

        **AND IT ONLY HAPPENS WHEN THE CLIENT CAN HOLD A COOKIE.**  A
        program with no cookie jar follows the redirect to a path with
        no token on it, and the answer is "no token" -- so a client
        with no cookie is answered with the page itself and no
        redirect, and the links it is given carry the token.

        **HOW THE CLIENT IS TOLD APART**: a browser sends
        `Accept: text/html`, and a program usually does not.  That is
        a hint and not a fact, so a program that DOES send it is
        answered with the redirect and gets the cookie, which is
        harmless -- it just does not keep it.
        """
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        values = q.get("token", [])
        if not values:
            return False
        if not any(hmac.compare_digest(v, self.token) for v in values):
            return False

        # AND A CLIENT THAT CANNOT HOLD A COOKIE IS SERVED THE PAGE.
        if not self._wants_html():
            return False

        # AND THE QUERY GOES, and the token comes back in the cookie.
        rest = {k: v for k, v in q.items() if k != "token"}
        target = parsed.path or "/"
        if rest:
            target += "?" + urllib.parse.urlencode(
                rest, doseq=True)

        # AND THE PATH IS MADE ABSOLUTE.  MEASURED: the redirect said
        # `deeper/`, and a browser resolved that against the page it
        # was on -- which is right -- but a program that asked for it
        # got `/deeper/`, and there was nothing there:
        #
        #     404
        #
        # A Location is a URL and not a fragment of one, and a URL
        # that starts with a slash is a URL from the root.
        if not target.startswith("/"):
            target = "/" + target

        self.send_response(303)
        self.send_header("Location", target)
        self._send_cookie()
        self.send_header("Content-Length", "0")
        self.end_headers()
        return True

    def _send_cookie(self) -> None:
        """Say the token in a cookie.

        **AND IT IS HTTP-ONLY AND SAME-SITE**, so a page on another
        site cannot make the browser send it, and it does not go out
        in a referrer.

        **AND IT HAS NO EXPIRY DATE**, so it lasts as long as the
        browser's session and not longer -- a token that is written
        down somewhere is a token that outlives the tunnel.
        """
        self.send_header(
            "Set-Cookie",
            f"{COOKIE_NAME}={self.token}; Path=/; HttpOnly; SameSite=Strict")

    # ---- AND THE METHODS THAT WOULD WRITE ARE SAID NO TO ----
    #
    # **THEY ARE HERE AND NOT LEFT TO THE DEFAULT, BECAUSE THE DEFAULT
    # SAYS "501 UNSUPPORTED METHOD"** -- which is true and is not an
    # answer to "can I put a file here?".  405 is the answer.
    #
    # **AND THE BODY IS READ AND THROWN AWAY.**  MEASURED: a refusal
    # that does not read the body leaves it on the connection, and the
    # next request on that connection reads the leftovers, and the
    # server dies with
    #
    #     ConnectionAbortedError: [WinError 10053]
    def do_PUT(self):
        self._no_write()

    def do_POST(self):
        self._no_write()

    def do_DELETE(self):
        self._no_write()

    def do_MKCOL(self):
        self._no_write()

    def _no_write(self) -> None:
        """Say no, in the way a server says no to a write."""
        self._drain_body()
        body = b"this server serves and nothing else\n"
        self.send_response(405)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Allow", "GET, HEAD")
        self.end_headers()
        self.wfile.write(body)

    def _drain_body(self) -> None:
        """Read the request's body and throw it away.

        **A REQUEST THAT IS REFUSED IS STILL READ.**  The body is on
        the connection, and if it is left there the next request reads
        it.
        """
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except (ValueError, TypeError):
            length = 0
        if length <= 0:
            return
        try:
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
        except OSError:
            pass

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
