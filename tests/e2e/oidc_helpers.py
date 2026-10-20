"""Helpers to run an external Accounts-contract OIDC IdP and a redxd with Accounts on."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar

from conftest import Host, free_port

IDP_BIN = os.environ.get("E2E_OIDC_IDP", "/workspace/redx-e2e-bin/e2e-oidc-idp")
OWNER_A = "owner@example.com"
OWNER_B = "support-owner@example.com"


class OIDCIdP:
    def __init__(self):
        self.proc = None
        self.issuer = None

    def start(self):
        port = free_port()
        self.proc = subprocess.Popen(
            [IDP_BIN, "-addr", "127.0.0.1:%d" % port],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        line = self.proc.stdout.readline().strip()
        if not line.startswith("ISSUER="):
            raise RuntimeError("IdP failed: " + line + (self.proc.stdout.read() or ""))
        self.issuer = line.split("=", 1)[1]
        return self

    def set_next(self, identity: dict):
        req = urllib.request.Request(
            self.issuer + "/test/next", data=json.dumps(identity).encode(),
            method="POST", headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status in (200, 204)


    def register_redirects(self, urls):
        req = urllib.request.Request(
            self.issuer + "/test/redirects", data=json.dumps({"redirects": list(urls)}).encode(),
            method="POST", headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status in (200, 204)


    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def start_accounts_host(issuer: str, idp: "OIDCIdP | None" = None, **extra_env) -> Host:
    env = {
        "REDX_ACCOUNTS_ISSUER": issuer,
        "REDX_ACCOUNTS_CLIENT_ID": "redx",
        "REDX_ACCOUNTS_CLIENT_SECRET": "test-client-secret",
        "REDXAI_OWNER_EMAILS": OWNER_A + "," + OWNER_B,
        **extra_env,
    }
    h = Host(env=env)
    h.start()
    if idp is not None:
        # Allow this host's callback (and clear any prior host's registration).
        idp.register_redirects([h.url + "/v1/auth/callback"])
    return h


class Browser:
    """Minimal cookie-jar client that follows redirects (except fragment handoff)."""

    def __init__(self):
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def get(self, url, max_hops=12):
        final = url
        for _ in range(max_hops):
            req = urllib.request.Request(final, method="GET")
            try:
                with self.opener.open(req, timeout=30) as resp:
                    return resp.geturl(), resp.status, resp.read(), dict(resp.headers)
            except urllib.error.HTTPError as e:
                if e.code in (301, 302, 303, 307, 308):
                    loc = e.headers.get("Location")
                    if not loc:
                        return final, e.code, e.read(), dict(e.headers)
                    final = urllib.parse.urljoin(final, loc)
                    # Fragment handoffs: urllib may drop fragment; Location often has it
                    if "#" in loc:
                        return loc if loc.startswith("http") else urllib.parse.urljoin(final, loc), e.code, b"", dict(e.headers)
                    continue
                return final, e.code, e.read(), dict(e.headers)
        raise RuntimeError("too many redirects: " + final)

    def post_json(self, url, body):
        data = json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read())
            except Exception:
                return e.code, {"raw": e.read().decode("utf-8", "replace")}


def sign_in(host: Host, idp: OIDCIdP, identity: dict) -> str:
    idp.set_next(identity)
    b = Browser()
    loc, status, _, _ = b.get(host.url + "/v1/auth/login?return=owner")
    # Expect console handoff in fragment /signin?handoff=...
    if "handoff=" not in loc and "#/signin" not in loc:
        raise RuntimeError("sign-in did not hand off: status=%s loc=%s" % (status, loc))
    frag = loc.split("#", 1)[-1]
    q = urllib.parse.parse_qs(frag.split("?", 1)[-1] if "?" in frag else "")
    # Sometimes Location is full URL with fragment
    if "handoff" not in q and "handoff=" in loc:
        q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).fragment.split("?", 1)[-1])
    code = q.get("handoff", [None])[0]
    if not code:
        # try query string
        q2 = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
        code = q2.get("handoff", [None])[0]
    if not code:
        raise RuntimeError("no handoff in " + loc)
    st, body = b.post_json(host.url + "/v1/auth/handoff", {"code": code})
    if st != 200:
        raise RuntimeError("handoff %s %s" % (st, body))
    return body["token"]
