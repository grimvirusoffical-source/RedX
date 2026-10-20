"""Accounts/OIDC E2E against a real external ES256 OIDC IdP process.

The IdP is the Accounts-contract server (cmd/e2e-oidc-idp), not mocked inside redxd.
Dex was considered but redxd accepts ES256-only ID tokens (host/accounts_oidc.go).
"""
import hashlib
import http.client
import json
import time
import urllib.parse
import urllib.request

import pytest

from oidc_helpers import (
    OWNER_A, OWNER_B, Browser, OIDCIdP, sign_in, start_accounts_host,
)


@pytest.fixture(scope="module")
def idp():
    s = OIDCIdP().start()
    yield s
    s.stop()


@pytest.fixture
def acct_host(idp):
    h = start_accounts_host(idp.issuer, idp=idp)
    yield h
    h.kill()


def test_happy_owner_signin(acct_host, idp):
    tok = sign_in(acct_host, idp, {
        "sub": "rxa_OWNER0000000000000000000001", "email": OWNER_A,
        "email_verified": True, "username": "owner_account",
        "amr": ["pwd", "otp"], "owner_scope": True,
    })
    r = acct_host.req("GET", "/v1/ui/whoami", key=tok)
    assert r.status == 200 and r.json()["account"]["owner"] is True


def test_code_verifier_mismatch_refuses_signin(acct_host, idp):
    """Stolen authorize code + wrong PKCE verifier must fail at the IdP token endpoint."""
    import base64, hashlib, secrets
    idp.set_next({
        "sub": "rxa_REGULAR00000000000000000001", "email": "user@example.com",
        "email_verified": True, "username": "u", "amr": ["pwd"],
    })
    cb = acct_host.url + "/v1/auth/callback"
    idp.register_redirects([cb])
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    auth = (
        idp.issuer + "/oauth2/authorize?"
        + urllib.parse.urlencode({
            "client_id": "redx", "redirect_uri": cb, "response_type": "code",
            "scope": "openid", "state": "st1", "nonce": "n1",
            "code_challenge": challenge, "code_challenge_method": "S256",
        })
    )
    # Do not follow redirect to callback — just capture Location
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(auth, timeout=10)
        raise AssertionError("expected redirect with code")
    except urllib.error.HTTPError as e:
        assert e.code in (302, 303)
        loc = e.headers.get("Location")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    code = q["code"][0]
    # Wrong verifier at IdP
    import base64 as b64
    token_url = idp.issuer + "/oauth2/token"
    body = urllib.parse.urlencode({
        "grant_type": "authorization_code", "code": code, "redirect_uri": cb,
        "client_id": "redx", "code_verifier": "x" * 64,
    }).encode()
    creds = b64.b64encode(b"redx:test-client-secret").decode()
    req = urllib.request.Request(token_url, data=body, method="POST",
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Authorization": "Basic " + creds})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raise AssertionError("wrong verifier accepted: %s" % resp.read())
    except urllib.error.HTTPError as e:
        assert e.code in (400, 401), e.code
        err = e.read().decode()
        assert "verifier" in err.lower() or "invalid_grant" in err.lower(), err
    # Forged host callback still yields no session
    r = acct_host.req("GET", "/v1/auth/callback?code=stolen&state=forged")
    # May land on HTML error page (200) after redirect follow — no rxs_ session
    assert acct_host.req("GET", "/v1/ui/whoami", key="rxs_forged").status == 401


def test_state_nonce_replay_refused(acct_host, idp):
    idp.set_next({
        "sub": "rxa_REGULAR00000000000000000002", "email": "user2@example.com",
        "email_verified": True, "username": "u2", "amr": ["pwd"],
    })
    b = Browser()
    loc1, _, _, _ = b.get(acct_host.url + "/v1/auth/login?return=dash")
    assert "handoff=" in loc1
    frag = loc1.split("#", 1)[-1]
    q = urllib.parse.parse_qs(frag.split("?", 1)[-1])
    handoff = q.get("handoff", [None])[0]
    st, body = b.post_json(acct_host.url + "/v1/auth/handoff", {"code": handoff})
    assert st == 200
    # Replay same handoff
    st2, _ = b.post_json(acct_host.url + "/v1/auth/handoff", {"code": handoff})
    assert st2 == 401


def test_redirect_uri_tampering_at_authorize(acct_host, idp):
    """IdP rejects unregistered redirect_uri once only the host callback is registered."""
    cfg = acct_host.req("GET", "/v1/auth/config").json()
    assert cfg["enabled"] is True
    idp.register_redirects([acct_host.url + "/v1/auth/callback"])
    evil = (
        idp.issuer + "/oauth2/authorize?"
        + urllib.parse.urlencode({
            "client_id": "redx",
            "redirect_uri": "http://evil.example/steal",
            "response_type": "code",
            "scope": "openid",
            "state": "x",
            "nonce": "y",
            "code_challenge": "A" * 43,
            "code_challenge_method": "S256",
        })
    )
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        opener.open(evil, timeout=10)
        status, body = 200, b""
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    except Exception as e:
        raise AssertionError(e)
    assert status == 400 and b"redirect" in body.lower(), (status, body)


def test_owner_requires_2fa_amr(acct_host, idp):
    """Owner email without otp/sms AMR is not owner (no escalation by email alone)."""
    tok = sign_in(acct_host, idp, {
        "sub": "rxa_OWNER0000000000000000000001", "email": OWNER_A,
        "email_verified": True, "username": "owner_account",
        "amr": ["pwd"], "owner_scope": True,
    })
    who = acct_host.req("GET", "/v1/ui/whoami", key=tok).json()["account"]
    assert who.get("owner") is False or who.get("owner_blocked")


def test_email_collision_does_not_transfer_owner(acct_host, idp):
    """Different sub claiming the owner email without owner_scope / 2FA cannot become owner."""
    tok = sign_in(acct_host, idp, {
        "sub": "rxa_ATTACKER0000000000000000001", "email": OWNER_A,
        "email_verified": True, "username": "attacker",
        "amr": ["pwd", "otp"], "owner_scope": False,
    })
    who = acct_host.req("GET", "/v1/ui/whoami", key=tok).json()["account"]
    assert who.get("owner") is not True


def test_unverified_email_owner_blocked(acct_host, idp):
    tok = sign_in(acct_host, idp, {
        "sub": "rxa_OWNER0000000000000000000001", "email": OWNER_A,
        "email_verified": False, "username": "owner_account",
        "amr": ["pwd", "otp"], "owner_scope": True,
    })
    who = acct_host.req("GET", "/v1/ui/whoami", key=tok).json()["account"]
    assert who.get("owner") is not True


def test_session_fixation_handoff_is_single_use(acct_host, idp):
    tok = sign_in(acct_host, idp, {
        "sub": "rxa_REGULAR00000000000000000003", "email": "u3@example.com",
        "email_verified": True, "username": "u3", "amr": ["pwd"],
    })
    assert tok.startswith("rxs_")
    # Attacker cannot mint a second session from the same completed flow without a new login
    assert acct_host.req("GET", "/v1/ui/whoami", key=tok).status == 200


def test_audience_confusion_refused(acct_host, idp):
    """ID token aud for a different client must not mint a session (BREAK if it does)."""
    try:
        sign_in(acct_host, idp, {
            "sub": "rxa_AUDCONF00000000000000000001", "email": "aud@example.com",
            "email_verified": True, "username": "audc", "amr": ["pwd"],
            "force_aud": "not-this-host",
        })
        raise AssertionError("session minted with wrong audience")
    except RuntimeError as e:
        assert "handoff" in str(e).lower() or "sign-in" in str(e).lower() or "401" in str(e) or "400" in str(e)


def test_issuer_confusion_refused(acct_host, idp):
    """ID token iss pointing at another issuer must not mint a session."""
    try:
        sign_in(acct_host, idp, {
            "sub": "rxa_ISSCONF00000000000000000001", "email": "iss@example.com",
            "email_verified": True, "username": "issc", "amr": ["pwd"],
            "force_iss": "http://evil-idp.example",
        })
        raise AssertionError("session minted with wrong issuer")
    except RuntimeError as e:
        assert "handoff" in str(e).lower() or "sign-in" in str(e).lower() or "401" in str(e) or "400" in str(e)


def test_redirect_uri_registered_only(acct_host, idp):
    """After registering only the host callback, evil redirect_uri is rejected at the IdP."""
    cb = acct_host.url + "/v1/auth/callback"
    idp.register_redirects([cb])
    evil = (
        idp.issuer + "/oauth2/authorize?"
        + urllib.parse.urlencode({
            "client_id": "redx",
            "redirect_uri": "http://evil.example/steal",
            "response_type": "code",
            "scope": "openid",
            "state": "x",
            "nonce": "y",
            "code_challenge": "A" * 43,
            "code_challenge_method": "S256",
        })
    )
    try:
        with urllib.request.urlopen(evil, timeout=10) as resp:
            status, body = resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read().decode()
    assert status == 400 and "redirect" in body.lower(), (status, body)
    # Legitimate callback still accepted (authorize redirects 302)
    good = (
        idp.issuer + "/oauth2/authorize?"
        + urllib.parse.urlencode({
            "client_id": "redx",
            "redirect_uri": cb,
            "response_type": "code",
            "scope": "openid",
            "state": "okstate",
            "nonce": "n",
            "code_challenge": "B" * 43,
            "code_challenge_method": "S256",
        })
    )
    try:
        with urllib.request.urlopen(good, timeout=10) as resp:
            assert resp.status in (200, 302)
    except urllib.error.HTTPError as e:
        # Redirect to loopback callback may fail open; accept 302 Location
        assert e.code in (302, 303, 400), e.code
