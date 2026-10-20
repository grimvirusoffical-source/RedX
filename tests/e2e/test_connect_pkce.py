"""App-connect PKCE E2E against a real redxd (no mocks)."""
import base64
import hashlib
import secrets

import pytest
from conftest import Host


def pkce_pair():
    # Match unit-test style: long verifier, S256 challenge
    verifier = "verifier-001-" + ("abcdefghij" * 5)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = "state001" + ("Zz09_-" * 6)
    return verifier, challenge, state


@pytest.fixture
def host():
    h = Host().start()
    yield h
    h.kill()


def start_and_approve(h):
    v, ch, st = pkce_pair()
    body = {
        "v": 1,
        "state": st,
        "pkce_challenge": ch,
        "callback": "rottenapple://redx-callback",
        "provider": "rottenapple-launcher",
        "app": "com.acme.stardrift",
        "scope": "write",
        "prefix": "saves",
        "label": "app:com.acme.stardrift",
        "name": "Rotten Apple",
    }
    r = h.req("POST", "/v1/connect/start", body, key=h.admin_key)
    assert r.status in (200, 201), r.text
    rid = r.json()["request_id"]
    ap = h.req(
        "POST", "/v1/connect/approve", {"request_id": rid},
        key=h.admin_key,
        headers={"X-RedX-Confirm": "connectApprove", "Origin": h.url},
    )
    assert ap.status == 200, ap.text
    return v, ch, st, ap.json()["code"]


def test_pkce_verifier_mismatch(host):
    v, ch, st, code = start_and_approve(host)
    bad = host.req("POST", "/v1/connect/exchange", {
        "code": code, "pkce_verifier": "x" * 50, "state": st, "device_label": "t",
    })
    assert bad.status == 400
    assert bad.json().get("code") == "pkce_mismatch"


def test_state_mismatch_on_exchange(host):
    v, ch, st, code = start_and_approve(host)
    bad = host.req("POST", "/v1/connect/exchange", {
        "code": code, "pkce_verifier": v, "state": "state999" + ("Zz09_-" * 6), "device_label": "t",
    })
    assert bad.status == 400
    assert bad.json().get("code") == "state_mismatch"


def test_exchange_replay_refused(host):
    v, ch, st, code = start_and_approve(host)
    ok = host.req("POST", "/v1/connect/exchange", {
        "code": code, "pkce_verifier": v, "state": st, "device_label": "t",
    })
    assert ok.status == 200, ok.text
    assert ok.json()["key"].startswith("rx_live_")
    again = host.req("POST", "/v1/connect/exchange", {
        "code": code, "pkce_verifier": v, "state": st, "device_label": "t",
    })
    assert again.status in (400, 409)
    assert again.json().get("code") in ("code_used", "invalid_request", "superseded") or "used" in again.text


def test_plain_pkce_method_rejected(host):
    v, ch, st = pkce_pair()
    r = host.req("POST", "/v1/connect/start", {
        "v": 1, "state": st, "pkce_challenge": ch, "pkce_method": "plain",
        "callback": "rottenapple://redx-callback", "provider": "rottenapple-launcher",
        "app": "com.acme.stardrift", "scope": "write", "prefix": "saves",
        "label": "app:com.acme.stardrift", "name": "RA",
    }, key=host.admin_key)
    assert r.status == 400
