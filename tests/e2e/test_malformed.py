"""Malformed input: the host must answer 4xx and keep serving, never crash or hang."""
import pytest
from conftest import P

PATH = "/v1/path/" + P("m.red-xai.db:B[ID=1]")


def alive(host):
    assert host.req("GET", "/healthz").status == 200


@pytest.mark.parametrize("body,ct", [
    ("not json", "application/json"),
    ("{", "application/json"),
    ('{"value":', "application/json"),
    ('{"value": ' + "[" * 5000 + "]" * 5000, "application/json"),
    ('{"box":"' + "[" * 300 + "]" * 300 + '"}', "application/json"),
    ("[" * 100000, "text/x-redx-box"),
    ("{Name[]} = " + '"' + "A" * 10 + '"' + "{" * 500, "text/x-redx-box"),
    ("\x00\x01\x02 binary", "text/x-redx-box"),
    ('{"value": 1e400}', "application/json"),
    ('{"value": {"a": {"a": ' * 300, "application/json"),
])
def test_malformed_put_bodies(host, body, ct):
    r = host.req("PUT", PATH, body, key=host.admin_key, headers={"Content-Type": ct})
    assert r.status in (400, 413), (r.status, r.text[:200])
    alive(host)


@pytest.mark.parametrize("path", [
    "m.red-xai.db:B[ID=1]/../../etc/passwd",
    "m.red-xai.db:../other.red-xai.db:B[ID=1]",
    "..%2F..%2Fetc%2Fpasswd",
    "m.red-xai.db:B[ID=1]." + "A" * 5000,
    "m.red-xai.db:B[ID=" + "9" * 400 + "]",
    "m.red-xai.db:B[ID=1]%00.Name",
    "m.red-xai.db:" + "B[ID=1]." * 2000,
])
def test_malformed_paths(host, path):
    r = host.req("GET", "/v1/path/" + path, key=host.admin_key)
    assert r.status in (400, 403, 404), (path, r.status)
    assert "root:" not in r.text
    alive(host)


def test_bad_query_params(host):
    for q in ("?ttl=abc", "?ttl=-5", "?ttl=99999999999999999999", "?checkpoint=x", "?ttl=5&ttl=6"):
        r = host.req("PUT", PATH + q, '"v"', key=host.admin_key)
        assert r.status in (200, 400), (q, r.status)
    alive(host)


def test_wrong_methods(host):
    for m in ("TRACE", "CONNECT", "PATCH"):
        r = host.req(m, "/v1/stats", key=host.admin_key)
        assert r.status in (400, 404, 405, 501), (m, r.status)
    alive(host)


def test_oversized_header_and_bad_content_length(host):
    r = host.req("GET", "/v1/stats", key=host.admin_key, headers={"X-Junk": "A" * 100000})
    assert r.status in (200, 431, 400), r.status
    alive(host)


def test_deeply_nested_boxql_is_rejected_not_crash(host):
    q = "{Get[]} = m:B[ID=1] -> " + "(" * 2000 + "Name" + ")" * 2000
    r = host.req("POST", "/v1/bx", {"q": q}, key=host.admin_key)
    assert r.status in (400, 403), r.status
    alive(host)
