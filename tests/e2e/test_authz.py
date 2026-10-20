"""Authorization, IDOR and privilege escalation against a running host.

Every key here is created through the real /v1/keys API. These are authenticated
callers trying to exceed the scope, database or prefix they were granted.
"""
import pytest

from conftest import P

CONF = {"X-RedX-Confirm": "createKey"}


@pytest.fixture(scope="module")
def seeded(host):
    a = host.admin_key
    for i in (1, 10, 2):
        assert host.req("PUT", "/v1/path/" + P("players.red-xai.db:Player[ID=%d].Name" % i), '"p%d"' % i, key=a).status == 200
    assert host.req("POST", "/v1/dbs", {"name": "other"}, key=a).status in (200, 201, 409)
    assert host.req("PUT", "/v1/db/other/path/" + P("secret.red-xai.db:S[ID=1].V"), '"top"', key=a).status == 200
    return host


def test_read_key_cannot_write_or_delete(seeded):
    k, _ = seeded.make_key("read")
    path = "/v1/path/" + P("players.red-xai.db:Player[ID=1].Name")
    assert seeded.req("GET", path, key=k).status == 200
    assert seeded.req("PUT", path, '"x"', key=k).status == 403
    assert seeded.req("DELETE", path, key=k).status == 403


def test_db_bound_key_cannot_reach_other_db(seeded):
    k, _ = seeded.make_key("admin", db="default")
    assert seeded.req("GET", "/v1/db/other/path/" + P("secret.red-xai.db:S[ID=1].V"), key=k).status == 403
    assert seeded.req("PUT", "/v1/db/other/path/" + P("secret.red-xai.db:S[ID=1].V"), '"x"', key=k).status == 403
    dbs = seeded.req("GET", "/v1/dbs", key=k).json()
    assert "other" not in str(dbs)


def test_prefix_key_boundary(seeded):
    k, _ = seeded.make_key("write", prefix="players.red-xai.db:Player[ID=1]")
    ok = "/v1/path/" + P("players.red-xai.db:Player[ID=1].Name")
    assert seeded.req("GET", ok, key=k).status == 200
    for bad in ("players.red-xai.db:Player[ID=10].Name", "players.red-xai.db:Player[ID=2]",
                "players.red-xai.db:Player[ID=*]", "players.red-xai.db:Player",
                "players.red-xai.db:Player[ID=1],Player[ID=10]"):
        r = seeded.req("GET", "/v1/path/" + P(bad), key=k)
        assert r.status in (400, 403), (bad, r.status, r.text)
        assert "p10" not in r.text and "p2" not in r.text
        r = seeded.req("PUT", "/v1/path/" + P(bad), '"pwn"', key=k)
        assert r.status in (400, 403), (bad, r.status)
    # query routes refuse prefix keys outright
    assert seeded.req("POST", "/v1/query", {"q": "players.red-xai.db:Player[ID=*].Name"}, key=k).status == 403
    r = seeded.req("POST", "/v1/bx", {"q": '{Get[]} = players:Player[ID=*] -> Name'}, key=k)
    assert r.status == 403, r.text
    assert seeded.req("GET", "/v1/path/" + P("players.red-xai.db:Player[ID=10].Name"), key=seeded.admin_key).json()["value"] == '"p10"'


def test_non_admin_cannot_mint_keys(seeded):
    for scope in ("read", "write"):
        k, _ = seeded.make_key(scope)
        r = seeded.req("POST", "/v1/keys", {"scope": "admin", "db": "*"}, key=k, headers=CONF)
        assert r.status == 403


def test_db_admin_cannot_escalate_to_host_admin(seeded):
    k, _ = seeded.make_key("admin", db="default")
    for spec in ({"scope": "admin", "db": "*"}, {"scope": "admin", "db": "other"}, {"scope": "read", "db": "other"}):
        r = seeded.req("POST", "/v1/keys", spec, key=k, headers=CONF)
        assert r.status == 403, (spec, r.status, r.text)
    # host-level routes
    for m, p in (("GET", "/v1/admin/backup"), ("POST", "/v1/dbs"), ("DELETE", "/v1/db/other"),
                 ("GET", "/v1/admin/config"), ("POST", "/v1/cluster/join-token")):
        r = seeded.req(m, p, {"name": "zz"} if m == "POST" else None, key=k,
                       headers={"X-RedX-Confirm": "x"})
        assert r.status in (403, 404, 405), (m, p, r.status)


def test_prefixed_admin_cannot_mint_unprefixed_key(seeded):
    k, _ = seeded.make_key("admin", db="default", prefix="players.red-xai.db:Player[ID=1]")
    r = seeded.req("POST", "/v1/keys", {"scope": "admin", "db": "default"}, key=k, headers=CONF)
    assert r.status == 403


def test_key_idor_across_databases(seeded):
    _, other_id = seeded.make_key("read", db="other")
    _, host_id = seeded.make_key("admin", db="*")
    k, _ = seeded.make_key("admin", db="default")
    listed = seeded.req("GET", "/v1/keys", key=k).json()["keys"]
    assert all(x["db"] == "default" for x in listed), listed
    for kid in (other_id, host_id):
        assert seeded.req("GET", "/v1/keys/" + kid, key=k).status == 404
        assert seeded.req("DELETE", "/v1/keys/" + kid, key=k, headers={"X-RedX-Confirm": "revokeKey"}).status == 404
        assert seeded.req("POST", "/v1/keys/" + kid + "/rotate", {}, key=k, headers={"X-RedX-Confirm": "rotateKey"}).status == 404
    assert seeded.req("GET", "/v1/keys/" + host_id, key=seeded.admin_key).json()["status"] == "active"


def test_dangerous_ops_order_401_403_428(seeded):
    k, _ = seeded.make_key("read")
    assert seeded.req("DELETE", "/v1/db/other").status == 401
    assert seeded.req("DELETE", "/v1/db/other", key=k).status == 403
    r = seeded.req("DELETE", "/v1/db/other", key=seeded.admin_key)
    assert r.status == 428 and r.json()["code"] == "confirm_required"


def test_revoke_takes_effect_immediately(seeded):
    k, kid = seeded.make_key("write")
    p = "/v1/path/" + P("players.red-xai.db:Player[ID=2].Name")
    assert seeded.req("GET", p, key=k).status == 200
    assert seeded.req("DELETE", "/v1/keys/" + kid, key=seeded.admin_key, headers={"X-RedX-Confirm": "revokeKey"}).status == 200
    assert seeded.req("GET", p, key=k).status == 401


def test_rotate_grace_then_old_key_dies(seeded):
    import time
    k, kid = seeded.make_key("read")
    r = seeded.req("POST", "/v1/keys/%s/rotate" % kid, {"grace": "2s"}, key=seeded.admin_key, headers={"X-RedX-Confirm": "rotateKey"})
    assert r.status == 201, r.text
    nk = r.json()["key"]
    p = "/v1/path/" + P("players.red-xai.db:Player[ID=2].Name")
    assert seeded.req("GET", p, key=k).status == 200
    assert seeded.req("GET", p, key=nk).status == 200
    time.sleep(3)
    assert seeded.req("GET", p, key=k).status == 401
    assert seeded.req("GET", p, key=nk).status == 200
