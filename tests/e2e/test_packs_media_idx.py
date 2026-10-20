"""Packs, media and indexes against a real redxd (no mocks)."""
import hashlib
import os
import signal
import tempfile
import textwrap

import pytest
from conftest import Host, P


@pytest.fixture(scope="module")
def host():
    h = Host().start()
    yield h
    h.kill()


def test_pack_put_get_roundtrip(host):
    data = b"pack-payload-" + b"A" * 1000
    digest = hashlib.sha256(data).hexdigest()
    path = "/v1/db/default/pack/media/file/images/cat.bin"
    r = host.req("PUT", path, data, key=host.admin_key,
                 headers={"Content-Type": "application/octet-stream", "X-Redx-SHA256": digest})
    assert r.status == 201, r.text
    g = host.req("GET", path, key=host.admin_key)
    assert g.status == 200
    assert g.body == data


def test_pack_sha_mismatch_stores_nothing(host):
    data = b"good-bytes"
    bad = "0" * 64
    path = "/v1/db/default/pack/media/file/images/bad.bin"
    r = host.req("PUT", path, data, key=host.admin_key,
                 headers={"Content-Type": "application/octet-stream", "X-Redx-SHA256": bad})
    assert r.status == 422, r.text
    g = host.req("GET", path, key=host.admin_key)
    assert g.status == 404


def test_pack_traversal_rejected(host):
    for p in ("../etc/passwd", "images/../../secret", "images/foo/../../../x", "/abs", "a/./b"):
        r = host.req("PUT", "/v1/db/default/pack/media/file/" + p, b"x", key=host.admin_key,
                     headers={"Content-Type": "application/octet-stream"})
        assert r.status in (400, 404), (p, r.status, r.text)


def test_pack_malformed_name_rejected(host):
    # Pack names must match ^[A-Za-z0-9_-]{1,64}$; bang is rejected by the route.
    r = host.req("PUT", "/v1/db/default/pack/Bad!Name/file/x.bin", b"x", key=host.admin_key,
                 headers={"Content-Type": "application/octet-stream"})
    assert r.status in (400, 404), r.status

def test_pack_prefix_acl(host):
    data = b"secret-pack"
    assert host.req("PUT", "/v1/db/default/pack/media/file/private/a.bin", data, key=host.admin_key,
                    headers={"Content-Type": "application/octet-stream"}).status == 201
    k, _ = host.make_key("write", prefix="media.red-xai-pack:public")
    r = host.req("GET", "/v1/db/default/pack/media/file/private/a.bin", key=k)
    assert r.status == 403


def test_pack_oversize_rejected_by_upload_limit():
    """Oversize media: host with max_upload_mb=1 must reject a 1.5 MiB PUT."""
    data = tempfile.mkdtemp(prefix="redx-pack-")
    conf = os.path.join(data, "redx.toml")
    with open(conf, "w") as f:
        f.write("max_upload_mb = 1\n")
    h = Host(data_dir=data, extra_args=["--config", conf])
    h.start()
    try:
        blob = b"Z" * (1500 * 1024)
        r = h.req("PUT", "/v1/db/default/pack/media/file/big/z.bin", blob, key=h.admin_key,
                  headers={"Content-Type": "application/octet-stream"}, timeout=60)
        assert r.status in (413, 400, 422), "expected oversize reject, got %s %s" % (r.status, r.text[:200])
    finally:
        h.kill()


def test_idx_define_query_rebuild(host):
    assert host.req("PUT", "/v1/path/" + P("players.red-xai.db:Player[ID=1].Name"), '"Ann"',
                    key=host.admin_key).status == 200
    decl = textwrap.dedent('''\
        {PlayerByName[]} = [
            {File[]}   = "players.red-xai.db",
            {Box[]}    = "Player",
            {Fields[]} = ;["Name"]:,
            {Kind[]}   = "exact",
            {Fold[]}   = TRUE
        ];
        ''')
    r = host.req("PUT", "/v1/db/default/idx/players", {"decl": decl}, key=host.admin_key)
    assert r.status in (200, 201), r.text
    q = host.req("GET",
                 "/v1/db/default/idx/players/PlayerByName/query?mode=exact&field=Name&value=ann",
                 key=host.admin_key)
    assert q.status == 200, q.text
    bad = host.req("PUT", "/v1/db/default/idx/junk", {"decl": "{NotAnIndex[]}=TRUE;"}, key=host.admin_key)
    assert bad.status in (400, 422), bad.text
    rb = host.req("POST", "/v1/db/default/idx/players/rebuild", key=host.admin_key)
    assert rb.status == 200, rb.text


def test_idx_corrupt_file_host_stays_up(host):
    """Corrupt on-disk .red-xai-db-idx; restart must not crash the host."""
    decl = textwrap.dedent('''\
        {PlayerByName[]} = [
            {File[]}   = "players.red-xai.db",
            {Box[]}    = "Player",
            {Fields[]} = ;["Name"]:,
            {Kind[]}   = "exact",
            {Fold[]}   = TRUE
        ];
        ''')
    host.req("PUT", "/v1/path/" + P("players.red-xai.db:Player[ID=2].Name"), '"Bob"',
             key=host.admin_key)
    assert host.req("PUT", "/v1/db/default/idx/players2", {"decl": decl}, key=host.admin_key).status in (200, 201)
    target = None
    for root, _, files in os.walk(host.data_dir):
        for fn in files:
            if fn.endswith(".red-xai-db-idx"):
                target = os.path.join(root, fn)
                with open(target, "ab") as f:
                    f.write(b"\xffCORRUPT")
    assert target, "no idx file found to corrupt"
    host.restart(signal.SIGKILL)
    assert host.req("GET", "/healthz").status == 200
    q = host.req("GET",
                 "/v1/db/default/idx/players2/PlayerByName/query?mode=exact&field=Name&value=bob",
                 key=host.admin_key)
    assert q.status in (200, 400, 404), q.text
    assert host.req("PUT", "/v1/db/default/idx/players2", {"decl": decl}, key=host.admin_key).status in (200, 201)
    q2 = host.req("GET",
                  "/v1/db/default/idx/players2/PlayerByName/query?mode=exact&field=Name&value=bob",
                  key=host.admin_key)
    assert q2.status == 200, q2.text

def test_pack_survives_sigkill(host):
    data = b"durable-pack-" + b"Z" * 500
    path = "/v1/db/default/pack/media/file/persist/z.bin"
    assert host.req("PUT", path, data, key=host.admin_key,
                    headers={"Content-Type": "application/octet-stream"}).status == 201
    host.restart(signal.SIGKILL)
    g = host.req("GET", path, key=host.admin_key)
    assert g.status == 200 and g.body == data
