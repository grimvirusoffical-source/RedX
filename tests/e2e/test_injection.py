"""Injection and parameter-safety against a running host.

Values and $params must never be parsed as BoxQL command text. A JSON PUT that
embeds Box delimiters must store them as literal string data, not as sibling keys.
"""
from conftest import P


def test_json_put_cannot_inject_sibling_box_keys(host):
    a = host.admin_key
    path = "/v1/path/" + P("inj.red-xai.db:U[ID=1]")
    payload = {"value": {"Name": 'x"]\n{Role[]} = "Admin"\n{z[]} = ["'}}
    assert host.req("PUT", path, payload, key=a).status == 200
    v = host.req("GET", path, key=a).json()["value"]
    # Top-level Box keys are the lines that look like `{Key[]} = ...` after stripping
    # indent. Injection would add a sibling Role key; correct escaping keeps Role
    # text inside the Name string only.
    keys = []
    for ln in v.splitlines():
        s = ln.strip()
        if s.startswith("{") and "[]}" in s:
            keys.append(s[1:s.index("[]}")])
    assert keys == ["Name"], (keys, v)


def test_boxql_params_are_never_command_text(host):
    a = host.admin_key
    assert host.req("PUT", "/v1/path/" + P("inj.red-xai.db:U[ID=2].Name"), '"bob"', key=a).status == 200
    attacks = [
        'bob"] , {Name[]} = "',
        '*',
        'x] -> Name; {Set[]} = inj:U[ID=2].Name = "pwn"',
        '{"$ne": null}',
    ]
    for v in attacks:
        r = host.req("POST", "/v1/bx", {"q": '{Get[]} = inj:U[Name = $n] -> Name', "params": {"n": v}}, key=a)
        assert r.status in (200, 400), (v, r.status, r.text)
        assert "pwn" not in r.text
    assert host.req("GET", "/v1/path/" + P("inj.red-xai.db:U[ID=2].Name"), key=a).json()["value"] == '"bob"'


def test_read_key_cannot_sneak_write_through_bx_or_tx(host):
    a = host.admin_key
    assert host.req("PUT", "/v1/path/" + P("inj.red-xai.db:U[ID=3].Gold"), "10", key=a).status == 200
    rk, _ = host.make_key("read")
    for q in (
        '{Set[]} = inj:U[ID=3].Gold = 999',
        '{Tx[]} = [ {Require[]} = inj:U[ID=3, Gold >= 0], {Set[]} = inj:U[ID=3].Gold = 999 ]',
        '{Add[]} = inj:U[ID=9] = [ {Gold[]} = 1 ]',
        '{Delete[]} = inj:U[ID=3]',
        '{Set [ ]} = inj:U[ID=3].Gold = 999',
    ):
        for explain in (False, True):
            r = host.req("POST", "/v1/bx", {"q": q, "explain": explain}, key=rk)
            assert r.status in (400, 403), (q, explain, r.status, r.text)
    assert host.req("GET", "/v1/path/" + P("inj.red-xai.db:U[ID=3].Gold"), key=a).json()["value"] == "10"


def test_path_null_byte_and_control_chars_rejected(host):
    for p in ("inj.red-xai.db:U[ID=1].Na\x00me", "inj.red-xai.db:U[ID=1].\x1fName"):
        r = host.req("GET", "/v1/path/" + P(p), key=host.admin_key)
        assert r.status == 400


def test_db_name_injection_rejected(host):
    for name in ("../x", "x/y", "x;rm", "x`id`", "DEFAULT", "a" * 100, "X", "-bad", "has space"):
        r = host.req("POST", "/v1/dbs", {"name": name}, key=host.admin_key)
        assert r.status in (400, 404, 409), (name, r.status, r.text)
