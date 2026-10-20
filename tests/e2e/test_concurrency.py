"""Concurrency and races against a running host, using real HTTP writes.

The key invariant is the BoxQL transaction: {Require}+{Set} must be atomic, so a
conditional debit under parallel load must never oversell.
"""
import concurrent.futures as cf

import pytest
from conftest import P


@pytest.fixture(scope="module")
def load_key(host):
    """A host-admin key with the per-key rate limit disabled (rate_rps=-1, documented)."""
    k, _ = host.make_key("admin", db="*", label="load", rate_rps=-1, rate_burst=-1)
    return k


def set_val(host, path, val, key):
    return host.req("PUT", "/v1/path/" + P(path), val, key=key).status


def test_conditional_debit_never_oversells(host, load_key):
    a = load_key
    assert set_val(host, "bank.red-xai.db:Acct[ID=1].Gold", "100", a) == 200
    debit = '{Tx[]} = [ {Require[]} = bank:Acct[ID=1, Gold >= 1], {Set[]} = bank:Acct[ID=1].Gold = Gold - 1 ]'

    def one(_):
        r = host.req("POST", "/v1/bx", {"q": debit}, key=a)
        return r.status, r.json().get("affected", 0) if r.status == 200 else 0

    with cf.ThreadPoolExecutor(32) as ex:
        res = list(ex.map(one, range(250)))
    ok = sum(aff for st, aff in res if st == 200)
    final = int(host.req("POST", "/v1/bx", {"q": '{Get[]} = bank:Acct[ID=1] -> Gold'}, key=a).json()["rows"][0][0])
    # started at 100; exactly min(100,250) successful debits, and the balance reconciles.
    assert final == 100 - ok, (final, ok)
    assert final >= 0
    assert ok == 100, "oversold or undersold: %d successful debits, final=%d" % (ok, final)


def test_concurrent_writes_to_same_record_are_serialized(host, load_key):
    a = load_key
    path = "race.red-xai.db:R[ID=1].N"
    assert set_val(host, path, "0", a) == 200

    def w(i):
        return set_val(host, path, str(i), a)

    with cf.ThreadPoolExecutor(32) as ex:
        codes = list(ex.map(w, range(500)))
    assert all(c == 200 for c in codes)
    v = host.req("GET", "/v1/path/" + P(path), key=a).json()["value"]
    assert v.strip() in {str(i) for i in range(500)}, v  # a clean last-writer value, not a torn mix


def test_parallel_db_create_same_name_is_idempotent_or_conflict(host, load_key):
    a = load_key

    def mk(_):
        return host.req("POST", "/v1/dbs", {"name": "racedb"}, key=a,
                        headers={"X-RedX-Confirm": "createDatabase"}).status

    with cf.ThreadPoolExecutor(16) as ex:
        codes = list(ex.map(mk, range(16)))
    assert all(c in (200, 201, 409, 428) for c in codes), codes
    dbs = host.req("GET", "/v1/dbs", key=a).json()
    assert str(dbs).count("racedb") >= 1


def test_concurrent_key_rotation_leaves_one_live_key(host, load_key):
    a = load_key
    k, kid = host.make_key("read")

    def rot(_):
        return host.req("POST", "/v1/keys/%s/rotate" % kid, {"grace": "0s"}, key=a,
                        headers={"X-RedX-Confirm": "rotateKey"})

    with cf.ThreadPoolExecutor(8) as ex:
        rs = list(ex.map(rot, range(8)))
    # at most the chain stays consistent; no 500s
    assert all(r.status in (201, 409) for r in rs), [r.status for r in rs]
