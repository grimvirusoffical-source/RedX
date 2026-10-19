"""Generated operations, danger levels, files, media, transactions, reconnecting streams and the app side
of the connect handshake, against a real redxd."""
import hashlib
import json
import os
import sys
import threading
import time
import unittest
import warnings

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import redx  # noqa: E402
from redx import RedX, RedXError  # noqa: E402
from tests.harness import Host  # noqa: E402

host = admin = None


def setUpModule():
    global host, admin
    host = Host()
    admin = RedX(host.url, host.admin_key)


def tearDownModule():
    if host:
        host.stop()


def wait_for(cond, secs=8.0):
    t0 = time.time()
    while not cond():
        if time.time() - t0 > secs:
            raise AssertionError("timed out waiting")
        time.sleep(0.02)


class Full(unittest.TestCase):
    def test_00_table_matches_spec(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "..", "..", "api", "redx-api.json")) as f:
            spec = json.load(f)
        self.assertEqual(len(redx.OPERATIONS), len(spec["operations"]))
        for o in spec["operations"]:
            self.assertEqual(redx.OPERATIONS[o["id"]]["danger"], o["danger"], o["id"])
        for op in ("deleteDatabase", "createKey", "revokeKey", "promote", "repoint", "connectApprove", "createJoinToken"):
            self.assertEqual(redx.danger_of(op), "dangerous", op)
        self.assertEqual(redx.danger_of("get_path"), "safe")
        self.assertEqual(redx.DANGER["dangerous"], 3)

    def test_01_dangerous_refused_without_request(self):
        c = RedX("http://127.0.0.1:9", "rx_" + "live_" + "x" * 43)  # nothing listens there
        for op in ("deleteDatabase", "promote", "connectApprove", "createPairingCode"):
            with self.assertRaises(RedXError) as cm:
                c.call(op, db="x")
            self.assertEqual((cm.exception.code, cm.exception.status), ("confirm_required", 0), op)
        with self.assertRaises(RedXError) as cm:
            c.delete_database(db="x")
        self.assertEqual(cm.exception.code, "confirm_required")
        self.assertNotIn("xxxx", repr(c))

    def test_02_data(self):
        admin.create_database(body={"name": "sdkpy"})
        self.assertIn("sdkpy", json.dumps(admin.list_databases()))
        c = admin.with_db("sdkpy")
        c.set("p.red-xai.db:P[ID=1]", {"Name": "Ann", "Level": 5})
        self.assertEqual(c.get("p.red-xai.db:P[ID=1]"), {"Name": "Ann", "Level": 5})
        self.assertEqual(c.get_path("p.red-xai.db:P[ID=1].Name")["value"], '"Ann"')
        self.assertIn("Ann", c.get_path_box("p.red-xai.db:P[ID=1]"))
        c.set_path("s.red-xai-db-qs:S[ID=1]", body={"value": "short", "ttl_seconds": 1})
        self.assertEqual(c.get("s.red-xai-db-qs:S[ID=1]"), "short")
        time.sleep(2.5)
        with self.assertRaises(RedXError) as cm:
            c.get("s.red-xai-db-qs:S[ID=1]")
        self.assertEqual(cm.exception.status, 404)
        self.assertEqual(c.bx("{Get[]} = p:P[Level >= $min] -> Name", {"min": 3})["count"], 1)
        t = c.tx(["{Set[]} = p:P[ID=1].Level = $l", '{Add[]} = p:P[ID=3] = [ {Name[]} = "Cy" ]'], {"l": 9})
        self.assertEqual(len(t["results"]), 2)
        with self.assertRaises(RedXError) as cm:
            c.tx(["{Require[]} = p:P[ID=1, Level > 100]", "{Delete[]} = p:P[ID=3]"])
        self.assertEqual(cm.exception.status, 409)
        self.assertEqual(c.get("p.red-xai.db:P[ID=3]"), {"Name": "Cy"})
        c.delete_path("p.red-xai.db:P[ID=3]")
        self.assertIsNone(c.get_or("p.red-xai.db:P[ID=3]"))

    def test_03_keys(self):
        k = admin.call("createKey", body={"db": "sdkpy", "scope": "read", "label": "py-ro"}, confirm=True)
        ro = RedX(host.url, k["key"], "sdkpy")
        self.assertEqual(ro.get("p.red-xai.db:P[ID=1].Name"), "Ann")
        with self.assertRaises(RedXError) as cm:
            ro.set("p.red-xai.db:P[ID=9]", 1)
        self.assertEqual(cm.exception.status, 403)
        rot = admin.rotate_key(k["id"], body={"grace": "0s"}, confirm=True)
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # a confirmed legacy call issues no warning
            admin.revoke_key(rot["id"], confirm=True)
        with self.assertRaises(RedXError) as cm:
            RedX(host.url, rot["key"]).get("p.red-xai.db:P[ID=1]")
        self.assertEqual(cm.exception.status, 401)
        pc = admin.create_pairing_code(body={"db": "sdkpy", "scope": "read"}, confirm=True)
        self.assertTrue(redx.exchange_pairing_code(host.url, pc["code"])["key"].startswith("rx_live_"))

    def test_04_files(self):
        c = admin.with_db("sdkpy")
        data = os.urandom(300000)
        c.upload_file("assets", "lvl/one.bin", data)
        self.assertEqual(c.pack_stat("assets", "lvl/one.bin")["size"], len(data))
        self.assertEqual(c.download_file("assets", "lvl/one.bin"), data)
        self.assertEqual(c.download_file("assets", "lvl/one.bin", range=(10, 19)), data[10:20])
        self.assertIn("one.bin", json.dumps(c.pack_list("assets", "lvl")))
        with self.assertRaises(RedXError) as cm:
            c.pack_put("assets", "bad.bin", body=b"x", headers={"X-Redx-SHA256": "0" * 64})
        self.assertEqual(cm.exception.status, 422)
        png = bytes.fromhex("89504e470d0a1a0a") + os.urandom(64)
        c.upload_media("art", "icon.png", png, type="image/png")
        self.assertEqual(c.download_media("art", "icon.png"), png)
        c.media_delete("art", "icon.png")

    def test_05_streams_reconnect(self):
        c = admin.with_db("sdkpy")
        got, reconnects = [], []
        sub = c.subscribe("w.red-xai.db:*", got.append, reconnect=True, on_reconnect=lambda: reconnects.append(1))
        try:
            c.set("w.red-xai.db:W[ID=1]", {"A": 1})
            wait_for(lambda: len(got) >= 1)
            self.assertEqual(got[0]["data"], {"A": 1})
            host.restart()
            wait_for(lambda: reconnects, 10)
            c.set("w.red-xai.db:W[ID=2]", {"A": 2})
            wait_for(lambda: any(e["path"] == "w.red-xai.db:W[ID=2]" for e in got))
        finally:
            sub.close()
        self.assertTrue(sub.wait_closed(3))
        w = c.stream("bxWatch", query={"q": "{Watch[]} = w:W[A > $min]", "params": json.dumps({"min": 4})})
        try:
            c.set("w.red-xai.db:W[ID=3]", {"A": 5})
            self.assertIsNotNone(w.get(timeout=8))
        finally:
            w.close()

    def test_06_cluster(self):
        self.assertIn("role", admin.cluster_status())
        with self.assertRaises(RedXError):
            admin.promote(confirm=True)

    def test_07_connect(self):
        rq = redx.connect_request()
        import base64
        self.assertEqual(rq["challenge"], base64.urlsafe_b64encode(hashlib.sha256(rq["verifier"].encode()).digest()).rstrip(b"=").decode())
        link = redx.connect_link(provider="gendragoon", state=rq["state"], challenge=rq["challenge"], callback="gendragoon://redx-callback")
        self.assertTrue(link.startswith("redx://connect?v=1&"))
        start = admin.connect_start(body={"v": 1, "provider": "gendragoon", "state": rq["state"], "pkce_challenge": rq["challenge"],
                                          "callback": "gendragoon://redx-callback"})
        ap = admin.connect_approve(body={"request_id": start["request_id"]}, confirm=True)
        cb_url = ap["callback_template"].replace("{state}", rq["state"])
        with self.assertRaises(RedXError) as cm:
            redx.parse_callback(cb_url, "x" * len(rq["state"]))
        self.assertEqual(cm.exception.code, "state_mismatch")
        cb = redx.parse_callback(cb_url, rq["state"])
        with self.assertRaises(RedXError) as cm:
            redx.exchange_connect_code(host.url, code=cb["code"], verifier="A" * 43, state=rq["state"])
        self.assertEqual(cm.exception.code, "pkce_mismatch")
        ex = redx.exchange_connect_code(host.url, code=cb["code"], verifier=rq["verifier"], state=rq["state"], device_label="py test")
        app = RedX(host.url, ex["key"], ex["workspace"]["db"])
        app.set("save.red-xai.db:S[ID=1]", {"L": 2})
        app.connect_revoke()
        with self.assertRaises(RedXError) as cm:
            app.get("save.red-xai.db:S[ID=1]")
        self.assertEqual(cm.exception.status, 401)

    def test_08_backup_and_delete(self):
        self.assertGreater(len(admin.backup()), 100)
        self.assertIsInstance(admin.admin_audit(query={"limit": 5}), dict)
        admin.delete_database(db="sdkpy", confirm=True)
        self.assertNotIn("sdkpy", json.dumps(admin.list_databases()))


if __name__ == "__main__":
    unittest.main()
