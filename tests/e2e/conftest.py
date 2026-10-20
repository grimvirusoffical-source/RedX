"""End-to-end fixtures: each test module talks to a real redxd process over HTTP.

The host binary is built from this checkout (make build) and started with an
empty data directory. The first admin key is taken from the console banner the
host prints on first run, exactly as an operator would copy it.
"""
import json
import os
import re
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
_FIXED = "/workspace/redx-e2e-bin/redxd"
REDXD = os.environ.get("REDXD") or (_FIXED if os.path.isfile(_FIXED) else os.path.join(ROOT, "bin", "redxd"))
KEY_RE = re.compile(r"rx_live_[A-Za-z0-9]{43}")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        return json.loads(self.body or b"null")

    @property
    def text(self):
        return self.body.decode("utf-8", "replace")


class Host:
    """A running redxd with its own data directory."""

    def __init__(self, data_dir=None, extra_args=(), env=None):
        self.data_dir = data_dir or tempfile.mkdtemp(prefix="redx-e2e-")
        self.extra_args = list(extra_args)
        self.env = dict(os.environ, **(env or {}))
        self.env.pop("REDX_KEY", None)
        self.port = None
        self.proc = None
        self.admin_key = None
        self.log = b""

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.port

    def start(self, expect_banner=None):
        self.port = free_port()
        args = [REDXD, "run", "--data-dir", self.data_dir, "--listen", "127.0.0.1:%d" % self.port,
                "--bootstrap", "console"] + self.extra_args
        self.logf = open(os.path.join(self.data_dir, "..", os.path.basename(self.data_dir) + ".log"), "ab")
        self.logpath = self.logf.name
        self.proc = subprocess.Popen(args, stdout=self.logf, stderr=subprocess.STDOUT, env=self.env)
        deadline = time.time() + 20
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("redxd exited: " + self.read_log())
            try:
                if self.req("GET", "/healthz").status == 200:
                    break
            except OSError:
                pass
            time.sleep(0.05)
        else:
            raise RuntimeError("redxd did not come up: " + self.read_log())
        m = KEY_RE.findall(self.read_log())
        if m and self.admin_key is None:
            self.admin_key = m[0]
        return self

    def read_log(self):
        with open(self.logpath, "rb") as f:
            return f.read().decode("utf-8", "replace")

    def kill(self, sig=signal.SIGKILL):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(sig)
            self.proc.wait(timeout=30)

    def stop(self):
        self.kill(signal.SIGTERM)

    def restart(self, sig=signal.SIGTERM):
        self.kill(sig)
        return self.start()

    def req(self, method, path, body=None, key=None, headers=None, timeout=30):
        h = dict(headers or {})
        if key:
            h["Authorization"] = "Bearer " + key
        data = body
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        elif isinstance(body, str):
            data = body.encode()
        r = urllib.request.Request(self.url + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(r, timeout=timeout) as resp:
                return Resp(resp.status, dict(resp.headers), resp.read())
        except urllib.error.HTTPError as e:
            return Resp(e.code, dict(e.headers), e.read())

    def make_key(self, scope="read", db="default", prefix="", label="e2e", **extra):
        spec = dict(scope=scope, db=db, label=label, **extra)
        if prefix:
            spec["prefix"] = prefix
        r = self.req("POST", "/v1/keys", spec, key=self.admin_key, headers={"X-RedX-Confirm": "createKey"})
        assert r.status in (200, 201), r.text
        j = r.json()
        return j["key"], j["id"]


def P(path):
    """URL-escape the brackets of an engine path."""
    return urllib.request.quote(path, safe=":=.*,-_")


@pytest.fixture(scope="module")
def host():
    h = Host().start()
    assert h.admin_key, "first-run banner did not print an admin key"
    yield h
    h.stop()


@pytest.fixture
def fresh_host():
    h = Host().start()
    yield h
    h.kill()
