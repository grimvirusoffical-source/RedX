"""RedX client (stdlib only, Python >= 3.9).

    from redx import RedX
    db = RedX("http://127.0.0.1:7777", os.environ["REDX_KEY"])
    db.set("players.red-xai.db:Player[ID=1]", {"Name": "Ann", "Level": 5})
    db.get("players.red-xai.db:Player[ID=1]")   # {'Level': 5, 'Name': 'Ann'}

The API key is kept out of repr(), error messages and pickles.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import queue
import random
import re
import secrets
import threading
import time
import warnings
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Iterator, Optional
from urllib.parse import quote, urlencode, urlsplit

from .boxtext import BoxTextError, from_box
from . import ws as _ws
from .operations import DANGER, OPERATIONS, SEGMENT_PARAMS, Operations

_DB_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")
_KEY_SHAPE = re.compile(r"rx_live_[A-Za-z0-9]+")


class RedXError(Exception):
    """HTTP or client-side failure. status 0 = network/timeout/decoding problem."""

    def __init__(self, status: int, message: str, retry_after: Optional[float] = None, body: Any = None,
                 code: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after
        self.body = body
        # machine-readable: the host's "code", or "confirm_required" for an unconfirmed dangerous call
        self.code = code if code is not None else (body.get("code") if isinstance(body, dict) else None)

    @property
    def unauthorized(self) -> bool:
        return self.status == 401

    @property
    def forbidden(self) -> bool:
        return self.status == 403

    @property
    def not_found(self) -> bool:
        return self.status == 404

    @property
    def rate_limited(self) -> bool:
        return self.status == 429

    def __str__(self) -> str:
        return f"[{self.status}] {self.message}" if self.status else self.message


def _scrub(s: Any) -> str:
    return _KEY_SHAPE.sub("rx_live_[redacted]", str(s))


def escape_path(p: str) -> str:
    """Percent-encode a RedX path for a URL path ([ ] : = are encoded too)."""
    if not isinstance(p, str) or p == "":
        raise TypeError("path must be a non-empty string")
    return quote(p, safe="")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):  # never follow: it could carry the key elsewhere
        return None


# No environment proxies (they would see the key) and no redirects.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())


class Subscription:
    """A live subscription. Iterate it (``for ev in sub``) or pass a handler to subscribe()."""

    def __init__(self, sock: _ws.WebSocket, handler: Optional[Callable[[dict], None]],
                 on_error: Optional[Callable[[BaseException], None]],
                 on_close: Optional[Callable[[int, str], None]]):
        self._ws = sock
        self._handler = handler
        self._on_error = on_error
        self._on_close = on_close
        self._q: "queue.Queue[Any]" = queue.Queue()
        self._done = threading.Event()
        self.close_code: Optional[int] = None
        self.close_reason = ""
        self._t = threading.Thread(target=self._run, name="redx-subscribe", daemon=True)
        self._t.start()

    def _err(self, e: BaseException):
        if self._on_error:
            try:
                self._on_error(e)
            except Exception:
                pass

    def _run(self):
        try:
            while True:
                try:
                    text = self._ws.recv_message()
                except _ws.ProtocolError as e:
                    self._err(e)
                    break
                if text is None:
                    break
                try:
                    ev = json.loads(text)
                except ValueError:
                    self._err(RedXError(0, "bad event JSON"))
                    continue
                data = None
                if ev.get("op") == "set" and isinstance(ev.get("value"), str):
                    try:
                        data = from_box(ev["value"])
                    except BoxTextError:
                        data = None
                ev["data"] = data
                if self._handler:
                    try:
                        self._handler(ev)
                    except Exception as e:  # handler bugs must not kill the stream
                        self._err(e)
                else:
                    self._q.put(ev)
        finally:
            code, reason = self._ws.close_info or (1006, "connection closed")
            self.close_code, self.close_reason = code, reason
            self._ws.shutdown()
            self._done.set()
            self._q.put(None)
            if self._on_close:
                try:
                    self._on_close(code, reason)
                except Exception:
                    pass

    def __iter__(self) -> Iterator[dict]:
        while True:
            ev = self._q.get()
            if ev is None:
                self._q.put(None)
                return
            yield ev

    def get(self, timeout: Optional[float] = None) -> Optional[dict]:
        """Next event, or None on timeout / when the subscription ended."""
        try:
            ev = self._q.get(timeout=timeout)
        except queue.Empty:
            return None
        if ev is None:
            self._q.put(None)
        return ev

    def ping(self):
        self._ws.ping()

    def close(self, timeout: float = 2.0) -> None:
        """Clean close; drops the connection if the server does not answer within ``timeout``."""
        self._ws.send_close(1000, "bye")
        if not self._done.wait(timeout):
            self._ws.shutdown()
            self._done.wait(timeout)

    def wait_closed(self, timeout: Optional[float] = None) -> bool:
        return self._done.wait(timeout)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class RedX(Operations):
    """Client for one host and key. Besides the methods below, every operation of the HTTP API
    (api/redx-api.json) is a method in snake_case (create_database, pack_put, cluster_status, ...),
    and call(op_id, ...) runs any of them by id. Dangerous operations need confirm=True."""

    def __init__(self, url: str, key: str, db: Optional[str] = None, timeout: float = 30.0):
        if not url:
            raise TypeError("url is required")
        if not key or not isinstance(key, str):
            raise TypeError("key is required")
        if db is not None and not _DB_NAME.match(db):
            raise TypeError("invalid db name")
        u = urlsplit(url)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise TypeError("url must be http(s)://host[:port]")
        self.base_url = f"{u.scheme}://{u.netloc}"
        self.db = db
        self.timeout = timeout
        self.__key = key

    def __repr__(self) -> str:
        return f"RedX(base_url={self.base_url!r}, db={self.db!r})"

    def __reduce__(self):
        raise TypeError("RedX clients hold an API key and cannot be pickled")

    def with_db(self, db: str) -> "RedX":
        return RedX(self.base_url, self.__key, db, self.timeout)

    def _prefix(self) -> str:
        return f"/v1/db/{self.db}" if self.db else "/v1"

    def _request(self, method: str, path: str, *, body: Optional[bytes] = None,
                 headers: Optional[Dict[str, str]] = None, query: Optional[Dict[str, Any]] = None,
                 auth: bool = True, raw: bool = False) -> Any:
        url = self.base_url + path
        if query:
            q = {k: ("true" if v is True else "false" if v is False else v) for k, v in query.items() if v is not None}
            if q:
                url += "?" + urlencode(q)
        h = dict(headers or {})
        if auth:
            h["Authorization"] = f"Bearer {self.__key}"
        req = urllib.request.Request(url, data=body, method=method, headers=h)
        try:
            with _OPENER.open(req, timeout=self.timeout) as r:
                data = r.read()
                return data if raw else data.decode("utf-8")
        except urllib.error.HTTPError as e:
            text = e.read(65536).decode("utf-8", "replace")
            msg, parsed = f"HTTP {e.code}", None
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict) and parsed.get("error"):
                    msg = str(parsed["error"])
            except ValueError:
                pass
            ra = e.headers.get("Retry-After") if e.headers else None
            try:
                retry_after = float(ra) if ra is not None else None
            except ValueError:
                retry_after = None
            raise RedXError(e.code, _scrub(msg), retry_after, parsed) from None
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise RedXError(0, _scrub(f"request failed: {reason}")) from None

    def _json(self, method: str, path: str, **kw) -> Any:
        text = self._request(method, path, **kw)
        try:
            return json.loads(text)
        except ValueError:
            raise RedXError(0, "server sent a non-JSON response") from None

    # -- API -----------------------------------------------------------------
    def health(self) -> dict:
        """GET /healthz (no key needed)."""
        return self._json("GET", "/healthz", auth=False)

    def stats(self) -> dict:
        return self._json("GET", "/v1/stats")

    def databases(self) -> dict:
        return self._json("GET", "/v1/dbs")

    def get_box(self, path: str) -> str:
        """Raw Box text of the value at ``path``."""
        return self._request("GET", f"{self._prefix()}/path/{escape_path(path)}",
                             headers={"Accept": "text/x-redx-box"})

    def get(self, path: str) -> Any:
        """The value at ``path`` as plain Python data. Raises RedXError(404) if absent."""
        j = self._json("GET", f"{self._prefix()}/path/{escape_path(path)}")
        if not isinstance(j, dict) or not isinstance(j.get("value"), str):
            raise RedXError(0, "unexpected response shape")
        try:
            return from_box(j["value"])
        except BoxTextError as e:
            raise RedXError(0, f"cannot decode value: {e}") from None

    def get_or(self, path: str, default: Any = None) -> Any:
        try:
            return self.get(path)
        except RedXError as e:
            if e.status == 404:
                return default
            raise

    def set(self, path: str, value: Any, *, ttl: Optional[float] = None, sliding: Optional[bool] = None,
            checkpoint: Optional[float] = None) -> dict:
        """Write a JSON-compatible value (dict -> box, None -> NELL). ttl/checkpoint in seconds."""
        body: Dict[str, Any] = {"value": value}
        if ttl is not None:
            body["ttl_seconds"] = ttl
        if sliding is not None:
            body["sliding"] = bool(sliding)
        if checkpoint is not None:
            body["checkpoint_seconds"] = checkpoint
        return self._json("PUT", f"{self._prefix()}/path/{escape_path(path)}",
                          body=json.dumps(body).encode(), headers={"Content-Type": "application/json"})

    def set_box(self, path: str, box_text: str, *, ttl: Optional[float] = None, sliding: Optional[bool] = None,
                checkpoint: Optional[float] = None) -> dict:
        """Write raw Box text (see docs/box-grammar.md)."""
        return self._json("PUT", f"{self._prefix()}/path/{escape_path(path)}", body=box_text.encode(),
                          headers={"Content-Type": "text/x-redx-box"},
                          query={"ttl": ttl, "sliding": sliding, "checkpoint": checkpoint})

    def delete(self, path: str) -> dict:
        return self._json("DELETE", f"{self._prefix()}/path/{escape_path(path)}")

    def query(self, q: str) -> dict:
        """Run a RedX path query (POST /v1/query), e.g. ``players.red-xai.db:Player[ID=*].Name``.

        This is the host's path-pattern query; use :meth:`bx` for the BoxQL language (both stay). Returns {"count", "results" (Box text), "values" (decoded)}.
        """
        if not isinstance(q, str) or q == "":
            raise TypeError("query must be a non-empty string")
        j = self._json("POST", f"{self._prefix()}/query", body=json.dumps({"q": q}).encode(),
                       headers={"Content-Type": "application/json"})
        results = j.get("results") or []
        values = []
        for r in results:
            try:
                values.append(from_box(r))
            except BoxTextError:
                values.append(r)
        return {"count": j.get("count"), "results": results, "values": values}

    def bx(self, q: str, params: Optional[Dict[str, Any]] = None) -> dict:
        """Run one BoxQL command (POST /v1/bx), e.g. ``{Get[]} = players:Player[Level >= $min] -> Name``.

        Values go in ``params`` (``{"min": 10}``, referenced as ``$min``; never concatenated into the text).
        Returns the host's result object: ``{kind, columns, rows, rows_box, count, affected, paths, access, plan}``;
        a Tx also carries ``results``, one per command. The language is specified in docs/boxql.md.
        """
        if not isinstance(q, str) or q == "":
            raise TypeError("bx command must be a non-empty string")
        if params is not None and not isinstance(params, dict):
            raise TypeError("params must be a dict")
        return self._json("POST", f"{self._prefix()}/bx", body=json.dumps({"q": q, "params": params or {}}).encode(),
                          headers={"Content-Type": "application/json"})

    def watch(self, q: str, handler: Optional[Callable[[dict], None]] = None, *,
              params: Optional[Dict[str, Any]] = None,
              on_error: Optional[Callable[[BaseException], None]] = None,
              on_close: Optional[Callable[[int, str], None]] = None,
              reconnect: bool = False, on_reconnect: Optional[Callable[[], None]] = None) -> Subscription:
        """Watch a BoxQL ``{Watch[]}`` command, e.g. ``{Watch[]} = players:Player[Level > $min]``.

        Events are dicts {path, op, value (the whole changed record as Box text, fields you may not read
        removed; empty for a removal), at, data}. ``{Watch[]} = Topic = "player.*"`` yields pulse events.
        With a handler it is called on the subscription's thread; without one, iterate the returned
        Subscription. Raises RedXError if the host refuses (400/401/403...).
        """
        if not isinstance(q, str) or q == "":
            raise TypeError("watch command must be a non-empty string")
        if params is not None and not isinstance(params, dict):
            raise TypeError("params must be a dict")
        qs = {"q": q}
        if params:
            qs["params"] = json.dumps(params)
        return self._stream("/bx/watch", qs, handler, on_error, on_close, reconnect, on_reconnect)

    def create_key(self, *, scope: str, db: Optional[str] = None, prefix: Optional[str] = None,
                   label: Optional[str] = None, ttl: Optional[str] = None,
                   rate_rps: Optional[float] = None, rate_burst: Optional[int] = None,
                   roles: Optional[list] = None, confirm: bool = False) -> dict:
        """Create an API key (needs an admin key). The returned ``key`` is shown once; store it.

        This is a dangerous operation: pass confirm=True."""
        if confirm is not True:
            raise RedXError(0, "create_key is a dangerous operation and needs confirm=True", code="confirm_required")
        body: Dict[str, Any] = {"db": db or self.db or "default", "scope": scope}
        for k, v in (("prefix", prefix), ("label", label), ("ttl", ttl), ("rate_rps", rate_rps), ("rate_burst", rate_burst)):
            if v is not None:
                body[k] = v
        if roles is not None:
            body["roles"] = roles
        return self.call("createKey", body=body, confirm=True)

    def revoke_key(self, key_id: str, *, confirm: bool = False) -> dict:
        """Revoke a key (dangerous: pass confirm=True)."""
        if confirm is not True:
            raise RedXError(0, "revoke_key is a dangerous operation and needs confirm=True", code="confirm_required")
        return self.call("revokeKey", id=key_id, confirm=True)

    def subscribe(self, path: str, handler: Optional[Callable[[dict], None]] = None, *,
                  on_error: Optional[Callable[[BaseException], None]] = None,
                  on_close: Optional[Callable[[int, str], None]] = None,
                  reconnect: bool = False, on_reconnect: Optional[Callable[[], None]] = None) -> Subscription:
        """Subscribe to changes matching ``path`` (a path pattern such as ``file.red-xai.db:Box[ID=*]``
        or ``file.red-xai.db:*``). Events are dicts {path, op: set|delete|expire, value (Box text), at, data}.

        With a handler it is called on the subscription's thread; without one, iterate the
        returned Subscription. Raises RedXError if the host refuses (401/403/429...).
        """
        return self._stream("/subscribe", {"path": path}, handler, on_error, on_close, reconnect, on_reconnect)

    def _stream(self, sub_path: str, params: Dict[str, str], handler, on_error, on_close,
                reconnect: bool = False, on_reconnect=None, absolute: bool = False):
        if handler is not None and not callable(handler):
            raise TypeError("handler must be callable")
        url = self.base_url + ("" if absolute else self._prefix()) + sub_path + "?" + urlencode(params)
        if reconnect:
            return ReconnectingSubscription(lambda h, e, c: Subscription(self._dial(url), h, e, c),
                                            handler, on_error, on_close, on_reconnect)
        return Subscription(self._dial(url), handler, on_error, on_close)

    def _dial(self, url: str) -> "_ws.WebSocket":
        try:
            sock = _ws.connect(url, {"Authorization": f"Bearer {self.__key}"}, timeout=self.timeout)
        except _ws.HandshakeError as e:
            msg, body = str(e), None
            try:
                body = json.loads(e.body)
                if isinstance(body, dict) and body.get("error"):
                    msg = str(body["error"])
            except ValueError:
                pass
            ra = e.headers.get("retry-after")
            raise RedXError(e.status, _scrub(msg), float(ra) if ra else None, body) from None
        except OSError as e:
            raise RedXError(0, _scrub(f"request failed: {e}")) from None
        return sock

    # -- every operation by id -------------------------------------------------
    def call(self, op_id: str, *, db: Optional[str] = None, body: Any = None, query: Optional[Dict[str, Any]] = None,
             confirm: bool = False, headers: Optional[Dict[str, str]] = None, **params: Any) -> Any:
        """Run any operation of api/redx-api.json: call("pack_stat" | "packStat", pack="p", file="a/b").

        Path parameters are keyword arguments and are escaped here. Returns parsed JSON, str (Box text) or
        bytes (binary). Dangerous operations raise RedXError(code="confirm_required") without sending
        anything unless confirm=True."""
        op = OPERATIONS.get(op_id) or OPERATIONS.get(_camel(op_id))
        if op is None:
            raise TypeError(f"unknown operation {op_id!r}")
        if op["response"] == "websocket":
            raise TypeError(f"{op['id']} is a stream: use stream()")
        _check_danger(op, confirm)
        h = dict(headers or {})
        if confirm is True:
            h["X-RedX-Confirm"] = op["id"]
        data: Optional[bytes] = None
        if op["request"] == "json":
            data = json.dumps({} if body is None else body).encode()
            h["Content-Type"] = "application/json"
        elif op["request"] == "text":
            if not isinstance(body, str):
                raise TypeError(f"{op['id']} takes Box text (str) as body")
            data = body.encode()
            h["Content-Type"] = "text/x-redx-box"
        elif op["request"] == "binary":
            if body is None:
                raise TypeError(f"{op['id']} needs a body (bytes)")
            data = body.encode() if isinstance(body, str) else bytes(body)
            h.setdefault("Content-Type", "application/octet-stream")
            if not any(k.lower() == "x-redx-sha256" for k in h):
                h["X-Redx-SHA256"] = hashlib.sha256(data).hexdigest()
        q = dict(query or {})
        if op["host_confirm"]:
            v = (db or self.db or "default") if op["host_confirm"] == "db" else params.get(op["host_confirm"])
            q.setdefault("confirm", v)
        if op["response"] == "text":
            h["Accept"] = "text/x-redx-box"
        path = self._op_path(op, db, params)
        res = self._request(op["method"], path, body=data, headers=h, query=q or None,
                            auth=op["auth"] != "none", raw=op["response"] == "binary")
        if op["response"] in ("binary", "text"):
            return res
        if res == "":
            return {}
        try:
            return json.loads(res)
        except ValueError:
            raise RedXError(0, "server sent a non-JSON response") from None

    def stream(self, op_id: str, handler: Optional[Callable[[dict], None]] = None, *, db: Optional[str] = None,
               query: Optional[Dict[str, Any]] = None, on_error=None, on_close=None,
               reconnect: bool = False, on_reconnect=None, **params: Any):
        """Open any WebSocket operation (bxWatch, subscribe, rulesSubscribe) by id."""
        op = OPERATIONS.get(op_id) or OPERATIONS.get(_camel(op_id))
        if op is None or op["response"] != "websocket":
            raise TypeError(f"{op_id} is not a stream operation")
        q = {k: ("1" if v is True else "0" if v is False else str(v)) for k, v in (query or {}).items() if v is not None}
        return self._stream(self._op_path(op, db, params), q, handler, on_error, on_close, reconnect, on_reconnect, absolute=True)

    def _op_path(self, op: Dict[str, Any], db: Optional[str], params: Dict[str, Any]) -> str:
        p = op["path"]
        if "{db}" in p:
            d = db or self.db
            if d is not None and not _DB_NAME.match(d):
                raise TypeError("invalid db name")
            if not d and op["shorthand"]:
                p = op["shorthand"]
            else:
                p = p.replace("{db}", d or "default")

        def sub(m: "re.Match[str]") -> str:
            n = m.group(1)
            v = params.get(n)
            if v is None or v == "":
                if n == "folder":
                    return ""
                raise TypeError(f"{op['id']} needs {n}")
            if n in SEGMENT_PARAMS:
                return "/".join(quote(seg, safe="") for seg in str(v).split("/"))
            return quote(str(v), safe="")

        return re.sub(r"\{([a-z]+)\}", sub, p)

    # -- convenience calls (same names in every RedX SDK) ----------------------
    def tx(self, commands: list, params: Optional[Dict[str, Any]] = None) -> dict:
        """Run several BoxQL commands all-or-nothing."""
        if not commands:
            raise TypeError("tx needs a non-empty list of commands")
        return self.bx("{Tx[]} = [\n  " + ",\n  ".join(commands) + "\n]", params)

    def upload_file(self, pack: str, file: str, data: bytes, *, db: Optional[str] = None) -> dict:
        """Store data as file (slash-separated) in pack; the host verifies its SHA-256."""
        return self.call("packPut", db=db, pack=pack, file=file, body=data)

    def download_file(self, pack: str, file: str, *, db: Optional[str] = None, range: Optional[tuple] = None) -> bytes:
        """Read a file of a pack; range=(start, end) inclusive (end may be None)."""
        return self.call("packGet", db=db, pack=pack, file=file, headers=_range(range))

    def upload_media(self, lib: str, name: str, data: bytes, *, db: Optional[str] = None, type: Optional[str] = None) -> dict:
        return self.call("mediaPut", db=db, lib=lib, name=name, body=data, query={"type": type} if type else None)

    def download_media(self, lib: str, name: str, *, db: Optional[str] = None, range: Optional[tuple] = None) -> bytes:
        return self.call("mediaGet", db=db, lib=lib, name=name, headers=_range(range))


class ReconnectingSubscription:
    """A subscription that reconnects after an unexpected close, with exponential backoff (jittered).
    Events that happened while disconnected are not replayed: re-read state in on_reconnect. A refusal
    (400/401/403/404) ends it. Same interface as Subscription."""

    def __init__(self, dial, handler, on_error, on_close, on_reconnect, min_s: float = 0.25, max_s: float = 10.0):
        self._dial, self._handler, self._on_error = dial, handler, on_error
        self._on_close, self._on_reconnect = on_close, on_reconnect
        self._min, self._max = min_s, max_s
        self._q: "queue.Queue[Any]" = queue.Queue()
        self._stop = threading.Event()
        self._done = threading.Event()
        self.close_code: Optional[int] = None
        self.close_reason = ""
        self._cur = self._open()  # the first connect raises to the caller
        self._t = threading.Thread(target=self._run, name="redx-reconnect", daemon=True)
        self._t.start()

    def _deliver(self, ev):
        if self._handler:
            try:
                self._handler(ev)
            except Exception as e:
                self._err(e)
        else:
            self._q.put(ev)

    def _err(self, e):
        if self._on_error:
            try:
                self._on_error(e)
            except Exception:
                pass

    def _open(self) -> Subscription:
        return self._dial(self._deliver, self._on_error, None)

    def _run(self):
        delay = self._min
        while True:
            self._cur.wait_closed()
            if self._stop.is_set():
                self._finish(self._cur.close_code or 1000, self._cur.close_reason or "bye")
                return
            while True:
                if self._stop.wait(delay / 2 + random.random() * delay / 2):
                    self._finish(1000, "bye")
                    return
                delay = min(delay * 2, self._max)
                try:
                    self._cur = self._open()
                except RedXError as e:
                    if e.status in (400, 401, 403, 404):
                        self._err(e)
                        self._finish(0, e.message)
                        return
                    continue
                if self._stop.is_set():
                    self._cur.close()
                    continue
                delay = self._min
                if self._on_reconnect:
                    try:
                        self._on_reconnect()
                    except Exception as e:
                        self._err(e)
                break

    def _finish(self, code, reason):
        self.close_code, self.close_reason = code, reason
        self._done.set()
        self._q.put(None)
        if self._on_close:
            try:
                self._on_close(code, reason)
            except Exception:
                pass

    def __iter__(self) -> Iterator[dict]:
        while True:
            ev = self._q.get()
            if ev is None:
                self._q.put(None)
                return
            yield ev

    def get(self, timeout: Optional[float] = None) -> Optional[dict]:
        try:
            ev = self._q.get(timeout=timeout)
        except queue.Empty:
            return None
        if ev is None:
            self._q.put(None)
        return ev

    def ping(self):
        self._cur.ping()

    def close(self, timeout: float = 2.0) -> None:
        self._stop.set()
        self._cur.close(timeout)
        self._done.wait(timeout)

    def wait_closed(self, timeout: Optional[float] = None) -> bool:
        return self._done.wait(timeout)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _camel(name: str) -> str:
    head, *rest = name.split("_")
    return head + "".join(w[:1].upper() + w[1:] for w in rest)


def _check_danger(op: Dict[str, Any], confirm: bool) -> None:
    if op["danger"] == "dangerous" and confirm is not True:
        raise RedXError(0, f"{op['id']} is a dangerous operation ({op['summary']}) and needs confirm=True",
                        code="confirm_required")


_warned: set = set()


def _unconfirmed(name: str) -> None:
    if name not in _warned:
        _warned.add(name)
        warnings.warn(f"{name}() without confirm=True is deprecated: it is a dangerous operation and will need "
                      "confirm in a later release", DeprecationWarning, stacklevel=3)


def _range(r: Optional[tuple]) -> Optional[Dict[str, str]]:
    if not r:
        return None
    start, end = (r[0], r[1] if len(r) > 1 else None)
    return {"Range": f"bytes={start}-{'' if end is None else end}"}


def danger_of(op_id: str) -> str:
    """The danger of an operation id: "safe", "write", "admin" or "dangerous"."""
    op = OPERATIONS.get(op_id) or OPERATIONS.get(_camel(op_id))
    if op is None:
        raise TypeError(f"unknown operation {op_id!r}")
    return op["danger"]


# -- app side of the connect handshake (no key needed) ---------------------------

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def connect_request() -> Dict[str, str]:
    """A fresh {"state", "verifier", "challenge"}; keep state and verifier secret until the exchange."""
    verifier = _b64url(secrets.token_bytes(32))
    return {"state": _b64url(secrets.token_bytes(24)), "verifier": verifier,
            "challenge": _b64url(hashlib.sha256(verifier.encode()).digest())}


_LINK_FIELDS = ("provider", "app", "workspace", "scope", "prefix", "label", "state", "callback", "host", "pin", "name")


def connect_link(*, provider: str, state: str, challenge: str, console_url: Optional[str] = None, **fields: str) -> str:
    """The link the owner opens: redx://connect?... or <console_url>/#/connect?..."""
    if not provider or not state or not challenge:
        raise TypeError("connect_link needs provider, state and challenge")
    q = [("v", "1")]
    vals = dict(fields, provider=provider, state=state)
    for k in _LINK_FIELDS:
        if vals.get(k):
            q.append((k, str(vals[k])))
    q += [("pkce_challenge", challenge), ("pkce_method", "S256")]
    if console_url:
        u = urlsplit(console_url)
        return f"{u.scheme}://{u.netloc}/#/connect?{urlencode(q)}"
    return "redx://connect?" + urlencode(q)


def parse_callback(url: str, expected_state: str) -> Dict[str, str]:
    """Read the callback URL; raises RedXError(code="state_mismatch") unless its state matches."""
    from urllib.parse import parse_qs
    qs = parse_qs(urlsplit(url).query)
    g = lambda k: (qs.get(k) or [""])[0]  # noqa: E731
    out = {"code": g("code"), "state": g("state"), "host": g("host"), "pin": g("pin")}
    if not out["code"]:
        raise RedXError(0, "callback carries no code", code="bad_callback")
    if not hmac.compare_digest(out["state"].encode(), str(expected_state or "").encode()):
        raise RedXError(0, "callback state does not match", code="state_mismatch")
    return out


def _anon_post(url: str, path: str, body: Dict[str, Any], timeout: float = 30.0) -> Any:
    u = urlsplit(url)
    req = urllib.request.Request(f"{u.scheme}://{u.netloc}{path}", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        parsed = None
        try:
            parsed = json.loads(e.read(65536).decode("utf-8", "replace"))
        except ValueError:
            pass
        msg = parsed.get("error") if isinstance(parsed, dict) and parsed.get("error") else f"HTTP {e.code}"
        raise RedXError(e.code, _scrub(msg), None, parsed) from None
    except (urllib.error.URLError, OSError) as e:
        raise RedXError(0, _scrub(f"request failed: {getattr(e, 'reason', e)}")) from None


def exchange_connect_code(url: str, *, code: str, verifier: str, state: str, device_label: Optional[str] = None,
                          provider_grant: Optional[str] = None, timeout: float = 30.0) -> Dict[str, Any]:
    """Trade an approved connect code plus the PKCE verifier for the app's key (returned once)."""
    body: Dict[str, Any] = {"code": code, "pkce_verifier": verifier, "state": state}
    if device_label:
        body["device_label"] = device_label
    if provider_grant:
        body["provider_grant"] = provider_grant
    return _anon_post(url, "/v1/connect/exchange", body, timeout)


def exchange_pairing_code(url: str, code: str, timeout: float = 30.0) -> Dict[str, Any]:
    """Trade a sign-in (pairing) code for a key."""
    return _anon_post(url, "/v1/pair/exchange", {"code": code}, timeout)
