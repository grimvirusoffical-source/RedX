"""TLS and certificate pinning against a real redxd with tls=auto / files."""
import hashlib
import os
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request

import pytest
from conftest import REDXD, free_port


def _wait_tls(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=1) as sock:
                with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
                    return hashlib.sha256(ssock.getpeercert(binary_form=True)).hexdigest()
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("TLS did not come up on %d" % port)


def _start_tls(extra_args, data=None):
    data = data or tempfile.mkdtemp(prefix="redx-tls-")
    port = free_port()
    logf = open(os.path.join(data, "log"), "wb")
    env = dict(os.environ)
    env.pop("REDX_KEY", None)
    proc = subprocess.Popen(
        [REDXD, "run", "--data-dir", data, "--listen", "127.0.0.1:%d" % port,
         "--bootstrap", "console"] + list(extra_args),
        stdout=logf, stderr=subprocess.STDOUT, env=env,
    )
    try:
        pin = _wait_tls(port)
    except Exception:
        proc.kill()
        raise RuntimeError(open(logf.name, "rb").read().decode("utf-8", "replace"))
    import re
    log = open(logf.name, "rb").read().decode("utf-8", "replace")
    m = re.search(r"rx_live_[A-Za-z0-9]{43}", log)
    h = type("TH", (), {})()
    h.proc, h.port, h.key, h.pin, h.data, h.log = proc, port, (m.group(0) if m else None), pin, data, log
    h.url = "https://127.0.0.1:%d" % port
    return h


def _stop(h):
    h.proc.terminate()
    try:
        h.proc.wait(timeout=10)
    except Exception:
        h.proc.kill()


@pytest.fixture
def tls_host():
    h = _start_tls(["--tls", "auto"])
    yield h
    _stop(h)


def test_tls_auto_serves_https(tls_host):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(tls_host.url + "/healthz")
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        assert resp.status == 200


def test_pin_mismatch_detected(tls_host):
    wrong = "00" * 32
    assert tls_host.pin != wrong
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", tls_host.port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
            got = hashlib.sha256(ssock.getpeercert(binary_form=True)).hexdigest()
    assert got == tls_host.pin
    assert got != wrong


def test_plaintext_http_to_tls_port_fails(tls_host):
    try:
        urllib.request.urlopen("http://127.0.0.1:%d/healthz" % tls_host.port, timeout=3)
        pytest.fail("plaintext HTTP must not succeed on TLS port")
    except Exception:
        pass


def test_wrong_hostname_cert_fails_verify():
    """tls=files with cert for wrong CN: client verify_hostname must fail (BREAK if accepted)."""
    data = tempfile.mkdtemp(prefix="redx-tls-wrong-")
    cert = os.path.join(data, "wrong.crt")
    key = os.path.join(data, "wrong.key")
    subprocess.check_call([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert, "-days", "1",
        "-subj", "/CN=evil.example",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    h = _start_tls(["--tls", "files", "--tls-cert", cert, "--tls-key", key], data=data)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        # Load our self-signed as CA so only hostname check remains the failure mode
        ctx.load_verify_locations(cert)
        try:
            with socket.create_connection(("127.0.0.1", h.port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
                    ssock.getpeercert()
            pytest.fail("hostname mismatch accepted")
        except ssl.SSLCertVerificationError:
            pass
    finally:
        _stop(h)


def test_expired_cert_refused():
    data = tempfile.mkdtemp(prefix="redx-tls-exp-")
    cert = os.path.join(data, "exp.crt")
    key = os.path.join(data, "exp.key")
    # Create already-expired cert (notBefore/notAfter in the past)
    subprocess.check_call([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key, "-out", cert, "-days", "1",
        "-subj", "/CN=127.0.0.1",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Backdate by rewriting with faketime if available; else openssl -startdate via config
    conf = os.path.join(data, "openssl.cnf")
    open(conf, "w").write("""
[req]
distinguished_name=req
[req_dist]
[v3]
""")
    # Generate expired: use openssl ca-style with -not_before/-not_after if supported
    try:
        subprocess.check_call([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert,
            "-subj", "/CN=127.0.0.1",
            "-not_before", "20200101000000Z",
            "-not_after", "20200102000000Z",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        import shutil
        if not shutil.which("faketime"):
            pytest.skip("openssl lacks -not_before and faketime missing — expired-cert NOT RUN")
        subprocess.check_call([
            "faketime", "2020-01-01", "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=127.0.0.1",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    h = _start_tls(["--tls", "files", "--tls-cert", cert, "--tls-key", key], data=data)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cert)
        try:
            with socket.create_connection(("127.0.0.1", h.port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
                    ssock.do_handshake()
            pytest.fail("expired certificate accepted by verifying client")
        except ssl.SSLError:
            pass
    finally:
        _stop(h)


def test_tls_downgrade_plaintext_listen_separate():
    """A plaintext redxd must not speak TLS; a TLS redxd must not speak plaintext."""
    # plaintext host
    data = tempfile.mkdtemp(prefix="redx-plain-")
    port = free_port()
    logf = open(os.path.join(data, "log"), "wb")
    env = dict(os.environ); env.pop("REDX_KEY", None)
    proc = subprocess.Popen(
        [REDXD, "run", "--data-dir", data, "--listen", "127.0.0.1:%d" % port,
         "--bootstrap", "console", "--tls", "off"],
        stdout=logf, stderr=subprocess.STDOUT, env=env,
    )
    try:
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                urllib.request.urlopen("http://127.0.0.1:%d/healthz" % port, timeout=1)
                break
            except Exception:
                time.sleep(0.05)
        else:
            raise RuntimeError("plaintext host down")
        # TLS handshake against plaintext must fail
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                with ctx.wrap_socket(sock, server_hostname="127.0.0.1") as ssock:
                    ssock.do_handshake()
            pytest.fail("TLS handshake succeeded against plaintext listener")
        except ssl.SSLError:
            pass
    finally:
        proc.kill()
