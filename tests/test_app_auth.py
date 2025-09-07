# tests/test_app_auth.py
import os
import sys
import tempfile
import importlib
import base64
from email.utils import formatdate

import pytest
from starlette.requests import Request
from fastapi.testclient import TestClient

pytest.importorskip("fastapi")

# -------- module loader that preserves DB isolation --------
@pytest.fixture
def appmod(tmp_path, monkeypatch):
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    monkeypatch.setenv("BASHMAN_DB_PATH", db_path)

    # Make sure DB_PATH is read from env on import
    sys.modules.pop("bashman.server.app", None)
    mod = importlib.import_module("bashman.server.app")
    try:
        yield mod
    finally:
        # Let other test modules import a fresh copy with their own env
        sys.modules.pop("bashman.server.app", None)

@pytest.fixture
def client(appmod):
    with TestClient(appmod.app) as c:
        yield c

def _make_request(headers=None, method="POST", path="/x", query=""):
    hdrs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method.upper(),
        "path": path,
        "raw_path": path.encode(),
        "query_string": query.encode(),
        "headers": hdrs,
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 5050),
    }
    return Request(scope)

# -------- small helpers coverage --------
def test__parse_alg_variants(appmod):
    assert appmod._parse_alg("ed25519") == "ed25519"
    assert appmod._parse_alg("rsa-pss-sha256") == "rsa"
    assert appmod._parse_alg("ecdsa-sha256") == "ecdsa"
    assert appmod._parse_alg("nope") is None

def test__canonical_bytes_shape(appmod):
    out = appmod._canonical_bytes("post", "/p?q=1", "Sun, 07 Sep 2025 08:00:00 GMT", "n", "dead")
    assert out == (
        b"POST\n/p?q=1\nSun, 07 Sep 2025 08:00:00 GMT\nn\ndead"
    )

def test__within_skew_valid_and_invalid(appmod):
    assert appmod._within_skew(formatdate(usegmt=True)) is True
    assert appmod._within_skew("garbage") is False

def test__replay_ok_first_true_then_false(appmod):
    appmod._NONCE_CACHE.clear()
    assert appmod._replay_ok("u", "n") is True
    assert appmod._replay_ok("u", "n") is False

def test__extract_signature_headers_variants(appmod):
    r1 = _make_request(headers={"X-Bashman-User":"u"})
    assert appmod._extract_signature_headers(r1) is None

    hdrs = {
        "X-Bashman-User": "u",
        "X-Bashman-Date": formatdate(usegmt=True),
        "X-Bashman-Nonce": "n1",
        "Authorization": "Bashman " + base64.b64encode(b"x").decode(),
    }
    r2 = _make_request(headers=hdrs)
    user, date_str, nonce, alg, auth = appmod._extract_signature_headers(r2)
    assert (user, nonce, alg) == ("u", "n1", "")

def test__prepare_signature_data_basic(appmod):
    hdrs = {
        "X-Bashman-User": "u",
        "X-Bashman-Date": "Sun, 07 Sep 2025 08:00:00 GMT",
        "X-Bashman-Nonce": "n1",
        "X-Bashman-Alg": "ed25519",
        "Authorization": "Bashman " + base64.b64encode(b"sig").decode(),
    }
    req = _make_request(headers=hdrs, method="POST", path="/api/x", query="a=1")
    sd = appmod._prepare_signature_data(
        req, "u", hdrs["X-Bashman-Date"], "n1", "ed25519", hdrs["Authorization"], b"body"
    )
    assert sd.user == "u" and sd.algorithm == "ed25519"
    assert b"POST\n/api/x?a=1\nSun, 07 Sep 2025 08:00:00 GMT\nn1\n" in sd.message

# -------- require_auth branches --------
def test_require_auth_blocks_when_enabled(client, appmod):
    appmod.REQUIRE_AUTH = True
    try:
        r = client.get("/scripts")
        assert r.status_code == 401
        assert "Missing or invalid Bashman auth headers" in r.json()["detail"]
    finally:
        appmod.REQUIRE_AUTH = False

def test_require_auth_allows_with_min_headers(client, appmod):
    appmod.REQUIRE_AUTH = True
    try:
        r = client.get("/scripts", headers={"X-Bashman-User":"u","Authorization":"Bashman abc"})
        assert r.status_code == 200
    finally:
        appmod.REQUIRE_AUTH = False

def test_require_auth_exempts_health_and_users(client, appmod):
    appmod.REQUIRE_AUTH = True
    try:
        assert client.get("/health").status_code == 200
        payload = {"nickname":"alice","public_key":"ssh-ed25519 AAA..."}
        assert client.post("/api/users", json=payload).status_code in (201, 409)
    finally:
        appmod.REQUIRE_AUTH = False

# -------- _verify_signature_or_401 branches (without real crypto) --------
@pytest.mark.asyncio
async def test_verify_signature_missing_headers_returns_when_not_required(appmod):
    req = _make_request(headers={})
    await appmod._verify_signature_or_401(req, database=None, content=b"")

@pytest.mark.asyncio
async def test_verify_signature_500_when_crypto_missing(appmod, monkeypatch):
    appmod.REQUIRE_AUTH = True
    try:
        hdrs = {
            "X-Bashman-User": "u",
            "X-Bashman-Date": formatdate(usegmt=True),
            "X-Bashman-Nonce": "n1",
            "Authorization": "Bashman " + base64.b64encode(b"sig").decode(),
        }
        req = _make_request(headers=hdrs)
        monkeypatch.setattr(appmod, "load_ssh_public_key", None)
        with pytest.raises(appmod.HTTPException) as ei:
            await appmod._verify_signature_or_401(req, database=None, content=b"")
        assert ei.value.status_code == 500
    finally:
        appmod.REQUIRE_AUTH = False

@pytest.mark.asyncio
async def test_verify_signature_401_unknown_user(appmod, monkeypatch):
    appmod.REQUIRE_AUTH = True
    try:
        hdrs = {
            "X-Bashman-User": "u",
            "X-Bashman-Date": formatdate(usegmt=True),
            "X-Bashman-Nonce": "n1",
            "Authorization": "Bashman " + base64.b64encode(b"sig").decode(),
        }
        req = _make_request(headers=hdrs)
        monkeypatch.setattr(appmod, "load_ssh_public_key", object())
        async def _none(*_a, **_k): return None
        monkeypatch.setattr(appmod, "_fetch_user_public_key", _none)
        with pytest.raises(appmod.HTTPException) as ei:
            await appmod._verify_signature_or_401(req, database=None, content=b"")
        assert ei.value.status_code == 401
    finally:
        appmod.REQUIRE_AUTH = False

# -------- algorithm-mismatch guards --------
def test_verify_functions_algorithm_mismatch(appmod):
    crypto = pytest.importorskip("cryptography", reason="optional in CI")
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec

    sd_ed     = appmod.SignatureData("u", "d", "n", "rsa",     b"sig", b"msg")
    sd_rsa    = appmod.SignatureData("u", "d", "n", "ecdsa",   b"sig", b"msg")
    sd_ecdsa  = appmod.SignatureData("u", "d", "n", "ed25519", b"sig", b"msg")

    appmod.REQUIRE_AUTH = True
    try:
        with pytest.raises(appmod.HTTPException):
            appmod._verify_ed25519_signature(ed25519.Ed25519PrivateKey.generate().public_key(), sd_ed)
        with pytest.raises(appmod.HTTPException):
            appmod._verify_rsa_signature(rsa.generate_private_key(65537, 2048).public_key(), sd_rsa)
        with pytest.raises(appmod.HTTPException):
            appmod._verify_ecdsa_signature(ec.generate_private_key(ec.SECP256R1()).public_key(), sd_ecdsa)
        with pytest.raises(appmod.HTTPException):
            appmod._perform_signature_verification(object(), sd_ed)
    finally:
        appmod.REQUIRE_AUTH = False
