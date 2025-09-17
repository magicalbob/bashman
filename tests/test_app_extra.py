# tests/test_app_extra.py
import base64
import asyncio
import importlib
import sys
from types import SimpleNamespace
from datetime import datetime, timezone
from email.utils import format_datetime

import os
import pytest
from starlette.requests import Request
from fastapi import HTTPException


# --- helper to build a Starlette Request without spinning up FastAPI ----
def _request(headers: dict[str, str], method: str = "GET", path: str = "/api/x", body: bytes = b""):
    async def receive():
        return {"type": "http.request", "body": body}
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope, receive)


# --- ensure our import of bashman.server.app never poisons other tests ----
@pytest.fixture
def fresh_app_mod(monkeypatch, tmp_path):
    # Give the module a harmless temp DB path for any constants it reads
    monkeypatch.setenv("BASHMAN_DB_PATH", str(tmp_path / "unit.db"))
    # Make sure we import a fresh copy
    sys.modules.pop("bashman.server.app", None)
    import bashman.server.app as app_mod
    try:
        yield app_mod
    finally:
        # Remove so other tests (which set env first) can import cleanly
        sys.modules.pop("bashman.server.app", None)


# ---------------------------
# Lightweight auth & helper coverage
# ---------------------------

def test_parse_alg_and_canonical_and_skew_and_replay(fresh_app_mod):
    app_mod = fresh_app_mod

    # _parse_alg mapping
    assert app_mod._parse_alg("ed25519") == "ed25519"
    assert app_mod._parse_alg("rsa-pss-sha256") == "rsa"
    assert app_mod._parse_alg("ecdsa-sha256") == "ecdsa"
    assert app_mod._parse_alg("weird") is None

    # _canonical_bytes shape
    msg = app_mod._canonical_bytes("get", "/a?b=1", "Tue, 01 Jan 2030 00:00:00 GMT", "nonce", "00")
    assert msg.startswith(b"GET\n/a?b=1\nTue, 01 Jan 2030")

    # _within_skew: now -> True, ancient -> False
    now_hdr = format_datetime(datetime.now(timezone.utc))
    assert app_mod._within_skew(now_hdr)
    assert not app_mod._within_skew("Mon, 01 Jan 1990 00:00:00 GMT")

    # _replay_ok: first OK, second same nonce blocked, then after prune OK again
    user, nonce = "alice", "xyz"
    app_mod._NONCE_CACHE.clear()
    assert app_mod._replay_ok(user, nonce) is True
    assert app_mod._replay_ok(user, nonce) is False
    # Force stale and try again
    app_mod._NONCE_CACHE[(user, nonce)] = app_mod.time.time() - app_mod.MAX_SKEW_SECONDS - 1
    assert app_mod._replay_ok(user, nonce) is True
    app_mod._NONCE_CACHE.clear()


@pytest.mark.asyncio
async def test_require_auth_enforced_and_health_exempt(fresh_app_mod):
    app_mod = fresh_app_mod
    # Enforce auth but allow /health
    app_mod.REQUIRE_AUTH = True
    # /health is exempt
    req_ok = _request({}, method="GET", path="/health")
    await app_mod.require_auth(req_ok)

    # /api/packages must 401 without headers
    req_bad = _request({}, method="GET", path="/api/packages")
    with pytest.raises(HTTPException) as e:
        await app_mod.require_auth(req_bad)
    assert e.value.status_code == 401
    assert "auth headers" in e.value.detail.lower()


@pytest.mark.asyncio
async def test_verify_signature_missing_crypto_returns_500(fresh_app_mod):
    app_mod = fresh_app_mod
    app_mod.REQUIRE_AUTH = True
    app_mod.load_ssh_public_key = None  # simulate cryptography missing

    hdrs = {
        "X-Bashman-User": "u",
        "X-Bashman-Date": format_datetime(datetime.now(timezone.utc)),
        "X-Bashman-Nonce": "n1",
        "X-Bashman-Alg": "ed25519",
        "Authorization": "Bashman " + base64.b64encode(b"sig").decode(),
    }
    req = _request(hdrs, method="POST", path="/api/packages")

    class DummyDB: ...
    with pytest.raises(HTTPException) as e:
        await app_mod._verify_signature_or_401(req, DummyDB(), b"")
    assert e.value.status_code == 500
    assert "crypto support" in e.value.detail.lower()


@pytest.mark.asyncio
async def test_verify_signature_unknown_user_401(fresh_app_mod, monkeypatch):
    app_mod = fresh_app_mod
    app_mod.REQUIRE_AUTH = True
    # Pretend crypto is present
    app_mod.load_ssh_public_key = lambda b: object()

    async def fake_fetch(db, user):
        return None  # unknown user
    monkeypatch.setattr(app_mod, "_fetch_user_public_key", fake_fetch)

    hdrs = {
        "X-Bashman-User": "someone",
        "X-Bashman-Date": format_datetime(datetime.now(timezone.utc)),
        "X-Bashman-Nonce": "n1",
        "X-Bashman-Alg": "ed25519",
        "Authorization": "Bashman " + base64.b64encode(b"sig").decode(),
    }
    req = _request(hdrs, method="GET", path="/api/packages")
    with pytest.raises(HTTPException) as e:
        await app_mod._verify_signature_or_401(req, object(), b"")
    assert e.value.status_code == 401
    assert "unknown user" in e.value.detail.lower()


@pytest.mark.asyncio
async def test_verify_signature_algorithm_mismatch_401(fresh_app_mod, monkeypatch):
    app_mod = fresh_app_mod

    # Only run if cryptography is available
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_ssh_public_key

    app_mod.REQUIRE_AUTH = True
    app_mod.load_ssh_public_key = load_ssh_public_key

    # Real ed25519 OpenSSH public key
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    pub_text = public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()

    async def fake_fetch(db, user):
        return pub_text
    monkeypatch.setattr(app_mod, "_fetch_user_public_key", fake_fetch)

    # But claim algorithm is RSA -> mismatch
    hdrs = {
        "X-Bashman-User": "eduser",
        "X-Bashman-Date": format_datetime(datetime.now(timezone.utc)),
        "X-Bashman-Nonce": "n1",
        "X-Bashman-Alg": "rsa-pss-sha256",
        "Authorization": "Bashman " + base64.b64encode(b"anything").decode(),
    }
    req = _request(hdrs, method="GET", path="/api/packages")
    with pytest.raises(HTTPException) as e:
        await app_mod._verify_signature_or_401(req, object(), b"")
    assert e.value.status_code == 401
    assert app_mod.ALGORITHM_MISMATCH in e.value.detail


# ---------------------------
# ShellCheck branches
# ---------------------------

def test_run_shellcheck_bytes_best_effort_skips_when_missing(fresh_app_mod, monkeypatch):
    app_mod = fresh_app_mod
    monkeypatch.setattr(app_mod, "_shellcheck_available", lambda: False)
    app_mod.BASHMAN_SHELLCHECK_MODE = "best-effort"
    ok, msg = app_mod._run_shellcheck_bytes(b"#!/bin/sh\necho hi\n")
    assert ok is True and "best-effort" in msg


def test_run_shellcheck_bytes_enforce_fails_when_missing(fresh_app_mod, monkeypatch):
    app_mod = fresh_app_mod
    monkeypatch.setattr(app_mod, "_shellcheck_available", lambda: False)
    app_mod.BASHMAN_SHELLCHECK_MODE = "enforce"
    ok, msg = app_mod._run_shellcheck_bytes(b"#!/bin/sh\necho hi\n")
    assert ok is False and "not available" in msg


def test_run_shellcheck_bytes_invocation_error_both_modes(fresh_app_mod, monkeypatch):
    app_mod = fresh_app_mod
    monkeypatch.setattr(app_mod, "_shellcheck_available", lambda: True)
    # Make subprocess.run blow up
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(app_mod.subprocess, "run", boom)

    app_mod.BASHMAN_SHELLCHECK_MODE = "best-effort"
    ok1, msg1 = app_mod._run_shellcheck_bytes(b"#!/bin/sh\necho hi\n")
    assert ok1 is True and "skipped" in msg1.lower()

    app_mod.BASHMAN_SHELLCHECK_MODE = "enforce"
    ok2, msg2 = app_mod._run_shellcheck_bytes(b"#!/bin/sh\necho hi\n")
    assert ok2 is False and "enforce" in msg2.lower()


# ---------------------------
# Publisher helpers
# ---------------------------

def test_supports_publish_jobs_capability_check(fresh_app_mod):
    app_mod = fresh_app_mod
    good = SimpleNamespace(
        claim_next_publish_job=object(),
        complete_publish_job=object(),
        fail_publish_job=object(),
        update_package=object(),
    )
    bad = SimpleNamespace(claim_next_publish_job=object())
    assert app_mod._supports_publish_jobs(good) is True
    assert app_mod._supports_publish_jobs(bad) is False


@pytest.mark.asyncio
async def test_interruptible_wait_returns_immediately(fresh_app_mod):
    app_mod = fresh_app_mod
    evt = asyncio.Event()
    evt.set()
    await app_mod._interruptible_wait(evt, timeout=0.01)


@pytest.mark.asyncio
async def test_process_publish_job_published(fresh_app_mod, monkeypatch):
    app_mod = fresh_app_mod
    monkeypatch.setattr(app_mod, "_should_run_shellcheck", lambda: False)

    from bashman.server.models import PackageMetadata, PackageStatus
    meta = PackageMetadata(
        name="demo", version="1.0.0", description="x",
        file_size=1, file_hash="h", status=PackageStatus.QUARANTINED,
    )

    class DB:
        def __init__(self):
            self.updates = []
            self.completed = False
        async def get_package_with_content(self, name, version):
            return meta, b"#!/bin/sh\necho ok\n"
        async def update_package(self, name, version, updates):
            self.updates.append(updates); return True
        async def complete_publish_job(self, job_id):
            self.completed = True
        async def fail_publish_job(self, job_id, msg):  # for _safe_fail_job paths
            pass

    db = DB()
    await app_mod._process_publish_job(db, (1, 1, "demo", "1.0.0", 0))
    assert any(u["status"] == meta.status.PUBLISHED for u in db.updates)
    assert db.completed is True


@pytest.mark.asyncio
async def test_process_publish_job_rejected_when_shellcheck_fails(fresh_app_mod, monkeypatch):
    app_mod = fresh_app_mod
    monkeypatch.setattr(app_mod, "_should_run_shellcheck", lambda: True)
    monkeypatch.setattr(app_mod, "_run_shellcheck_bytes", lambda content, name_hint=None: (False, "bad"))

    from bashman.server.models import PackageMetadata, PackageStatus
    meta = PackageMetadata(
        name="demo2", version="1.0.0", description="x",
        file_size=1, file_hash="h", status=PackageStatus.QUARANTINED,
    )

    class DB:
        def __init__(self):
            self.updates = []
            self.failed = []
        async def get_package_with_content(self, name, version):
            return meta, b"#!/bin/sh\necho nope\n"
        async def update_package(self, name, version, updates):
            self.updates.append(updates); return True
        async def complete_publish_job(self, job_id): pass
        async def fail_publish_job(self, job_id, msg):
            self.failed.append((job_id, msg))

    db = DB()
    await app_mod._process_publish_job(db, (2, 1, "demo2", "1.0.0", 0))
    assert any(u["status"] == meta.status.REJECTED for u in db.updates)
