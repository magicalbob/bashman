# tests/test_cli.py
import os
import json
import base64
from pathlib import Path
from types import SimpleNamespace

import pytest
import httpx
from typer.testing import CliRunner

from bashman.cli import (
    app as cli_app,
    DEFAULT_SERVER_URL,
    DEFAULT_URL,  # back-compat in case older constant is used
    _supports_headers_param,
    _canonical_string,
    build_signed_headers,
)

runner = CliRunner()


# ---------------------------
# Helpers
# ---------------------------

class DummyResponse:
    def __init__(self, status_code=200, text="OK", json_data=None):
        self.status_code = status_code
        self.text = text
        self._json = json_data if json_data is not None else []

    def raise_for_status(self):
        if self.status_code >= 400:
            req = httpx.Request("GET", "https://example.invalid")
            resp = httpx.Response(self.status_code, request=req, text=self.text)
            raise httpx.HTTPStatusError(f"{self.status_code} error", request=req, response=resp)

    def json(self):
        return self._json


def _monkey_home(monkeypatch, tmp_path):
    # Ensure CLI uses temp ~/.config/bashman
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)


def _cfg_path(tmp_path):
    return tmp_path / ".config" / "bashman" / "config.json"


# ---------------------------
# Unit tests: small helpers
# ---------------------------

def test__supports_headers_param_variants():
    def f1(**kwargs):  # VAR_KEYWORD -> True
        return kwargs

    def f2(url, headers=None):  # explicit headers kw -> True
        return url, headers

    def f3(url, timeout=None):  # no headers, no **kwargs -> False
        return url, timeout

    assert _supports_headers_param(f1) is True
    assert _supports_headers_param(f2) is True
    assert _supports_headers_param(f3) is False


def test__canonical_string_format():
    out = _canonical_string("post", "/foo?bar=1", "Sun, 07 Sep 2025 08:00:00 GMT", "abc", "deadbeef")
    assert out == (
        b"POST\n"
        b"/foo?bar=1\n"
        b"Sun, 07 Sep 2025 08:00:00 GMT\n"
        b"abc\n"
        b"deadbeef"
    )


def test_build_signed_headers_happy_path(tmp_path, monkeypatch):
    # Prepare fake key file (exists check only)
    keyfile = tmp_path / "id_fake"
    keyfile.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n")

    # Deterministic date & nonce
    monkeypatch.setattr("bashman.cli.formatdate", lambda usegmt=True: "Sun, 07 Sep 2025 08:00:00 GMT")
    monkeypatch.setattr("bashman.cli.uuid", SimpleNamespace(uuid4=lambda: "nonce-123"))

    # Provide a fake signer and algorithm
    captured = {}
    def fake_signer(msg: bytes) -> bytes:
        captured["msg"] = msg
        return b"sig-bytes"

    monkeypatch.setattr("bashman.cli._load_private_key_for_signing", lambda _kp: (fake_signer, "ed25519"))

    # Body: empty -> well-known SHA256
    ctx = SimpleNamespace(obj={"nickname": "ian", "private_key_path": str(keyfile), "server_url": DEFAULT_SERVER_URL})
    headers = build_signed_headers(ctx, "POST", f"{DEFAULT_SERVER_URL}/scripts", b"")

    # Check canonical message captured by signer
    expected = (
        b"POST\n/scripts\nSun, 07 Sep 2025 08:00:00 GMT\nnonce-123\n"
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    assert captured["msg"] == expected

    # Check produced headers
    assert headers["X-Bashman-User"] == "ian"
    assert headers["X-Bashman-Date"] == "Sun, 07 Sep 2025 08:00:00 GMT"
    assert headers["X-Bashman-Nonce"] == "nonce-123"
    assert headers["X-Bashman-Alg"] == "ed25519"
    # Authorization must be base64 of b"sig-bytes"
    assert headers["Authorization"] == "Bashman " + base64.b64encode(b"sig-bytes").decode("ascii")


def test_build_signed_headers_missing_config(tmp_path):
    # Missing nickname OR key path -> {}
    ctx = SimpleNamespace(obj={"server_url": DEFAULT_SERVER_URL, "private_key_path": str(tmp_path / "nope")})
    assert build_signed_headers(ctx, "GET", f"{DEFAULT_SERVER_URL}/scripts", b"") == {}

    keyfile = tmp_path / "id_fake"
    keyfile.write_text("x")
    ctx2 = SimpleNamespace(obj={"server_url": DEFAULT_SERVER_URL, "nickname": None, "private_key_path": str(keyfile)})
    assert build_signed_headers(ctx2, "GET", f"{DEFAULT_SERVER_URL}/scripts", b"") == {}


# ---------------------------
# CLI: publish
# ---------------------------

def test_cli_publish_success_with_signing_and_typeerror_fallback(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)
    # Make a valid-looking shell file
    script = tmp_path / "ok.sh"
    script.write_text("#!/bin/bash\necho ok\n")

    # Force signing headers to exist, so first call tries headers=
    monkeypatch.setattr("bashman.cli.build_signed_headers", lambda *a, **k: {"K": "V"})

    # First call with headers -> raise TypeError, retry without headers -> succeed
    def fake_post(url, files=None, headers=None):
        assert url == f"{DEFAULT_URL}/scripts"
        if headers is not None:
            raise TypeError("headers not supported")
        return DummyResponse(200, "OK")

    monkeypatch.setattr("httpx.post", fake_post)

    res = runner.invoke(cli_app, ["publish", str(script)])
    assert res.exit_code == 0
    assert "✓ Quarantined: ok.sh" in res.stdout


def test_cli_publish_http_error_path(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)
    script = tmp_path / "bad.sh"
    script.write_text("#!/bin/bash\necho x\n")

    def fake_post(url, files=None, headers=None):
        req = httpx.Request("POST", url)
        resp = httpx.Response(500, request=req, text="boom")
        raise httpx.HTTPStatusError("oops", request=req, response=resp)

    monkeypatch.setattr("httpx.post", fake_post)

    res = runner.invoke(cli_app, ["publish", str(script)])
    assert res.exit_code != 0
    assert "An HTTP error occurred" in res.stderr


def test_cli_publish_request_error_path(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)
    script = tmp_path / "net.sh"
    script.write_text("#!/bin/bash\necho x\n")

    def fake_post(url, files=None, headers=None):
        raise httpx.RequestError("network", request=httpx.Request("POST", url))

    monkeypatch.setattr("httpx.post", fake_post)

    out = runner.invoke(cli_app, ["publish", str(script)])
    assert out.exit_code != 0
    assert "An error occurred while publishing" in out.stderr


def test_cli_publish_rejects_missing_file(monkeypatch, tmp_path):
    _monkey_home(monkeypatch, tmp_path)
    out = runner.invoke(cli_app, ["publish", str(tmp_path / "nope.sh")])
    assert out.exit_code != 0
    assert "file does not exist" in out.stderr


def test_cli_publish_rejects_bad_shebang(monkeypatch, tmp_path):
    _monkey_home(monkeypatch, tmp_path)
    script = tmp_path / "bad.sh"
    script.write_text("echo no shebang")
    out = runner.invoke(cli_app, ["publish", str(script)])
    assert out.exit_code != 0
    assert "recognized shell shebang" in out.stderr


# ---------------------------
# CLI: list
# ---------------------------

def test_cli_list_success_and_typeerror_fallback(monkeypatch, tmp_path):
    _monkey_home(monkeypatch, tmp_path)
    cfg = _cfg_path(tmp_path)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"server_url": DEFAULT_URL}))

    # Force signing headers to exist, so first call uses headers=
    monkeypatch.setattr("bashman.cli.build_signed_headers", lambda *a, **k: {"K": "V"})

    def fake_get(url, headers=None):
        # Raise TypeError when headers param appears -> exercise fallback path
        if headers is not None:
            raise TypeError("headers not supported")
        return DummyResponse(200, "OK", json_data=["a.sh", "b.sh"])

    monkeypatch.setattr("httpx.get", fake_get)

    res = runner.invoke(cli_app, ["list"])
    assert res.exit_code == 0
    assert "a.sh" in res.stdout and "b.sh" in res.stdout


def test_cli_list_http_and_request_errors(monkeypatch, tmp_path):
    _monkey_home(monkeypatch, tmp_path)
    cfg = _cfg_path(tmp_path)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"server_url": DEFAULT_URL}))

    # HTTPStatusError
    def get_http_err(url, headers=None):
        req = httpx.Request("GET", url)
        resp = httpx.Response(404, request=req, text="missing")
        raise httpx.HTTPStatusError("not found", request=req, response=resp)

    monkeypatch.setattr("httpx.get", get_http_err)
    r1 = runner.invoke(cli_app, ["list"])
    assert r1.exit_code != 0
    assert "An HTTP error occurred" in r1.stderr

    # RequestError
    def get_req_err(url, headers=None):
        raise httpx.RequestError("net", request=httpx.Request("GET", url))

    monkeypatch.setattr("httpx.get", get_req_err)
    r2 = runner.invoke(cli_app, ["list"])
    assert r2.exit_code != 0
    assert "An error occurred while listing scripts" in r2.stderr


# ---------------------------
# CLI: init
# ---------------------------

def test_cli_init_success_201(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)

    key = tmp_path / "id_fake"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n")

    # Bypass heavy crypto; we just want CLI flow
    monkeypatch.setattr("bashman.cli.validate_private_key", lambda p: (True, ""))
    monkeypatch.setattr("bashman.cli.get_public_key", lambda p: "ssh-rsa AAA... user@host")

    def fake_post(url, json=None):
        assert url == f"{DEFAULT_SERVER_URL}/api/users"
        return DummyResponse(201, "Created")

    monkeypatch.setattr("httpx.post", fake_post)

    res = runner.invoke(
        cli_app,
        ["init", "--nickname", "ian", "--key-file", str(key), "--server-url", DEFAULT_SERVER_URL],
    )
    assert res.exit_code == 0
    cfg = json.loads(_cfg_path(tmp_path).read_text())
    assert cfg["nickname"] == "ian"
    assert cfg["server_url"] == DEFAULT_SERVER_URL
    assert Path(cfg["private_key_path"]).exists()
    assert "✓ User registered successfully!" in res.stdout


def test_cli_init_already_initialized(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)
    cfg = _cfg_path(tmp_path)
    cfg.parent.mkdir(parents=True, exist_ok=True)
    cfg.write_text(json.dumps({"server_url": DEFAULT_SERVER_URL, "nickname": "old"}))

    key = tmp_path / "id_fake"
    key.write_text("…")

    r = runner.invoke(
        cli_app,
        ["init", "--nickname", "ian", "--key-file", str(key), "--server-url", DEFAULT_SERVER_URL],
    )
    assert r.exit_code != 0
    assert "already been initialized" in r.stderr


def test_cli_init_409_still_writes_config(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)

    key = tmp_path / "id_fake"
    key.write_text("…")

    monkeypatch.setattr("bashman.cli.validate_private_key", lambda p: (True, ""))
    monkeypatch.setattr("bashman.cli.get_public_key", lambda p: "ssh-rsa AAA...")

    def fake_post(url, json=None):
        return DummyResponse(409, "Conflict")

    monkeypatch.setattr("httpx.post", fake_post)

    r = runner.invoke(
        cli_app,
        ["init", "--nickname", "ian", "--key-file", str(key), "--server-url", DEFAULT_SERVER_URL],
    )
    assert r.exit_code == 0
    assert "already registered; proceeding" in r.stdout.lower()
    cfg = json.loads(_cfg_path(tmp_path).read_text())
    assert cfg["nickname"] == "ian"


def test_cli_init_http_error_and_request_error(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)

    key = tmp_path / "id_fake"
    key.write_text("…")

    monkeypatch.setattr("bashman.cli.validate_private_key", lambda p: (True, ""))
    monkeypatch.setattr("bashman.cli.get_public_key", lambda p: "ssh-ed25519 AAA...")

    # HTTPStatusError
    def post_http_err(url, json=None):
        req = httpx.Request("POST", url)
        resp = httpx.Response(500, request=req, text="oops")
        raise httpx.HTTPStatusError("server err", request=req, response=resp)

    monkeypatch.setattr("httpx.post", post_http_err)
    r1 = runner.invoke(
        cli_app,
        ["init", "--nickname", "ian", "--key-file", str(key), "--server-url", DEFAULT_SERVER_URL],
    )
    assert r1.exit_code != 0
    assert "An HTTP error occurred during registration" in r1.stderr

    # RequestError
    def post_req_err(url, json=None):
        raise httpx.RequestError("net", request=httpx.Request("POST", url))

    monkeypatch.setattr("httpx.post", post_req_err)
    r2 = runner.invoke(
        cli_app,
        ["init", "--nickname", "ian", "--key-file", str(key), "--server-url", DEFAULT_SERVER_URL],
    )
    assert r2.exit_code != 0
    assert "An error occurred while registering" in r2.stderr


def test_cli_init_rejects_invalid_key(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)
    # Force validation failure
    monkeypatch.setattr("bashman.cli.validate_private_key", lambda p: (False, "Key file does not exist"))
    r = runner.invoke(
        cli_app,
        ["init", "--nickname", "ian", "--key-file", str(tmp_path / "nope"), "--server-url", DEFAULT_SERVER_URL],
    )
    assert r.exit_code != 0
    assert "Key file does not exist" in r.stderr


def test_cli_init_unexpected_error_from_get_public_key(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)
    key = tmp_path / "id_fake"
    key.write_text("…")
    monkeypatch.setattr("bashman.cli.validate_private_key", lambda p: (True, ""))
    monkeypatch.setattr("bashman.cli.get_public_key", lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
    # httpx.post should never be reached; ensure a guard anyway
    monkeypatch.setattr("httpx.post", lambda *a, **k: DummyResponse(200, "OK"))

    r = runner.invoke(
        cli_app,
        ["init", "--nickname", "ian", "--key-file", str(key), "--server-url", DEFAULT_SERVER_URL],
    )
    assert r.exit_code != 0
    assert "An unexpected error occurred: boom" in r.stderr


# ---------------------------
# CLI: start
# ---------------------------

def test_cli_start_execs_uvicorn_command_without_replacing_process(monkeypatch, tmp_path):
    _monkey_home(monkeypatch, tmp_path)
    called = {}

    def fake_execvp(prog, args):
        called["prog"] = prog
        called["args"] = args
        raise SystemExit(0)

    monkeypatch.setattr(os, "execvp", fake_execvp)

    r = runner.invoke(cli_app, ["start", "--host", "0.0.0.0", "--port", "9000"])
    assert r.exit_code == 0
    # Prog is the Python interpreter (env-specific); args must include uvicorn target
    assert "uvicorn" in " ".join(called["args"])
