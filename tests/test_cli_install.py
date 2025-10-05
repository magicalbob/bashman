# tests/test_cli_install.py
from typer.testing import CliRunner
import hashlib
import os
from pathlib import Path
import bashman.cli as cli

runner = CliRunner()

class _Resp:
    def __init__(self, status=200, data=None, content=b""):
        self.status_code = status
        self._data = data
        self.content = content
        self.text = ""
    def raise_for_status(self): pass
    def json(self): return self._data

def test_install_ok(monkeypatch, tmp_path):
    data = b"#!/usr/bin/env bash\necho ok\n"
    file_hash = hashlib.sha256(data).hexdigest()

    # fake config
    monkeypatch.setattr(cli, "load_config", lambda: {
        "server_url": "http://example",
        "install_dir": str(tmp_path),
    })
    # no signing
    monkeypatch.setattr(cli, "build_signed_headers", lambda *a, **k: {})

    def fake_get(url, headers=None):
        if url.startswith("http://example/api/packages/") and "/download" not in url:
            return _Resp(200, {"name":"hello","status":"published","file_hash":file_hash})
        if url.startswith("http://example/api/packages/") and url.endswith("/download"):
            return _Resp(200, content=data)
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(cli.httpx, "get", fake_get)

    r = runner.invoke(cli.app, ["install", "hello"])
    assert r.exit_code == 0
    target = Path(tmp_path) / "hello"
    assert target.exists()
    assert target.read_bytes() == data

def test_install_no_verify(monkeypatch, tmp_path):
    data = b"#!/bin/sh\necho badhash\n"

    monkeypatch.setattr(cli, "load_config", lambda: {
        "server_url": "http://example",
        "install_dir": str(tmp_path),
    })
    monkeypatch.setattr(cli, "build_signed_headers", lambda *a, **k: {})

    def fake_get(url, headers=None):
        if "/download" in url:
            return _Resp(200, content=data)
        return _Resp(200, {"name":"hello","status":"published","file_hash":"0"*64})

    monkeypatch.setattr(cli.httpx, "get", fake_get)
    r = runner.invoke(cli.app, ["install", "hello", "--no-verify"])
    assert r.exit_code == 0
    assert (Path(tmp_path) / "hello").exists()

def test_install_bad_mode(monkeypatch, tmp_path):
    data = b"#!/bin/sh\necho ok\n"
    monkeypatch.setattr(cli, "load_config", lambda: {
        "server_url": "http://example",
        "install_dir": str(tmp_path),
    })
    monkeypatch.setattr(cli, "build_signed_headers", lambda *a, **k: {})

    def fake_get(url, headers=None):
        if "/download" in url:
            return _Resp(200, content=data)
        return _Resp(200, {"name":"hello","status":"published","file_hash":""})

    monkeypatch.setattr(cli.httpx, "get", fake_get)
    r = runner.invoke(cli.app, ["install", "hello", "--mode", "not-octal"])
    assert r.exit_code != 0
    assert "Invalid --mode" in r.stderr
