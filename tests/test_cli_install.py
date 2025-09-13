# tests/test_cli_install.py
import os
import json
import stat
from pathlib import Path
from types import SimpleNamespace

import httpx
from typer.testing import CliRunner

import pytest

from bashman.cli import app as cli_app, DEFAULT_URL

runner = CliRunner()


class DummyResponse:
    def __init__(self, status_code=200, text="OK", json_data=None, content=b""):
        self.status_code = status_code
        self.text = text
        self._json = json_data if json_data is not None else []
        self.content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            req = httpx.Request("GET", "https://example.invalid")
            resp = httpx.Response(self.status_code, request=req, text=self.text)
            raise httpx.HTTPStatusError(f"{self.status_code} error", request=req, response=resp)

    def json(self):
        return self._json


def _monkey_home(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)


def _write_cfg(tmp_path, install_dir=None):
    cfg_dir = tmp_path / ".config" / "bashman"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg = {"server_url": DEFAULT_URL}
    if install_dir is not None:
        cfg["install_dir"] = str(install_dir)
    (cfg_dir / "config.json").write_text(json.dumps(cfg))


def _sha256(b: bytes) -> str:
    import hashlib

    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def clean_home(tmp_path, monkeypatch):
    _monkey_home(monkeypatch, tmp_path)
    return tmp_path


def test_install_success_with_configured_dir(clean_home, monkeypatch):
    tmp = clean_home
    bin_dir = tmp / "bin"
    _write_cfg(tmp, install_dir=bin_dir)

    content = b"#!/usr/bin/env bash\necho hi\n"
    meta = {
        "name": "foo",
        "version": "0.1.0",
        "status": "published",
        "file_hash": _sha256(content),
    }

    def fake_get(url, headers=None):
        if "/api/packages/foo/download" in url:
            return DummyResponse(200, "OK", json_data=None, content=content)
        if "/api/packages/foo" in url:
            return DummyResponse(200, "OK", json_data=meta)
        return DummyResponse(404, "Nope")

    # No-op signing to keep flow simple
    monkeypatch.setattr("bashman.cli.build_signed_headers", lambda *a, **k: {})
    monkeypatch.setattr("httpx.get", fake_get)

    res = runner.invoke(cli_app, ["install", "foo"])
    assert res.exit_code == 0, res.output
    target = bin_dir / "foo"
    assert target.exists()
    data = target.read_bytes()
    assert data == content
    # default mode is 755 (execute bit set)
    mode = stat.S_IMODE(os.stat(target).st_mode)
    assert mode & stat.S_IXUSR


def test_install_not_published_fails(clean_home, monkeypatch):
    tmp = clean_home
    bin_dir = tmp / "bin"
    _write_cfg(tmp, install_dir=bin_dir)

    meta = {"name": "foo", "version": "0.1.0", "status": "quarantined"}

    monkeypatch.setattr("bashman.cli.build_signed_headers", lambda *a, **k: {})
    monkeypatch.setattr("httpx.get", lambda url, headers=None: DummyResponse(200, "OK", json_data=meta))

    res = runner.invoke(cli_app, ["install", "foo"])
    assert res.exit_code == 4
    assert "not published" in res.stderr.lower()


def test_install_hash_mismatch_fails(clean_home, monkeypatch):
    tmp = clean_home
    bin_dir = tmp / "bin"
    _write_cfg(tmp, install_dir=bin_dir)

    good = b"#!/bin/bash\necho hi\n"
    bad = b"#!/bin/bash\necho bad\n"

    meta = {"name": "foo", "version": "0.1.0", "status": "published", "file_hash": _sha256(good)}

    def fake_get(url, headers=None):
        if "/download" in url:
            return DummyResponse(200, "OK", content=bad)
        return DummyResponse(200, "OK", json_data=meta)

    monkeypatch.setattr("bashman.cli.build_signed_headers", lambda *a, **k: {})
    monkeypatch.setattr("httpx.get", fake_get)

    res = runner.invoke(cli_app, ["install", "foo"])
    assert res.exit_code == 5
    assert "mismatch" in res.stderr.lower()


def test_install_existing_without_force_fails(clean_home, monkeypatch):
    tmp = clean_home
    bin_dir = tmp / "bin"
    _write_cfg(tmp, install_dir=bin_dir)
    (bin_dir).mkdir(parents=True, exist_ok=True)
    target = bin_dir / "foo"
    target.write_text("#!/bin/sh\necho old\n")

    meta = {"name": "foo", "version": "0.1.0", "status": "published", "file_hash": _sha256(b"abc")}
    monkeypatch.setattr("bashman.cli.build_signed_headers", lambda *a, **k: {})
    # Even if download would succeed, we should error out before downloading due to existing file
    monkeypatch.setattr("httpx.get", lambda url, headers=None: DummyResponse(200, "OK", json_data=meta))

    res = runner.invoke(cli_app, ["install", "foo"])
    assert res.exit_code == 3
    assert "already exists" in res.stderr.lower()


def test_install_force_and_custom_mode(clean_home, monkeypatch):
    tmp = clean_home
    bin_dir = tmp / "bin"
    _write_cfg(tmp, install_dir=bin_dir)
    (bin_dir).mkdir(parents=True, exist_ok=True)
    target = bin_dir / "foo"
    target.write_text("#!/bin/sh\necho old\n")

    content = b"#!/bin/sh\necho new\n"
    meta = {"name": "foo", "version": "0.1.0", "status": "published", "file_hash": _sha256(content)}

    def fake_get(url, headers=None):
        if "/download" in url:
            return DummyResponse(200, "OK", content=content)
        return DummyResponse(200, "OK", json_data=meta)

    monkeypatch.setattr("bashman.cli.build_signed_headers", lambda *a, **k: {})
    monkeypatch.setattr("httpx.get", fake_get)

    res = runner.invoke(cli_app, ["install", "foo", "--force", "--mode", "700"])
    assert res.exit_code == 0, res.output
    data = (bin_dir / "foo").read_bytes()
    assert data == content
    mode = stat.S_IMODE(os.stat(bin_dir / "foo").st_mode)
    assert mode == 0o700


#def test_install_invalid_mode_fails(clean_home, monkeypatch):
#    tmp = clean_home
#    bin_dir = tmp / "bin"
#    _write_cfg(tmp, install_dir=bin_dir)
#
#    res = runner.invoke(cli_app, ["install", "foo", "--mode", "not-octal"])
#    assert res.exit_code == 2
#    assert "invalid --mode" in res.stderr.lower()


#def test_install_no_default_dir_then_dest_works(clean_home, monkeypatch):
#    tmp = clean_home
#    # No install_dir in config
#    _write_cfg(tmp, install_dir=None)
#    dest = tmp / "custom"
#
#    content = b"#!/usr/bin/env bash\necho hi\n"
#    meta = {"name": "foo", "version": "0.1.0", "status": "published", "file_hash": _sha256(content)}
#
#    def fake_get(url, headers=None):
#        if "/download" in url:
#            return DummyResponse(200, "OK", content=content)
#        return DummyResponse(200, "OK", json_data=meta)
#
#    monkeypatch.setattr("bashman.cli.build_signed_headers", lambda *a, **k: {})
#    monkeypatch.setattr("httpx.get", fake_get)
#
#    # First, without --dest -> should fail
#    r1 = runner.invoke(cli_app, ["install", "foo"])
#    assert r1.exit_code == 2
#    assert "no install directory configured" in r1.stderr.lower()
#
#    # Provide --dest -> succeeds
#    r2 = runner.invoke(cli_app, ["install", "foo", "--dest", str(dest)])
#    assert r2.exit_code == 0
#    assert (dest / "foo").exists()


def test_install_with_as_rename(clean_home, monkeypatch):
    tmp = clean_home
    bin_dir = tmp / "bin"
    _write_cfg(tmp, install_dir=bin_dir)

    content = b"#!/bin/sh\necho hi\n"
    meta = {"name": "foo", "version": "0.1.0", "status": "published", "file_hash": _sha256(content)}

    def fake_get(url, headers=None):
        if "/download" in url:
            return DummyResponse(200, "OK", content=content)
        return DummyResponse(200, "OK", json_data=meta)

    monkeypatch.setattr("bashman.cli.build_signed_headers", lambda *a, **k: {})
    monkeypatch.setattr("httpx.get", fake_get)

    res = runner.invoke(cli_app, ["install", "foo", "--as", "bar"])
    assert res.exit_code == 0
    assert (bin_dir / "bar").exists()
    assert not (bin_dir / "foo").exists()
