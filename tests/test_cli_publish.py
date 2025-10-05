# tests/test_cli_publish.py
from typer.testing import CliRunner
import bashman.cli as cli

runner = CliRunner()

class _Resp:
    def __init__(self, status=200, data=None, text=""):
        self.status_code = status
        self._data = data
        self.text = text
    def raise_for_status(self): pass
    def json(self): return self._data or {}

def test_publish_legacy(monkeypatch, tmp_path):
    f = tmp_path / "tool.sh"
    f.write_text("#!/usr/bin/env bash\necho hi\n", encoding="utf-8")

    def fake_post(url, files=None, headers=None):
        assert url.endswith("/scripts")
        assert "file" in files
        return _Resp(200)

    monkeypatch.setattr(cli.httpx, "post", fake_post)
    # disable signing to keep it simple
    monkeypatch.setattr(cli, "build_signed_headers", lambda *a, **k: {})
    r = runner.invoke(cli.app, ["publish", str(f)])
    assert r.exit_code == 0
    assert "Quarantined" in r.stdout

def test_publish_rich_metadata(monkeypatch, tmp_path):
    f = tmp_path / "tool.sh"
    f.write_text("#!/bin/bash\necho hi\n", encoding="utf-8")

    def fake_post(url, data=None, files=None, headers=None):
        assert url.endswith("/api/packages")
        assert data["name"] == "hello"
        assert "file" in files
        return _Resp(200, {"message":"created successfully"})

    monkeypatch.setattr(cli.httpx, "post", fake_post)
    monkeypatch.setattr(cli, "build_signed_headers", lambda *a, **k: {})
    r = runner.invoke(
        cli.app,
        ["publish", str(f), "--name", "hello", "--version", "1.2.3", "-d", "desc", "--author", "me"]
    )
    assert r.exit_code == 0
    assert "created successfully" in r.stdout
