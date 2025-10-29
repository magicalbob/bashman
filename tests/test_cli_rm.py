import pytest
from types import SimpleNamespace
from bashman import cli

class Ctx(SimpleNamespace):
    pass

def test_rm_success(monkeypatch, capsys):
    ctx = Ctx(obj={"server_url": "https://x", "nickname": "me", "private_key_path": None})
    monkeypatch.setattr(cli, "build_signed_headers", lambda *a, **k: {})
    class FakeResp:
        status_code = 200
        def raise_for_status(self): pass
        def json(self): return {"status":"deleted"}
    monkeypatch.setattr(cli.httpx, "delete", lambda url, headers=None: FakeResp())
    cli.rm(ctx, "pkg")
    out = capsys.readouterr().out
    assert "✓ Deleted pkg" in out
