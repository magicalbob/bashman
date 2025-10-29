import sys
from base64 import b64decode
from types import SimpleNamespace
import pytest
from bashman import cli

class DummyCtx:
    def __init__(self, obj):
        self.obj = obj

def test_build_signed_headers_missing_cfg():
    ctx = DummyCtx({})
    h = cli.build_signed_headers(ctx, "GET", "https://example/", None)
    assert h == {}

def test_build_signed_headers_with_dummy_signer(monkeypatch, tmp_path):
    key = tmp_path / "key.pem"
    key.write_text("-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----\n")
    ctx = DummyCtx({"nickname": "me", "private_key_path": str(key)})

    def signer(msg: bytes) -> bytes:
        return b"sig-" + msg[:8]
    monkeypatch.setattr(cli, "_load_private_key_for_signing", lambda p: (signer, "ed25519"))
    h = cli.build_signed_headers(ctx, "POST", "https://example/path?q=1", b"data")
    assert "X-Bashman-User" in h and h["X-Bashman-User"] == "me"
    assert h["X-Bashman-Alg"] == "ed25519"
    assert h["Authorization"].startswith("Bashman ")
    assert b"sig-" in b64decode(h["Authorization"].split(" ", 1)[1])
