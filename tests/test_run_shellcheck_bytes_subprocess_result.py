import pytest
import types
from bashman.server import app as server_app

def test_run_shellcheck_bytes_nonzero(monkeypatch):
    monkeypatch.setattr(server_app, "_shellcheck_available", lambda: True)
    class Out: 
        returncode = 1
        stdout = "SOMEOUT"
        stderr = "SOMEERR"
    monkeypatch.setattr(server_app.subprocess, "run", lambda *a, **k: Out())
    ok, msg = server_app._run_shellcheck_bytes(b"#!/bin/sh\necho hi\n")
    assert ok is False
    assert "SOMEOUT" in msg or "SOMEERR" in msg

