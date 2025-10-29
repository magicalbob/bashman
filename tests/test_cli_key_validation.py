import sys
import pytest
from bashman import cli

def test_validate_private_key_missing():
    ok, msg = cli.validate_private_key("/non/existent/path")
    assert not ok
    assert "does not exist" in msg

def test_validate_private_key_empty(tmp_path):
    p = tmp_path / "k"
    p.write_text("")
    ok, msg = cli.validate_private_key(str(p))
    assert not ok
    assert "empty" in msg
