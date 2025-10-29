import pytest
from bashman import cli

def test_parse_set_pairs_valid():
    out = cli._parse_set_pairs(["description=ok", "author=me"])
    assert out["description"] == "ok"
    assert out["author"] == "me"

