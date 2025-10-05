# tests/test_cli_list.py
import json
from typer.testing import CliRunner
import bashman.cli as cli

runner = CliRunner()

class _Resp:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self._data = data
        self.text = ""
    def raise_for_status(self): pass
    def json(self): return self._data

def test_list_published_names_default(monkeypatch):
    def fake_get(url, headers=None):
        assert "/api/packages?status=published" in url
        return _Resp(200, [{"name":"a"}, {"name":"b"}])
    monkeypatch.setattr(cli.httpx, "get", fake_get)
    r = runner.invoke(cli.app, ["list"])
    assert r.exit_code == 0
    lines = [x for x in r.stdout.strip().splitlines() if x]
    assert lines == ["a", "b"]

def test_list_quarantined_legacy_names(monkeypatch):
    def fake_get(url, headers=None):
        assert url.endswith("/scripts")
        return _Resp(200, ["x", "y"])
    monkeypatch.setattr(cli.httpx, "get", fake_get)
    r = runner.invoke(cli.app, ["list", "--status", "quarantined"])
    assert r.exit_code == 0
    assert "x" in r.stdout and "y" in r.stdout

def test_list_long_switches_to_table(monkeypatch):
    data = [
        {"name":"p1", "version":"1.0.0", "description":"D1", "author":"A1", "license":"MIT"},
        {"name":"p2", "version":"2.0.0", "description":"D2", "author":"A2", "license":"Apache-2.0"},
    ]
    def fake_get(url, headers=None):
        return _Resp(200, data)
    monkeypatch.setattr(cli.httpx, "get", fake_get)
    r = runner.invoke(cli.app, ["list", "--long"])
    assert r.exit_code == 0
    out = r.stdout
    assert "name" in out and "version" in out and "description" in out
    assert "p1" in out and "p2" in out

def test_list_columns_csv(monkeypatch):
    data = [{"name":"n", "version":"1", "author":"me"}]
    def fake_get(url, headers=None):
        return _Resp(200, data)
    monkeypatch.setattr(cli.httpx, "get", fake_get)
    r = runner.invoke(cli.app, ["list", "--columns", "name,version,author", "--format", "csv"])
    assert r.exit_code == 0
    lines = r.stdout.strip().splitlines()
    assert lines[0] == "name,version,author"
    assert lines[1].startswith("n,1,me")

def test_list_columns_json(monkeypatch):
    data = [{"name":"n", "version":"1", "author":"me"}]
    def fake_get(url, headers=None): return _Resp(200, data)
    monkeypatch.setattr(cli.httpx, "get", fake_get)
    r = runner.invoke(cli.app, ["list", "-c", "name,version", "-F", "json"])
    assert r.exit_code == 0
    j = json.loads(r.stdout)
    assert j == [{"name":"n", "version":"1"}]

def test_list_invalid_column(monkeypatch):
    def fake_get(url, headers=None): return _Resp(200, [])
    monkeypatch.setattr(cli.httpx, "get", fake_get)
    r = runner.invoke(cli.app, ["list", "--columns", "nope"])
    assert r.exit_code != 0
    assert "Unknown column(s)" in r.stderr

def test_list_headers_typeerror_fallback(monkeypatch):
    # Simulate httpx.get that doesn't accept 'headers=' keyword
    def get_without_headers(url):  # no headers kwarg on purpose → TypeError on first call
        return _Resp(200, [{"name":"z"}])
    monkeypatch.setattr(cli.httpx, "get", get_without_headers)
    r = runner.invoke(cli.app, ["list"])
    assert r.exit_code == 0
    assert "z" in r.stdout
