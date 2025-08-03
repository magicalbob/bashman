# tests/test_app.py
import pytest
pytest.importorskip("fastapi")
from fastapi.testclient import TestClient
import os
import shutil

import importlib
app_module = importlib.import_module('bashman.server.app')
app = app_module.app

client = TestClient(app)

@pytest.fixture(autouse=True)
def clean_quarantine(tmp_path, monkeypatch):
    # Use a subdirectory for quarantine to avoid collision with test files
    import importlib
    server_app = importlib.import_module('bashman.server.app')
    quarantine_dir = tmp_path / 'quarantine_dir'
    monkeypatch.setattr(server_app, 'QUARANTINE_DIR', str(quarantine_dir))
    quarantine_dir.mkdir()
    yield
    # Clean up
    import shutil
    shutil.rmtree(str(quarantine_dir), ignore_errors=True)
    shutil.rmtree(str(tmp_path), ignore_errors=True)
    shutil.rmtree(str(tmp_path), ignore_errors=True)


def test_list_empty():
    resp = client.get('/scripts')
    assert resp.status_code == 200
    assert resp.json() == []


def test_upload_and_list(tmp_path):
    script_path = tmp_path / 'hello.sh'
    script_path.write_text('echo Hello')
    with open(script_path, 'rb') as f:
        resp = client.post('/scripts', files={'file': ('hello.sh', f)})
    assert resp.status_code == 200
    assert resp.json() == {'status': 'quarantined', 'filename': 'hello.sh'}
    list_resp = client.get('/scripts')
    assert list_resp.status_code == 200
    assert list_resp.json() == ['hello.sh']


def test_upload_non_sh_file(tmp_path):
    non_script = tmp_path / 'readme.txt'
    non_script.write_text('not a script')
    with open(non_script, 'rb') as f:
        resp = client.post('/scripts', files={'file': ('readme.txt', f)})
    assert resp.status_code == 400
    assert 'Only .sh files are allowed' in resp.json()['detail']

# tests/test_cli.py
import pytest
pytest.importorskip("typer")
pytest.importorskip("httpx")
from typer.testing import CliRunner

from bashman.cli import app, DEFAULT_URL

runner = CliRunner()

class DummyResponse:
    def __init__(self, status_code, text, json_data=None):
        self.status_code = status_code
        self.text = text
        self._json = json_data or []
    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception(f"HTTP {self.status_code}")
    def json(self):
        return self._json


def test_publish_success(tmp_path, monkeypatch):
    script = tmp_path / 'test.sh'
    script.write_text('echo hi')
    def fake_post(url, files):
        assert url == f"{DEFAULT_URL}/scripts"
        return DummyResponse(200, 'OK')
    monkeypatch.setattr('httpx.post', fake_post)
    result = runner.invoke(app, ['publish', str(script)])
    assert result.exit_code == 0
    assert '✓ Quarantined: test.sh' in result.stdout


def test_publish_invalid_path():
    result = runner.invoke(app, ['publish', 'nope.sh'])
    assert result.exit_code != 0
    assert 'must point at an existing .sh file' in result.stderr


def test_list_scripts(monkeypatch):
    def fake_get(url):
        assert url == f"{DEFAULT_URL}/scripts"
        return DummyResponse(200, 'OK', json_data=['a.sh', 'b.sh'])
    monkeypatch.setattr('httpx.get', fake_get)
    result = runner.invoke(app, ['list'])
    assert result.exit_code == 0
    assert 'a.sh' in result.stdout
    assert 'b.sh' in result.stdout
