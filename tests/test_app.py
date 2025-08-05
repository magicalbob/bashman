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


def test_list_empty():
    resp = client.get('/scripts')
    assert resp.status_code == 200
    assert resp.json() == []


def test_upload_and_list(tmp_path):
    script_path = tmp_path / 'hello.sh'
    script_path.write_text('#!/bin/bash\necho Hello')  # Add proper shebang
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
    assert 'Script must begin with a recognized shell shebang' in resp.json()['detail']


def test_upload_different_shebangs(tmp_path):
    """Test various valid shebang formats"""
    valid_shebangs = [
        '#!/bin/bash',
        '#!/bin/sh',
        '#!/usr/bin/env bash',
        '#!/usr/bin/env zsh',
        '#!/bin/zsh',
        '#!/usr/bin/env fish'
    ]
    
    for i, shebang in enumerate(valid_shebangs):
        script_path = tmp_path / f'test{i}.sh'
        script_path.write_text(f'{shebang}\necho test')
        with open(script_path, 'rb') as f:
            resp = client.post('/scripts', files={'file': (f'test{i}.sh', f)})
        assert resp.status_code == 200, f"Failed for shebang: {shebang}"


def test_upload_invalid_shebang(tmp_path):
    """Test invalid shebang formats"""
    invalid_cases = [
        'echo hello',  # No shebang
        '# This is a comment',  # Not a shebang
        '#!/usr/bin/python',  # Wrong interpreter
        '#!/bin/cat',  # Wrong interpreter
    ]
    
    for i, content in enumerate(invalid_cases):
        script_path = tmp_path / f'invalid{i}.sh'
        script_path.write_text(content)
        with open(script_path, 'rb') as f:
            resp = client.post('/scripts', files={'file': (f'invalid{i}.sh', f)})
        assert resp.status_code == 400, f"Should have failed for: {content}"
        assert 'Script must begin with a recognized shell shebang' in resp.json()['detail']


def test_upload_duplicate_file(tmp_path):
    """Test uploading the same filename twice"""
    script_path = tmp_path / 'duplicate.sh'
    script_path.write_text('#!/bin/bash\necho first')
    
    # First upload should succeed
    with open(script_path, 'rb') as f:
        resp = client.post('/scripts', files={'file': ('duplicate.sh', f)})
    assert resp.status_code == 200
    
    # Second upload should fail
    with open(script_path, 'rb') as f:
        resp = client.post('/scripts', files={'file': ('duplicate.sh', f)})
    assert resp.status_code == 409
    assert 'duplicate.sh already exists' in resp.json()['detail']


def test_upload_empty_file(tmp_path):
    """Test uploading an empty file"""
    script_path = tmp_path / 'empty.sh'
    script_path.write_text('')
    with open(script_path, 'rb') as f:
        resp = client.post('/scripts', files={'file': ('empty.sh', f)})
    assert resp.status_code == 400
    assert 'Script must begin with a recognized shell shebang' in resp.json()['detail']


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
    script.write_text('#!/bin/bash\necho hi')  # Add proper shebang
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
    assert 'Error: file does not exist' in result.stderr


def test_publish_invalid_shebang(tmp_path):
    """Test CLI validation of shebang"""
    script = tmp_path / 'bad.sh'
    script.write_text('echo no shebang')
    result = runner.invoke(app, ['publish', str(script)])
    assert result.exit_code != 0
    assert 'Error: file does not start with a recognized shell shebang' in result.stderr


def test_list_scripts(monkeypatch):
    def fake_get(url):
        assert url == f"{DEFAULT_URL}/scripts"
        return DummyResponse(200, 'OK', json_data=['a.sh', 'b.sh'])
    monkeypatch.setattr('httpx.get', fake_get)
    result = runner.invoke(app, ['list'])
    assert result.exit_code == 0
    assert 'a.sh' in result.stdout
    assert 'b.sh' in result.stdout


def test_publish_server_error(tmp_path, monkeypatch):
    """Test handling of server errors during publish"""
    script = tmp_path / 'test.sh'
    script.write_text('#!/bin/bash\necho hi')
    def fake_post(url, files):
        return DummyResponse(500, 'Internal Server Error')
    monkeypatch.setattr('httpx.post', fake_post)
    result = runner.invoke(app, ['publish', str(script)])
    assert result.exit_code != 0
    assert '✗ 500 — Internal Server Error' in result.stderr
