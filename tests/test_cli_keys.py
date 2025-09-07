import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer

from bashman.cli import (
    validate_private_key,
    get_public_key,
    _load_private_key_for_signing,
    build_signed_headers,
    _supports_headers_param,
    _canonical_string,
    DEFAULT_SERVER_URL,
)

# ---------- validate_private_key: early failures + ImportError ----------

def test_validate_private_key_missing_and_not_file(tmp_path):
    missing = tmp_path / "nope"
    ok, msg = validate_private_key(str(missing))
    assert ok is False and "does not exist" in msg

    d = tmp_path / "dir"
    d.mkdir()
    ok, msg = validate_private_key(str(d))
    assert ok is False and "not a file" in msg


def test_validate_private_key_empty_and_no_header(tmp_path):
    empty = tmp_path / "k1"
    empty.write_text("")
    ok, msg = validate_private_key(str(empty))
    # Accept the exact message the code returns
    assert ok is False and "key file is empty" in msg.lower()

    no_header = tmp_path / "k2"
    no_header.write_text("this is not a key")
    ok, msg = validate_private_key(str(no_header))
    assert ok is False and "missing pem header" in msg.lower()


def test_validate_private_key_malformed_missing_end(tmp_path):
    malformed = tmp_path / "k3"
    malformed.write_text("-----BEGIN PRIVATE KEY-----\nxyz\n")
    ok, msg = validate_private_key(str(malformed))
    # Parsing fails before the END-check branch; assert the actual path:
    assert ok is False and "invalid private key data" in msg.lower()


def test_validate_private_key_importerror_basic_validation(monkeypatch, tmp_path):
    orig_import = __import__

    def fake_import(name, *a, **k):
        if name.startswith("cryptography"):
            raise ImportError("no crypto")
        return orig_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", fake_import)

    key = tmp_path / "k4"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n")
    ok, msg = validate_private_key(str(key))
    assert ok is True and "Warning" in msg


# If cryptography exists, exercise deeper failure and happy paths.
crypto = pytest.importorskip("cryptography", reason="optional in CI")

def test_validate_private_key_invalid_bytes_with_crypto(tmp_path):
    key = tmp_path / "k5"
    key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nnotreally\n-----END OPENSSH PRIVATE KEY-----\n")
    ok, msg = validate_private_key(str(key))
    assert ok is False and "invalid private key data" in msg


# ---------- get_public_key: ImportError + happy path ----------

def test_get_public_key_importerror_exits(monkeypatch, tmp_path, capsys):
    orig_import = __import__

    def fake_import(name, *a, **k):
        if name.startswith("cryptography"):
            raise ImportError("no crypto")
        return orig_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", fake_import)

    k = tmp_path / "id_any"
    k.write_text("irrelevant")
    with pytest.raises(typer.Exit):
        get_public_key(str(k))
    out = capsys.readouterr()
    assert "pip install cryptography" in out.err


def test_get_public_key_from_pem_and_openssh(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    # PEM (PKCS8)
    k1 = ed25519.Ed25519PrivateKey.generate()
    f1 = tmp_path / "id_pem"
    f1.write_bytes(
        k1.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    pub1 = get_public_key(str(f1))
    assert pub1.startswith("ssh-ed25519 ")

    # OpenSSH private format
    k2 = ed25519.Ed25519PrivateKey.generate()
    f2 = tmp_path / "id_ssh"
    f2.write_bytes(
        k2.private_bytes(
            serialization.Encoding.PEM,  # loader will still handle this path
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
    )
    pub2 = get_public_key(str(f2))
    assert pub2.startswith("ssh-ed25519 ")


# ---------- _load_private_key_for_signing: alg variants ----------

def test__load_private_key_for_signing_variants(tmp_path):
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa, ec
    from cryptography.hazmat.primitives import serialization

    # Ed25519
    e = ed25519.Ed25519PrivateKey.generate()
    f_e = tmp_path / "ed25519.pem"
    f_e.write_bytes(
        e.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signer, alg = _load_private_key_for_signing(str(f_e))
    assert alg == "ed25519" and callable(signer)
    assert isinstance(signer(b"msg"), bytes)

    # RSA
    r = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    f_r = tmp_path / "rsa.pem"
    f_r.write_bytes(
        r.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signer, alg = _load_private_key_for_signing(str(f_r))
    assert alg == "rsa-pss-sha256" and callable(signer)
    assert isinstance(signer(b"msg"), bytes)

    # ECDSA P-256
    c = ec.generate_private_key(ec.SECP256R1())
    f_c = tmp_path / "ecdsa.pem"
    f_c.write_bytes(
        c.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    signer, alg = _load_private_key_for_signing(str(f_c))
    assert alg == "ecdsa-sha256" and callable(signer)
    assert isinstance(signer(b"msg"), bytes)


# ---------- build_signed_headers: fail-open branch ----------

def test_build_signed_headers_returns_empty_when_signer_none(monkeypatch, tmp_path):
    key = tmp_path / "id"
    key.write_text("x")
    ctx = SimpleNamespace(obj={"nickname": "ian", "private_key_path": str(key), "server_url": DEFAULT_SERVER_URL})
    monkeypatch.setattr("bashman.cli._load_private_key_for_signing", lambda *_: (None, None))
    assert build_signed_headers(ctx, "POST", f"{DEFAULT_SERVER_URL}/scripts", b"body") == {}
