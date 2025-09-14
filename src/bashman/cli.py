import os
import sys
import re
import json
import hashlib
import uuid
import inspect
from base64 import b64encode
from urllib.parse import urlsplit
from email.utils import formatdate
from pathlib import Path
from typing import Iterable, List, Union, Dict, Any

import typer
import httpx

app = typer.Typer()

# ---- Constants (stable for tests) ----
DEFAULT_SERVER_URL = "https://bashman.ellisbs.co.uk"
# Back-compat for tests and older callers
DEFAULT_URL = DEFAULT_SERVER_URL
SERVER_URL_HELP = "URL of the Bashman server"
VALID_STATUSES = ("published", "quarantined")

# Shell validation regex
SHELL_REGEX = re.compile(r'^#!/(?:usr/bin/|bin/)?(?:env\s+)?(sh|bash|zsh|ksh|fish)')

# ---- Config path helpers (computed at call time; safe with Path.home() monkeypatch) ----
def get_config_dir() -> Path:
    return Path.home() / ".config" / "bashman"

def get_config_file() -> Path:
    return get_config_dir() / "config.json"

def load_config() -> dict:
    """Load the configuration file, or return {} if missing/unreadable."""
    cfg_file = get_config_file()
    try:
        with open(cfg_file) as f:
            return json.load(f)
    except Exception:
        return {}

def save_config(cfg: dict) -> None:
    cfg_file = get_config_file()
    cfg_file.parent.mkdir(parents=True, exist_ok=True)
    with open(cfg_file, "w") as f:
        json.dump(cfg, f, indent=2)

def default_install_dir() -> str:
    """Conservative cross-platform default install directory."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return os.path.join(base, "bashman", "bin")
    # POSIX/macOS
    return str(Path.home() / ".local" / "bin")

# ---- Key utilities ----
def validate_private_key(key_path: str) -> tuple[bool, str]:
    """
    Validate that the key file exists and contains a plausible private key.
    Returns (is_valid, msg_or_empty).
    """
    key_file = Path(key_path)

    if not key_file.exists():
        return False, f"Key file does not exist: {key_path}"
    if not key_file.is_file():
        return False, f"Key path is not a file: {key_path}"

    try:
        with open(key_file, "r") as f:
            key_content = f.read().strip()
    except Exception as e:
        return False, f"Cannot read key file: {e}"

    if not key_content:
        return False, "Key file is empty"

    valid_headers = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ]
    if not any(key_content.startswith(h) for h in valid_headers):
        return False, "File does not appear to contain a valid private key (missing PEM header)"

    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
            load_ssh_private_key,
        )
        key_bytes = key_content.encode("utf-8")
        try:
            load_pem_private_key(key_bytes, password=None)
        except Exception:
            try:
                load_ssh_private_key(key_bytes, password=None)
            except Exception:
                return False, "File contains invalid private key data"
    except ImportError:
        return True, "Warning: cryptography library not available, doing basic validation only"

    if "-----BEGIN" in key_content and "-----END" not in key_content:
        return False, "Private key appears malformed (missing END marker)"

    return True, ""

def get_public_key(key_path: str) -> str:
    """Derive and return the OpenSSH public key string from a private key file."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
            load_ssh_private_key,
        )

        with open(key_path, "rb") as key_file:
            key_bytes = key_file.read()

        try:
            private_key = load_pem_private_key(key_bytes, password=None)
        except ValueError:
            private_key = load_ssh_private_key(key_bytes, password=None)

        public_key = private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH,
        ).decode("utf-8")

    except ImportError:
        typer.echo(
            "Error: `cryptography` library is required to derive the public key. "
            "Please install it with `pip install cryptography`.",
            err=True,
        )
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Error: Could not derive public key from file: {e}", err=True)
        raise typer.Exit(1)

# ---- Request signing (client) ----
def _supports_headers_param(func) -> bool:
    """True if a (possibly monkeypatched) function accepts **kwargs or a 'headers' kwarg."""
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return True
    for p in sig.parameters.values():
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            return True
    return "headers" in sig.parameters

def _canonical_string(method: str, path_qs: str, date_str: str, nonce: str, body_sha256_hex: str) -> bytes:
    # METHOD \n PATH?QUERY \n RFC1123_DATE \n NONCE \n SHA256_HEX
    return f"{method.upper()}\n{path_qs}\n{date_str}\n{nonce}\n{body_sha256_hex}".encode("utf-8")

def _load_private_key_for_signing(key_path: str):
    """
    Load a private key and return (signer_fn, alg_label) or (None, None) if unavailable.
    Supports Ed25519, RSA (PSS-SHA256), ECDSA-P256/384 with SHA-256.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.asymmetric import padding as _padding
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec, ed25519 as _ed25519
    except Exception:
        return None, None

    try:
        with open(key_path, "rb") as fh:
            key_bytes = fh.read()
        try:
            pk = load_pem_private_key(key_bytes, password=None)
        except Exception:
            pk = load_ssh_private_key(key_bytes, password=None)
    except Exception:
        return None, None

    # Ed25519
    try:
        if isinstance(getattr(pk, "public_key", lambda: None)(), _ed25519.Ed25519PublicKey):
            def signer(msg: bytes) -> bytes:
                return pk.sign(msg)
            return signer, "ed25519"
    except Exception:
        pass

    # RSA (PSS/SHA-256)
    try:
        if isinstance(pk, _rsa.RSAPrivateKey):
            def signer(msg: bytes) -> bytes:
                return pk.sign(
                    msg,
                    _padding.PSS(mgf=_padding.MGF1(_hashes.SHA256()), salt_length=_padding.PSS.MAX_LENGTH),
                    _hashes.SHA256(),
                )
            return signer, "rsa-pss-sha256"
    except Exception:
        pass

    # ECDSA (P-256/384)
    try:
        if isinstance(pk, _ec.EllipticCurvePrivateKey):
            def signer(msg: bytes) -> bytes:
                return pk.sign(msg, _ec.ECDSA(_hashes.SHA256()))
            return signer, "ecdsa-sha256"
    except Exception:
        pass

    return None, None

def build_signed_headers(ctx: typer.Context, method: str, url: str, body_bytes: bytes | None) -> dict:
    """
    Produce signature headers or return {} if we can't sign (no key, no crypto, etc.).
    """
    try:
        cfg = ctx.obj or {}
        nickname = cfg.get("nickname")
        key_path = cfg.get("private_key_path")
        if not nickname or not key_path or not os.path.exists(key_path):
            return {}

        signer, alg = _load_private_key_for_signing(key_path)
        if signer is None:
            return {}

        parts = urlsplit(url)
        path_qs = parts.path + (f"?{parts.query}" if parts.query else "")
        body = body_bytes or b""
        body_sha256_hex = hashlib.sha256(body).hexdigest()
        date_str = formatdate(usegmt=True)
        nonce = str(uuid.uuid4())
        msg = _canonical_string(method, path_qs, date_str, nonce, body_sha256_hex)
        sig = signer(msg)

        return {
            "X-Bashman-User": nickname,
            "X-Bashman-Date": date_str,
            "X-Bashman-Nonce": nonce,
            "X-Bashman-Alg": alg,
            "Authorization": "Bashman " + b64encode(sig).decode("ascii"),
        }
    except Exception:
        # Fail open: if anything about signing goes wrong, just don't sign.
        return {}

# ---- Typer callback ----
@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    server_url: str = typer.Option(
        None,
        "--server-url",
        help="Override the server URL (default from config)"
    )
):
    """
    Load config and inject defaults for commands.
    Do not force `init`; commands that truly require config should check themselves.
    """
    cfg = load_config()
    resolved_server = (
        server_url
        or os.environ.get("BASHMAN_SERVER_URL")
        or cfg.get("server_url", DEFAULT_SERVER_URL)
    )

    ctx.obj = {
        "server_url": resolved_server,
        "nickname": cfg.get("nickname"),
        "private_key_path": cfg.get("private_key_path"),
        "install_dir": cfg.get("install_dir"),
    }

# ---- Commands ----
@app.command()
def init(
    nickname: str = typer.Option(..., "--nickname", help="User nickname"),
    key_file: str = typer.Option(..., "--key-file", help="Path to private key file"),
    server_url: str = typer.Option(DEFAULT_SERVER_URL, "--server-url", help=SERVER_URL_HELP),
    install_dir: str | None = typer.Option(None, "--install-dir", help="Default directory to install scripts (will be created if missing)"),
):
    """
    Initialize Bashman configuration with server URL, user nickname, private key,
    and a default install dir (defaults to ~/.local/bin on POSIX/macOS).
    """
    config_file = get_config_file()
    config_dir = get_config_dir()
    if config_file.exists():
        typer.echo("Error: Bashman has already been initialized.", err=True)
        raise typer.Exit(1)

    expanded_key_path = os.path.expanduser(key_file)
    is_valid, error_msg = validate_private_key(expanded_key_path)
    if not is_valid:
        typer.echo(f"Error: {error_msg}", err=True)
        raise typer.Exit(1)
    elif error_msg:
        typer.echo(f"{error_msg}", err=True)

    absolute_key_path = os.path.abspath(expanded_key_path)

    # Pick default install dir if not provided (keeps backward compatibility with existing tests/automation)
    chosen_install_dir = install_dir or default_install_dir()
    install_dir_abs = os.path.abspath(os.path.expanduser(chosen_install_dir))
    try:
        Path(install_dir_abs).mkdir(parents=True, exist_ok=True)
        # basic writability check
        if not os.access(install_dir_abs, os.W_OK | os.X_OK):
            typer.echo(f"✗ Install dir not writable: {install_dir_abs}", err=True)
            raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ Could not prepare install dir '{install_dir_abs}': {e}", err=True)
        raise typer.Exit(1)

    # Register the user on the server
    typer.echo("Registering user on the server...")
    try:
        public_key = get_public_key(absolute_key_path)
        payload = {"nickname": nickname, "public_key": public_key}

        resp = httpx.post(f"{server_url}/api/users", json=payload)
        if resp.status_code in (200, 201):
            typer.echo("✓ User registered successfully!")
        elif resp.status_code == 409:
            typer.echo("ℹ️ User already registered; proceeding to write local config.")
        else:
            resp.raise_for_status()

    except httpx.HTTPStatusError as e:
        typer.echo(
            f"✗ An HTTP error occurred during registration: {e.response.status_code} - {e.response.text}",
            err=True,
        )
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"✗ An error occurred while registering: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ An unexpected error occurred: {e}", err=True)
        raise typer.Exit(1)

    # Write config
    config_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "server_url": server_url,
        "nickname": nickname,
        "private_key_path": absolute_key_path,
        "install_dir": install_dir_abs,
    }
    with open(config_file, "w") as f:
        json.dump(config, f, indent=2)

    typer.echo(f"Bashman configuration created at {config_file}")
    typer.echo(f"User: {nickname}")
    typer.echo(f"Key: {absolute_key_path}")
    typer.echo(f"Server: {server_url}")
    typer.echo(f"Install dir: {install_dir_abs}")

@app.command()
def start(host: str = "127.0.0.1", port: int = 8000):
    """Launch the FastAPI server via uvicorn."""
    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "bashman.server.app:app",
        "--host",
        host,
        "--port",
        str(port),
    ]
    os.execvp(cmd[0], cmd)

@app.command()
def publish(ctx: typer.Context, path: str):
    """Upload a shell script to the server (signed if possible)."""
    server = (ctx.obj or {}).get("server_url", DEFAULT_SERVER_URL)

    if not os.path.isfile(path):
        typer.echo("Error: file does not exist", err=True)
        raise typer.Exit(1)

    try:
        # Quick shebang validation from the first kilobyte
        with open(path, "rb") as f:
            snippet = f.read(1024)
            first_line = snippet.splitlines()[0].decode(errors="ignore") if snippet else ""
            if not SHELL_REGEX.match(first_line):
                typer.echo(
                    "Error: file does not start with a recognized shell shebang "
                    "(e.g. #!/bin/bash or #!/usr/bin/env bash)",
                    err=True,
                )
                raise typer.Exit(1)

        # Build signature over the full content
        with open(path, "rb") as fh_for_hash:
            content_bytes = fh_for_hash.read()

        url = f"{server}/scripts"
        headers = build_signed_headers(ctx, "POST", url, content_bytes)

        # Post using a fresh handle so we don't double-read
        with open(path, "rb") as fh_for_upload:
            files = {"file": (os.path.basename(path), fh_for_upload)}
            try:
                if headers:
                    resp = httpx.post(url, files=files, headers=headers)
                else:
                    resp = httpx.post(url, files=files)
            except TypeError:
                # test stubs or older clients may not accept headers=; retry without it
                resp = httpx.post(url, files=files)
            resp.raise_for_status()

        typer.echo(f"✓ Quarantined: {os.path.basename(path)}")
    except httpx.HTTPStatusError as e:
        typer.echo(f"✗ An HTTP error occurred: {e.response.status_code} - {e.response.text}", err=True)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"✗ An error occurred while publishing: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ An unexpected error occurred: {e}", err=True)
        raise typer.Exit(1)

def _validate_status(status: str) -> str:
    s = (status or "published").lower()
    if s not in VALID_STATUSES:
        typer.echo("Error: --status must be 'quarantined' or 'published'", err=True)
        raise typer.Exit(2)
    return s

def _url_for(server: str, status: str) -> str:
    if status == "quarantined":
        # Legacy endpoint used by old flows/tests
        return f"{server}/scripts"
    # Modern API for published packages
    return f"{server}/api/packages?status=published&limit=1000"

def _fetch_json(url: str, headers: Dict[str, str] | None) -> Any:
    """
    Fetch JSON with a compatibility fallback:
    if a monkeypatched/legacy httpx.get doesn't accept headers=, retry without it.
    """
    try:
        resp = httpx.get(url, headers=headers)
    except TypeError:
        # Back-compat for test stubs / older clients that don't accept headers kwarg
        resp = httpx.get(url)
    resp.raise_for_status()
    return resp.json()

def _fetch_bytes(url: str, headers: Dict[str, str] | None) -> bytes:
    try:
        resp = httpx.get(url, headers=headers)
    except TypeError:
        resp = httpx.get(url)
    resp.raise_for_status()
    return getattr(resp, "content", b"") or b""

def _names_from_legacy(data: Any) -> List[str]:
    # legacy shape: list[str]
    if isinstance(data, list):
        return [str(x) for x in data if str(x)]
    return []

def _names_from_published(data: Any) -> List[str]:
    """
    published shape: list[dict] normally, but be tolerant of list[str] (test stubs)
    """
    if not isinstance(data, list):
        return []
    names: List[str] = []
    for item in data:
        if isinstance(item, dict):
            name = item.get("name", "")
        else:
            name = str(item)
        if name:
            names.append(name)
    return names

def _safe_filename(name: str) -> str:
    base = os.path.basename(name)
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return cleaned or "script"

def _ensure_dest_dir(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if not dest.is_dir():
        raise RuntimeError(f"Install destination is not a directory: {dest}")
    if not os.access(dest, os.W_OK | os.X_OK):
        raise RuntimeError(f"Install destination not writable: {dest}")

def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp") if path.suffix else Path(str(path) + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)

def _parse_mode_opt(mode: str | None) -> int:
    """Parse an octal mode string (e.g. '755'); on bad input, print usage error and Exit 2."""
    if not mode:
        return 0o755
    try:
        return int(mode, 8)
    except Exception:
        typer.echo("✗ Invalid --mode (use octal like 755)", err=True)
        raise typer.Exit(2)

def _resolve_install_dir(cfg: dict, dest_opt: str | None) -> Path:
    """
    Resolve the destination directory:
      - If --dest provided, use it.
      - Else require cfg['install_dir']; if missing → usage error Exit 2.
      - Ensure directory exists and is writable/enterable (via _ensure_dest_dir).
    """
    if dest_opt:
        dest_dir = os.path.abspath(os.path.expanduser(dest_opt))
    else:
        configured = cfg.get("install_dir")
        if not configured:
            typer.echo(
                "✗ No install directory configured. Re-run `bashman init --install-dir PATH` or pass --dest.",
                err=True,
            )
            raise typer.Exit(2)
        dest_dir = os.path.abspath(os.path.expanduser(configured))
    dest_path = Path(dest_dir)
    _ensure_dest_dir(dest_path)
    return dest_path

@app.command(name="list")
def _list(
    ctx: typer.Context,
    status: str = typer.Option(
        "published",
        "--status",
        help="Which status to list: 'published' (default) or 'quarantined' (legacy).",
    ),
):
    """
    List packages by status.
    Default lists *published* packages from the modern API; use --status quarantined for legacy uploads.
    """
    server = (ctx.obj or {}).get("server_url", DEFAULT_SERVER_URL)
    status = _validate_status(status)
    url = _url_for(server, status)

    try:
        headers = build_signed_headers(ctx, "GET", url, b"") or None
        data = _fetch_json(url, headers)
        names = (
            _names_from_legacy(data)
            if status == "quarantined"
            else _names_from_published(data)
        )
        for name in names:
            typer.echo(name)

    except httpx.HTTPStatusError as e:
        typer.echo(f"✗ An HTTP error occurred: {e.response.status_code} - {e.response.text}", err=True)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"✗ An error occurred while listing scripts: {e}", err=True)
        raise typer.Exit(1)
    except ValueError as e:
        typer.echo(f"✗ Failed to parse server response: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ An unexpected error occurred: {e}", err=True)
        raise typer.Exit(1)

@app.command()
def install(
    ctx: typer.Context,
    name: str,
    version: str = typer.Option(None, "--version", "-v", help="Specific version to install"),
    dest: str = typer.Option(None, "--dest", help="Override install directory (defaults to init's --install-dir)"),
    as_name: str = typer.Option(None, "--as", help="Install under a different filename"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite if file exists"),
    mode: str = typer.Option(None, "--mode", help="File mode in octal, e.g. 755 (default 755)"),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip SHA256 verification against server metadata"),
):
    """
    Install a published package to your install directory.
    """
    cfg = ctx.obj or {}
    server = cfg.get("server_url", DEFAULT_SERVER_URL)

    # Resolve destination directory (usage error → Exit 2; env/perm issues → Exit 1)
    try:
        dest_path = _resolve_install_dir(cfg, dest)
    except typer.Exit:
        raise
    except Exception as e:
        typer.echo(f"✗ {e}", err=True)
        raise typer.Exit(1)

    # Determine filename
    target_name = as_name or _safe_filename(name)
    target_file = dest_path / target_name
    if target_file.exists() and not force:
        typer.echo(f"✗ Target already exists: {target_file}. Use --force to overwrite.", err=True)
        raise typer.Exit(3)

    # Fetch package metadata (to check status and get hash)
    meta_url = f"{server}/api/packages/{name}"
    if version:
        meta_url += f"?version={version}"
    headers = build_signed_headers(ctx, "GET", meta_url, b"") or None
    try:
        meta = _fetch_json(meta_url, headers)
    except httpx.HTTPStatusError as e:
        typer.echo(f"✗ Failed to fetch metadata: {e.response.status_code} - {e.response.text}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ Failed to fetch metadata: {e}", err=True)
        raise typer.Exit(1)

    status = str(meta.get("status", "")).lower()
    if status != "published":
        typer.echo(f"✗ Package is not published (status={status}). You can only install published packages.", err=True)
        raise typer.Exit(4)

    # Download content
    dl_url = f"{server}/api/packages/{name}/download"
    if version:
        dl_url += f"?version={version}"
    headers = build_signed_headers(ctx, "GET", dl_url, b"") or None
    try:
        data = _fetch_bytes(dl_url, headers)
    except httpx.HTTPStatusError as e:
        typer.echo(f"✗ Failed to download: {e.response.status_code} - {e.response.text}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ Failed to download: {e}", err=True)
        raise typer.Exit(1)
    if not data:
        typer.echo("✗ Empty download from server", err=True)
        raise typer.Exit(1)

    # Verify hash unless skipped
    if not no_verify:
        want = (meta.get("file_hash") or "").lower()
        got = hashlib.sha256(data).hexdigest().lower()
        if want and got != want:
            typer.echo(f"✗ SHA256 mismatch (expected {want}, got {got}). Use --no-verify to bypass.", err=True)
            raise typer.Exit(5)

    # Parse mode (usage error → Exit 2)
    file_mode = _parse_mode_opt(mode)

    # Write atomically and chmod
    try:
        _atomic_write(target_file, data, file_mode)
    except Exception as e:
        typer.echo(f"✗ Failed to write {target_file}: {e}", err=True)
        raise typer.Exit(1)

    typer.echo(f"✓ Installed {name}{(':'+version) if version else ''} → {target_file}")

if __name__ == "__main__":
    app()
