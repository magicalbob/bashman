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
from typing import Iterable, List, Union, Dict, Any, Optional, Tuple

import typer
import httpx

app = typer.Typer()

# ---- Constants ----
DEFAULT_SERVER_URL = "https://bashman.ellisbs.co.uk"
DEFAULT_URL = DEFAULT_SERVER_URL
SERVER_URL_HELP = "URL of the Bashman server"
VALID_STATUSES = ("published", "quarantined")

SHELL_REGEX = re.compile(r'^#!/(?:usr/bin/|bin/)?(?:env\s+)?(sh|bash|zsh|ksh|fish)')

HTTP_ERROR_MSG = "An HTTP error occurred"
FAILED_TO_FETCH_JSON = "Failed to fetch JSON"

# ---- Config paths ----
def get_config_dir() -> Path:
    return Path.home() / ".config" / "bashman"


def get_config_file() -> Path:
    return get_config_dir() / "config.json"


def load_config() -> dict:
    try:
        with open(get_config_file()) as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg: dict) -> None:
    p = get_config_file()
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w") as f:
        json.dump(cfg, f, indent=2)


def default_install_dir() -> str:
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return os.path.join(base, "bashman", "bin")
    return str(Path.home() / ".local" / "bin")


# ---- Key utilities ----
def validate_private_key(key_path: str) -> tuple[bool, str]:
    key_file = Path(key_path)
    if not key_file.exists():
        return False, f"Key file does not exist: {key_path}"
    if not key_file.is_file():
        return False, f"Key path is not a file: {key_path}"
    try:
        content = key_file.read_text().strip()
    except Exception as e:
        return False, f"Cannot read key file: {e}"
    if not content:
        return False, "Key file is empty"

    valid_headers = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    ]
    if not any(content.startswith(h) for h in valid_headers):
        return False, "File does not appear to contain a valid private key (missing PEM header)"

    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key, load_ssh_private_key
        )
        b = content.encode("utf-8")
        try:
            load_pem_private_key(b, password=None)
        except Exception:
            try:
                load_ssh_private_key(b, password=None)
            except Exception:
                return False, "File contains invalid private key data"
    except ImportError:
        return True, "Warning: cryptography library not available, doing basic validation only"

    if "-----BEGIN" in content and "-----END" not in content:
        return False, "Private key appears malformed (missing END marker)"
    return True, ""


def get_public_key(key_path: str) -> str:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key, load_ssh_private_key
        )
        key_bytes = Path(key_path).read_bytes()
        try:
            pk = load_pem_private_key(key_bytes, password=None)
        except ValueError:
            pk = load_ssh_private_key(key_bytes, password=None)
        return pk.public_key().public_bytes(
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
def _canonical_string(method: str, path_qs: str, date_str: str, nonce: str, body_sha256_hex: str) -> bytes:
    return f"{method.upper()}\n{path_qs}\n{date_str}\n{nonce}\n{body_sha256_hex}".encode("utf-8")


def _load_private_key_for_signing(key_path: str):
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_ssh_private_key
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.asymmetric import padding as _padding
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa, ec as _ec, ed25519 as _ed25519
    except Exception:
        return None, None

    try:
        key_bytes = Path(key_path).read_bytes()
        try:
            pk = load_pem_private_key(key_bytes, password=None)
        except Exception:
            pk = load_ssh_private_key(key_bytes, password=None)
    except Exception:
        return None, None

    try:
        if isinstance(getattr(pk, "public_key", lambda: None)(), _ed25519.Ed25519PublicKey):
            def signer(msg: bytes) -> bytes: return pk.sign(msg)
            return signer, "ed25519"
    except Exception:
        pass

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

    try:
        if isinstance(pk, _ec.EllipticCurvePrivateKey):
            def signer(msg: bytes) -> bytes:
                return pk.sign(msg, _ec.ECDSA(_hashes.SHA256()))
            return signer, "ecdsa-sha256"
    except Exception:
        pass

    return None, None


def _supports_headers_param(func) -> bool:
    """
    Back-compat helper expected by tests:
    True if a function accepts **kwargs or a 'headers' kwarg.
    """
    try:
        sig = inspect.signature(func)
    except (TypeError, ValueError):
        return True
    for p in sig.parameters.values():
        if p.kind == inspect.Parameter.VAR_KEYWORD:
            return True
    return "headers" in sig.parameters


def build_signed_headers(ctx: typer.Context, method: str, url: str, body_bytes: bytes | None) -> dict:
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
        body_sha256_hex = hashlib.sha256((body_bytes or b"")).hexdigest()
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
        return {}


# ---- CLI setup ----
@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    server_url: str = typer.Option(
        None,
        "--server-url",
        help="Override the server URL (default from config)"
    )
):
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


# ---- HTTP helpers ----
def _echo_http_error(prefix: str, e: httpx.HTTPStatusError) -> None:
    typer.echo(f"✗ {prefix}: {e.response.status_code} - {e.response.text}", err=True)


def _http_get_json(url: str, headers: Dict[str, str] | None) -> Any:
    try:
        resp = httpx.get(url, headers=headers)
    except TypeError:
        resp = httpx.get(url)
    resp.raise_for_status()
    return resp.json()


def _http_get_bytes(url: str, headers: Dict[str, str] | None) -> bytes:
    try:
        resp = httpx.get(url, headers=headers)
    except TypeError:
        resp = httpx.get(url)
    resp.raise_for_status()
    return getattr(resp, "content", b"") or b""


def _fetch_json_safe(
    ctx: typer.Context,
    url: str,
    *,
    on_http_msg: str = FAILED_TO_FETCH_JSON,
    on_request_action: Optional[str] = None,
    on_generic_msg: str = FAILED_TO_FETCH_JSON,
) -> Dict[str, Any] | List[Any]:
    headers = build_signed_headers(ctx, "GET", url, b"") or None
    try:
        data = _http_get_json(url, headers)
        if not isinstance(data, (list, dict)):
            raise ValueError("unexpected payload")
        return data
    except httpx.HTTPStatusError as e:
        typer.echo(f"✗ {on_http_msg}: {e.response.status_code} - {e.response.text}", err=True)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        if on_request_action:
            typer.echo(f"✗ An error occurred while {on_request_action}: {e}", err=True)
        else:
            typer.echo(f"✗ {on_generic_msg}: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ {on_generic_msg}: {e}", err=True)
        raise typer.Exit(1)


def _fetch_bytes_safe(ctx: typer.Context, url: str) -> bytes:
    headers = build_signed_headers(ctx, "GET", url, b"") or None
    try:
        data = _http_get_bytes(url, headers)
    except httpx.HTTPStatusError as e:
        typer.echo(f"✗ Failed to download: {e.response.status_code} - {e.response.text}", err=True)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"✗ Failed to download: {e}", err=True)
        raise typer.Exit(1)
    if not data:
        typer.echo("✗ Empty download from server", err=True)
        raise typer.Exit(1)
    return data


# ---- Misc helpers ----
def _safe_filename(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(name)) or "script"


def _ensure_dir_writable(dest: Path) -> None:
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
    if not mode:
        return 0o755
    try:
        return int(mode, 8)
    except Exception:
        typer.echo("✗ Invalid --mode (use octal like 755)", err=True)
        raise typer.Exit(2)


def _resolve_install_dir(cfg: dict, dest_opt: str | None) -> Path:
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
    _ensure_dir_writable(dest_path)
    return dest_path


def _determine_target_file(dest_path: Path, target_name: str, force: bool) -> Path:
    target_file = dest_path / target_name
    if target_file.exists() and not force:
        typer.echo(f"✗ Target already exists: {target_file}. Use --force to overwrite.", err=True)
        raise typer.Exit(3)
    return target_file


def _meta_url(server: str, name: str, version: str | None) -> str:
    return f"{server}/api/packages/{name}" + (f"?version={version}" if version else "")


def _download_url(server: str, name: str, version: str | None) -> str:
    return f"{server}/api/packages/{name}/download" + (f"?version={version}" if version else "")


def _verify_published(meta: Dict[str, Any]) -> None:
    status = str(meta.get("status", "")).lower()
    if status != "published":
        typer.echo(f"✗ Package is not published (status={status}). You can only install published packages.", err=True)
        raise typer.Exit(4)


def _verify_hash(meta: Dict[str, Any], data: bytes, skip: bool) -> None:
    if skip:
        return
    want = (meta.get("file_hash") or "").lower()
    got = hashlib.sha256(data).hexdigest().lower()
    if want and got != want:
        typer.echo(f"✗ SHA256 mismatch (expected {want}, got {got}). Use --no-verify to bypass.", err=True)
        raise typer.Exit(5)


def _validate_shebang_or_exit(path: str) -> None:
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


def _wants_modern_upload(
    name: Optional[str],
    version: Optional[str],
    has_arrays: bool,
    has_manifest: bool,
    has_set_pairs: bool,
    desc_given: bool,
    author_given: bool,
) -> bool:
    return any([name, version, has_arrays, has_manifest, has_set_pairs, desc_given, author_given])


def _parse_set_pairs(pairs: List[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in pairs:
        if "=" not in item:
            typer.echo(f"✗ --set must be key=value (got: {item})", err=True)
            raise typer.Exit(2)
        k, v = item.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _normalize_keywords(existing: Any, extra: List[str]) -> List[str]:
    kw = existing or []
    if isinstance(kw, str):
        kw = [x.strip() for x in kw.split(",") if x.strip()]
    return list(kw) + list(extra)


def _normalize_deps(existing: Any, extra: List[str]) -> Dict[str, str]:
    dep_map: Dict[str, str] = {}
    if isinstance(existing, dict):
        dep_map.update(existing)
    elif isinstance(existing, list):
        for entry in existing:
            if isinstance(entry, str) and "=" in entry:
                k, v = entry.split("=", 1)
                dep_map[k.strip()] = v.strip()
    for d in extra:
        if "=" in d:
            k, v = d.split("=", 1)
            dep_map[k.strip()] = v.strip()
        else:
            dep_map[d.strip()] = "*"
    return dep_map


def _normalize_platforms(existing: Any, extra: List[str]) -> List[str]:
    plats = existing or []
    if isinstance(plats, str):
        plats = [x.strip() for x in plats.split(",") if x.strip()]
    return list(plats) + list(extra)


# ---- list rendering helpers ----
def _render_table(rows: List[Dict[str, Any]], columns: List[str]) -> None:
    widths: List[int] = []
    for i, c in enumerate(columns):
        w = len(c)
        for r in rows:
            cell = r.get(c, "")
            s = json.dumps(cell) if isinstance(cell, (dict, list)) else str(cell or "")
            w = max(w, len(s))
        widths.append(w)
    header = "  ".join(c.ljust(widths[i]) for i, c in enumerate(columns))
    typer.echo(header)
    typer.echo("  ".join("-" * widths[i] for i in range(len(columns))))
    for r in rows:
        cells = []
        for i, c in enumerate(columns):
            v = r.get(c, "")
            if isinstance(v, (dict, list)):
                v = json.dumps(v)
            cells.append(str(v or "").ljust(widths[i]))
        typer.echo("  ".join(cells))


def _columns_known() -> set[str]:
    return {
        "name", "version", "description", "author", "homepage", "repository", "license",
        "keywords", "dependencies", "platforms", "shell_version", "file_size", "file_hash",
        "status", "created_at", "updated_at", "download_count"
    }


def _parse_columns_or_exit(columns: Optional[str]) -> List[str]:
    if not columns:
        return []
    cols = [c.strip() for c in columns.split(",") if c.strip()]
    unknown = [c for c in cols if c not in _columns_known()]
    if unknown:
        typer.echo(f"✗ Unknown column(s): {', '.join(unknown)}", err=True)
        raise typer.Exit(2)
    return cols


def _print_delimited(rows: List[Dict[str, Any]], cols: List[str], sep: str) -> None:
    typer.echo(sep.join(cols))
    for r in rows:
        vals = []
        for k in cols:
            v = r.get(k, "")
            if isinstance(v, (dict, list)):
                v = json.dumps(v)
            vals.append(str(v))
        typer.echo(sep.join(vals))


def _names_from_legacy(data: Any) -> List[str]:
    return [str(x) for x in data] if isinstance(data, list) else []


def _names_from_published(data: Any) -> List[str]:
    if not isinstance(data, list):
        return []
    out: List[str] = []
    for item in data:
        if isinstance(item, dict):
            nm = item.get("name", "")
        else:
            nm = str(item)
        if nm:
            out.append(nm)
    return out


def _list_quarantined(ctx: typer.Context, url: str) -> None:
    data = _fetch_json_safe(
        ctx, url,
        on_http_msg=HTTP_ERROR_MSG,
        on_request_action="listing scripts",
        on_generic_msg=FAILED_TO_FETCH_JSON,
    )
    for name in _names_from_legacy(data):
        typer.echo(name)


def _list_published(ctx: typer.Context, url: str, long: bool, columns: Optional[str], fmt: str) -> None:
    data = _fetch_json_safe(
        ctx, url,
        on_http_msg=HTTP_ERROR_MSG,
        on_request_action="listing scripts",
        on_generic_msg=FAILED_TO_FETCH_JSON,
    )
    rows: List[Dict[str, Any]] = [x for x in data if isinstance(x, dict)]
    cols = _parse_columns_or_exit(columns)

    if cols:
        if fmt == "json":
            typer.echo(json.dumps([{k: r.get(k) for k in cols} for r in rows], indent=2))
            return
        if fmt == "csv":
            _print_delimited(rows, cols, ",")
            return
        if fmt == "tsv":
            _print_delimited(rows, cols, "\t")
            return
        _render_table(rows, cols)
        return

    if long:
        _render_table(rows, ["name", "version", "description", "author", "license"])
        return

    for name in _names_from_published(data):
        typer.echo(name)


# ---- publish helpers ----
def _legacy_publish(ctx: typer.Context, server: str, path: str, content_bytes: bytes) -> None:
    url = f"{server}/scripts"
    headers = build_signed_headers(ctx, "POST", url, content_bytes)
    try:
        with open(path, "rb") as fh:
            files = {"file": (os.path.basename(path), fh)}
            try:
                resp = httpx.post(url, files=files, headers=headers or None)
            except TypeError:
                resp = httpx.post(url, files=files)
        resp.raise_for_status()
        typer.echo(f"✓ Quarantined: {os.path.basename(path)}")
    except httpx.HTTPStatusError as e:
        _echo_http_error(HTTP_ERROR_MSG, e)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"✗ An error occurred while publishing: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ An unexpected error occurred: {e}", err=True)
        raise typer.Exit(1)


def _modern_publish(
    ctx: typer.Context,
    server: str,
    path: str,
    content_bytes: bytes,
    *,
    name: Optional[str],
    version: Optional[str],
    manifest: Optional[str],
    set_pairs: Dict[str, str],
    keywords: List[str],
    deps: List[str],
    platforms: List[str],
) -> None:
    meta: Dict[str, Any] = {}

    if manifest:
        try:
            with open(manifest) as mf:
                m = json.load(mf)
                if not isinstance(m, dict):
                    raise ValueError("Manifest must be a JSON object")
                meta.update(m)
        except Exception as e:
            typer.echo(f"✗ Failed to read manifest: {e}", err=True)
            raise typer.Exit(2)

    meta.setdefault("name", name or os.path.basename(path))
    meta.setdefault("version", version or "0.1.0")

    for k in ("description", "author", "homepage", "repository", "license", "shell_version"):
        if k in set_pairs:
            meta[k] = set_pairs[k]

    kw = _normalize_keywords(meta.get("keywords", []), keywords)
    dep_map = _normalize_deps(meta.get("dependencies", {}), deps)
    plats = _normalize_platforms(meta.get("platforms", []), platforms)

    data = {
        "name": str(meta["name"]),
        "version": str(meta["version"]),
        "description": str(meta.get("description") or f"Uploaded script: {os.path.basename(path)}"),
        "author": meta.get("author"),
        "homepage": meta.get("homepage"),
        "repository": meta.get("repository"),
        "license": meta.get("license"),
        "keywords": json.dumps(kw),
        "dependencies": json.dumps(dep_map),
        "platforms": json.dumps(plats),
        "shell_version": meta.get("shell_version"),
    }

    url = f"{server}/api/packages"
    headers = build_signed_headers(ctx, "POST", url, content_bytes)
    try:
        with open(path, "rb") as fh:
            files = {"file": (os.path.basename(path), fh)}
            resp = httpx.post(url, data=data, files=files, headers=headers or None)
        resp.raise_for_status()
        msg = resp.json().get("message", "created/updated")
        typer.echo(f"✓ {msg}")
    except httpx.HTTPStatusError as e:
        _echo_http_error(HTTP_ERROR_MSG, e)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"✗ An error occurred while publishing: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ An unexpected error occurred: {e}", err=True)
        raise typer.Exit(1)


# ---- Commands ----
@app.command()
def init(
    nickname: str = typer.Option(..., "--nickname", help="User nickname"),
    key_file: str = typer.Option(..., "--key-file", help="Path to private key file"),
    server_url: str = typer.Option(DEFAULT_SERVER_URL, "--server-url", help=SERVER_URL_HELP),
    install_dir: str | None = typer.Option(None, "--install-dir", help="Default directory to install scripts (created if missing)"),
):
    """
    Initialize Bashman configuration and register your public key on the server.
    """
    config_file = get_config_file()
    if config_file.exists():
        typer.echo("Error: Bashman has already been initialized.", err=True)
        raise typer.Exit(1)

    expanded_key_path = os.path.expanduser(key_file)
    is_valid, msg = validate_private_key(expanded_key_path)
    if not is_valid:
        typer.echo(f"Error: {msg}", err=True)
        raise typer.Exit(1)
    elif msg:
        typer.echo(msg, err=True)

    absolute_key_path = os.path.abspath(expanded_key_path)
    chosen_install_dir = install_dir or default_install_dir()
    install_dir_abs = os.path.abspath(os.path.expanduser(chosen_install_dir))
    try:
        Path(install_dir_abs).mkdir(parents=True, exist_ok=True)
        if not os.access(install_dir_abs, os.W_OK | os.X_OK):
            typer.echo(f"✗ Install dir not writable: {install_dir_abs}", err=True)
            raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ Could not prepare install dir '{install_dir_abs}': {e}", err=True)
        raise typer.Exit(1)

    # Register user
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
        _echo_http_error("An HTTP error occurred during registration", e)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"✗ An error occurred while registering: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ An unexpected error occurred: {e}", err=True)
        raise typer.Exit(1)

    save_config({
        "server_url": server_url,
        "nickname": nickname,
        "private_key_path": absolute_key_path,
        "install_dir": install_dir_abs,
    })
    typer.echo(f"Bashman configuration created at {config_file}")
    typer.echo(f"User: {nickname}")
    typer.echo(f"Key: {absolute_key_path}")
    typer.echo(f"Server: {server_url}")
    typer.echo(f"Install dir: {install_dir_abs}")


@app.command()
def start(host: str = "127.0.0.1", port: int = 8000):
    """Launch the FastAPI server via uvicorn."""
    cmd = [sys.executable, "-m", "uvicorn", "bashman.server.app:app", "--host", host, "--port", str(port)]
    os.execvp(cmd[0], cmd)


@app.command()
def publish(
    ctx: typer.Context,
    path: str,
    name: Optional[str] = typer.Option(None, "--name", help="Package name (default: filename)"),
    version: Optional[str] = typer.Option(None, "--version", "-v", help="Version (e.g. 1.2.3; default: 0.1.0 for legacy)"),
    manifest: Optional[str] = typer.Option(None, "--manifest", help="Path to JSON manifest with fields"),
    keyword: List[str] = typer.Option([], "--keyword", "-k", help="Add a keyword (repeatable)"),
    dep: List[str] = typer.Option([], "--dep", help="Dependency (repeatable) as name=version"),
    platform: List[str] = typer.Option([], "--platform", help="Target platform (repeatable)"),
    set: List[str] = typer.Option([], "--set", "-s", help="Override simple metadata as key=value (description,author,homepage,repository,license,shell_version)"),
    # Back-compat shorthands for tests:
    description: Optional[str] = typer.Option(None, "--description", "-d", help="Description (alias for --set description=...)"),
    author: Optional[str] = typer.Option(None, "--author", help="Author (alias for --set author=...)"),
):
    """
    Upload a shell script to the server (signed if possible).

    If any metadata flags/arrays, `--set`, or `--manifest` are provided, use /api/packages.
    Otherwise, fall back to legacy /scripts for maximum compatibility.
    """
    server = (ctx.obj or {}).get("server_url", DEFAULT_SERVER_URL)
    if not os.path.isfile(path):
        typer.echo("Error: file does not exist", err=True)
        raise typer.Exit(1)

    _validate_shebang_or_exit(path)

    with open(path, "rb") as fh:
        content_bytes = fh.read()

    wants_modern = _wants_modern_upload(
        name, version, has_arrays=bool(keyword or dep or platform),
        has_manifest=bool(manifest), has_set_pairs=bool(set),
        desc_given=description is not None, author_given=author is not None,
    )
    if not wants_modern:
        _legacy_publish(ctx, server, path, content_bytes)
        return

    set_pairs = _parse_set_pairs(set)
    if description is not None:
        set_pairs.setdefault("description", description)
    if author is not None:
        set_pairs.setdefault("author", author)

    _modern_publish(
        ctx, server, path, content_bytes,
        name=name, version=version, manifest=manifest,
        set_pairs=set_pairs, keywords=keyword, deps=dep, platforms=platform
    )


# ---- list ----
def _validate_status(status: str) -> str:
    s = (status or "published").lower()
    if s not in VALID_STATUSES:
        typer.echo("Error: --status must be 'quarantined' or 'published'", err=True)
        raise typer.Exit(2)
    return s


def _url_for(server: str, status: str) -> str:
    if status == "quarantined":
        return f"{server}/scripts"
    return f"{server}/api/packages?status=published&limit=1000"


@app.command(name="list")
def list_cmd(
    ctx: typer.Context,
    status: str = typer.Option(
        "published", "--status",
        help="Which status to list: 'published' (default) or 'quarantined' (legacy).",
    ),
    long: bool = typer.Option(False, "--long", help="Show a table with common metadata columns."),
    columns: Optional[str] = typer.Option(None, "--columns", "-c", help="Comma-separated column names (published API only)"),
    format: str = typer.Option("plain", "--format", "-F", help="plain|csv|tsv|json (published API only)"),
):
    """
    List packages by status.
    Default lists published packages; use --status quarantined for legacy uploads.
    """
    server = (ctx.obj or {}).get("server_url", DEFAULT_SERVER_URL)
    status = _validate_status(status)
    url = _url_for(server, status)
    if status == "quarantined":
        _list_quarantined(ctx, url)
        return
    _list_published(ctx, url, long, columns, format)


# ---- install ----
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

    dest_path = _resolve_install_dir(cfg, dest)
    target_name = as_name or _safe_filename(name)
    target_file = _determine_target_file(dest_path, target_name, force)

    meta_url = _meta_url(server, name, version)
    dl_url = _download_url(server, name, version)

    meta = _fetch_json_safe(
        ctx, meta_url,
        on_http_msg="Failed to fetch metadata",
        on_request_action="fetching metadata",
        on_generic_msg="Failed to fetch metadata",
    )
    _verify_published(meta)  # type: ignore[arg-type]
    data = _fetch_bytes_safe(ctx, dl_url)
    _verify_hash(meta, data, skip=no_verify)  # type: ignore[arg-type]

    file_mode = _parse_mode_opt(mode)
    try:
        _atomic_write(target_file, data, file_mode)
    except Exception as e:
        typer.echo(f"✗ Failed to write {target_file}: {e}", err=True)
        raise typer.Exit(1)

    typer.echo(f"✓ Installed {name}{(':'+version) if version else ''} → {target_file}")


if __name__ == "__main__":
    app()
