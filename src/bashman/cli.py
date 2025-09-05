import os
import sys
import re
import json
from pathlib import Path

import typer
import httpx

app = typer.Typer()

# Configuration constants
CONFIG_DIR = Path.home() / ".config" / "bashman"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_SERVER_URL = "https://bashman.ellisbs.co.uk"
# Back-compat for tests and older callers
DEFAULT_URL = DEFAULT_SERVER_URL
SERVER_URL_HELP = "URL of the Bashman server"

# Shell validation regex
SHELL_REGEX = re.compile(r'^#!/(?:usr/bin/|bin/)?(?:env\s+)?(sh|bash|zsh|ksh|fish)')

def load_config() -> dict:
    """Load the configuration file, or return defaults."""
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def validate_private_key(key_path: str) -> tuple[bool, str]:
    """
    Validate that the key file exists and contains a valid private key.

    Returns:
        tuple[bool, str]: (is_valid, error_message)
    """
    key_file = Path(key_path)

    # Check if file exists
    if not key_file.exists():
        return False, f"Key file does not exist: {key_path}"

    # Check if file is readable
    if not key_file.is_file():
        return False, f"Key path is not a file: {key_path}"

    try:
        with open(key_file, 'r') as f:
            key_content = f.read().strip()
    except Exception as e:
        return False, f"Cannot read key file: {e}"

    if not key_content:
        return False, "Key file is empty"

    # Basic validation for common private key formats
    valid_headers = [
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN DSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    ]

    if not any(key_content.startswith(header) for header in valid_headers):
        return False, "File does not appear to contain a valid private key (missing PEM header)"

    # Try to load the key using cryptography library for more thorough validation
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
            load_ssh_private_key
        )

        key_bytes = key_content.encode('utf-8')

        # Try different key loading methods
        try:
            # Try PEM format first
            load_pem_private_key(key_bytes, password=None)
        except Exception:
            try:
                # Try SSH format
                load_ssh_private_key(key_bytes, password=None)
            except Exception:
                return False, "File contains invalid private key data"

    except ImportError:
        # If cryptography is not available, do basic format checking
        return True, "Warning: cryptography library not available, doing basic validation only"

    # Basic sanity check - should have matching footer
    if "-----BEGIN" in key_content and "-----END" not in key_content:
        return False, "Private key appears malformed (missing END marker)"

    return True, ""

def get_public_key(key_path: str) -> str:
    """
    Derives the public key from the private key file.
    
    Returns:
        str: The serialized OpenSSH public key.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
            load_ssh_private_key,
            NoEncryption,
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
            format=serialization.PublicFormat.OpenSSH
        ).decode("utf-8")

    except ImportError:
        typer.echo("Error: `cryptography` library is required to derive the public key. Please install it with `pip install cryptography`.", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"Error: Could not derive public key from file: {e}", err=True)
        raise typer.Exit(1)

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
    cfg = load_config() if CONFIG_FILE.exists() else {}
    resolved_server = server_url or cfg.get("server_url", DEFAULT_SERVER_URL)

    ctx.obj = {
        "server_url": resolved_server,
        "nickname": cfg.get("nickname"),
        "private_key_path": cfg.get("private_key_path"),
    }

@app.command()
def init(
    nickname: str = typer.Option(
        ...,  # mandatory
        "--nickname",
        help="User nickname"
    ),
    key_file: str = typer.Option(
        ...,  # mandatory
        "--key-file",
        help="Path to private key file"
    ),
    server_url: str = typer.Option(
        DEFAULT_SERVER_URL,
        "--server-url",
        help=SERVER_URL_HELP
    )
):
    """Initialize Bashman configuration with server URL, user nickname, and private key."""
    if CONFIG_FILE.exists():
        typer.echo(
            "Error: Bashman has already been initialized.",
            err=True,
        )
        raise typer.Exit(1)

    # Expand user path if needed (e.g., ~/path/to/key)
    expanded_key_path = os.path.expanduser(key_file)

    # Validate the private key
    is_valid, error_msg = validate_private_key(expanded_key_path)
    if not is_valid:
        typer.echo(f"Error: {error_msg}", err=True)
        raise typer.Exit(1)
    elif error_msg:
        # Print a warning if basic validation was used
        typer.echo(f"{error_msg}", err=True)

    # Convert to absolute path for storage
    absolute_key_path = os.path.abspath(expanded_key_path)

    # Register the user on the server
    typer.echo("Registering user on the server...")
    try:
        public_key = get_public_key(absolute_key_path)
        
        payload = {
            "nickname": nickname,
            "public_key": public_key
        }
        
        resp = httpx.post(f"{server_url}/api/users", json=payload)
        resp.raise_for_status()
        
        typer.echo("✓ User registered successfully!")

    except httpx.HTTPStatusError as e:
        typer.echo(f"✗ An HTTP error occurred during registration: {e.response.status_code} - {e.response.text}", err=True)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"✗ An error occurred while registering: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ An unexpected error occurred: {e}", err=True)
        raise typer.Exit(1)

    # Create the config file only after successful registration
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config = {
        "server_url": server_url,
        "nickname": nickname,
        "private_key_path": absolute_key_path
    }

    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

    typer.echo(f"Bashman configuration created at {CONFIG_FILE}")
    typer.echo(f"User: {nickname}")
    typer.echo(f"Key: {absolute_key_path}")
    typer.echo(f"Server: {server_url}")


@app.command()
def start(
    host: str = "127.0.0.1",
    port: int = 8000
):
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
def publish(
    ctx: typer.Context,
    path: str
):
    """Upload a shell script to the server."""
    # Context object is automatically passed by Typer
    server = ctx.obj["server_url"]

    if not os.path.isfile(path):
        typer.echo("Error: file does not exist", err=True)
        raise typer.Exit(1)

    try:
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
            f.seek(0) # Reset file pointer to beginning for post request

            resp = httpx.post(f"{server}/scripts", files={"file": (os.path.basename(path), f)})
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

@app.command(name="list")
def _list(
    ctx: typer.Context
):
    """List scripts in quarantine."""
    # Context object is automatically passed by Typer
    server = ctx.obj["server_url"]

    try:
        resp = httpx.get(f"{server}/scripts")
        resp.raise_for_status()
        for name in resp.json():
            typer.echo(name)
    except httpx.HTTPStatusError as e:
        typer.echo(f"✗ An HTTP error occurred: {e.response.status_code} - {e.response.text}", err=True)
        raise typer.Exit(1)
    except httpx.RequestError as e:
        typer.echo(f"✗ An error occurred while listing scripts: {e}", err=True)
        raise typer.Exit(1)
    except Exception as e:
        typer.echo(f"✗ An unexpected error occurred: {e}", err=True)
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
