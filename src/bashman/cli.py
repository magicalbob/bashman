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
# Alias for tests compatibility
DEFAULT_URL = DEFAULT_SERVER_URL
BASHMAN_SERVER_URL="URL of the Bashman server"

# Shell validation regex
SHELL_REGEX = re.compile(
    r'#!/(?:usr/bin/)?(?:env\s+)?(sh|bash|zsh|ksh|fish)'
)

def load_config() -> dict:
    """Load the configuration file, or return defaults."""
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    server_url: str = typer.Option(
        None,
        "--server-url",
        help="Override the server URL (default from config)"
    )
):
    """Ensure Bashman is initialized before running most commands"""
    # Skip check for init itself
    if ctx.invoked_subcommand and ctx.invoked_subcommand != "init":
        if not CONFIG_FILE.exists():
            typer.echo(
                "Error: Bashman is not initialized. Please run `bashman init` first.",
                err=True,
            )
            raise typer.Exit(1)

    cfg = load_config()
    ctx.obj = {
        "server_url": server_url or cfg.get("server_url", DEFAULT_SERVER_URL),
        "nickname": cfg.get("nickname")
    }

@app.command()
def init(
    nickname: str = typer.Option(
        ...,  # mandatory
        "--nickname",
        help="User nickname"
    ),
    server_url: str = typer.Option(
        DEFAULT_SERVER_URL,
        "--server-url",
        help=BASHMAN_SERVER_URL
    )
):
    """Initialize Bashman configuration with server URL and user nickname."""
    if CONFIG_FILE.exists():
        typer.echo(
            "Error: Bashman has already been initialized.",
            err=True,
        )
        raise typer.Exit(1)

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    config = {
        "server_url": server_url,
        "nickname": nickname
    }
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)
    typer.echo(f"Bashman initialized at {CONFIG_FILE}")

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
    path: str,
    url: str = typer.Option(
        None,
        "--server-url",
        help=BASHMAN_SERVER_URL
    )
):
    """Upload a shell script to the server."""
    cfg = load_config()
    server = url or cfg.get("server_url", DEFAULT_SERVER_URL)

    if not os.path.isfile(path):
        typer.echo("Error: file does not exist", err=True)
        raise typer.Exit(1)

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

    with open(path, "rb") as f:
        resp = httpx.post(f"{server}/scripts", files={"file": (os.path.basename(path), f)})
    if resp.status_code == 200:
        typer.echo(f"✓ Quarantined: {os.path.basename(path)}")
    else:
        typer.echo(f"✗ {resp.status_code} — {resp.text}", err=True)
        raise typer.Exit(1)

@app.command(name="list")
def _list(
    url: str = typer.Option(
        None,
        "--server-url",
        help=BASHMAN_SERVER_URL
    )
):
    """List scripts in quarantine."""
    cfg = load_config()
    server = url or cfg.get("server_url", DEFAULT_SERVER_URL)
    resp = httpx.get(f"{server}/scripts")
    resp.raise_for_status()
    for name in resp.json():
        typer.echo(name)

if __name__ == "__main__":
    app()
