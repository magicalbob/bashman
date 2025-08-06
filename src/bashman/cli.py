import os
import sys
import re
import json

import typer
import httpx

app = typer.Typer()
DEFAULT_URL = "http://127.0.0.1:8000"

SHELL_REGEX = re.compile(
    r"^#!\s*(?:/[^ \t]+/)*(?:env\s+)?(sh|bash|zsh|csh|ksh|dash|fish)\b"
)

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Ensure Bashman is initialized before running most commands"""
    # Skip check for init itself
    if ctx.invoked_subcommand and ctx.invoked_subcommand != "init":
        config_path = os.path.expanduser("~/.config/bashman/config.json")
        if not os.path.exists(config_path):
            typer.echo(
                "Error: Bashman is not initialized. Please run `bashman init` first.",
                err=True
            )
            raise typer.Exit(1)

@app.command()
def init():
    """Initialize Bashman configuration"""
    config_dir = os.path.expanduser("~/.config/bashman")
    config_file = os.path.join(config_dir, "config.json")
    # If already initialized, error
    if os.path.exists(config_file):
        typer.echo(
            "Error: Bashman has already been initialized.",
            err=True
        )
        raise typer.Exit(1)
    # Create config directory and file
    os.makedirs(config_dir, exist_ok=True)
    with open(config_file, "w") as f:
        json.dump({}, f)
    typer.echo(f"Bashman initialized at {config_file}")

@app.command()
def start(host: str = "127.0.0.1", port: int = 8000):
    """Launch the FastAPI server via uvicorn."""
    cmd = [
        sys.executable, "-m", "uvicorn",
        "bashman.server.app:app",
        "--host", host, "--port", str(port)
    ]
    os.execvp(cmd[0], cmd)

@app.command()
def publish(path: str, url: str = DEFAULT_URL):
    """Upload a shell script to the server."""
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
            err=True
        )
        raise typer.Exit(1)

    with open(path, "rb") as f:
        resp = httpx.post(f"{url}/scripts", files={"file": (os.path.basename(path), f)})
    if resp.status_code == 200:
        typer.echo(f"✓ Quarantined: {os.path.basename(path)}")
    else:
        typer.echo(f"✗ {resp.status_code} — {resp.text}", err=True)
        raise typer.Exit(1)

@app.command(name="list")
def _list(url: str = DEFAULT_URL):
    """List scripts in quarantine."""
    resp = httpx.get(f"{url}/scripts")
    resp.raise_for_status()
    for name in resp.json():
        typer.echo(name)

if __name__ == "__main__":
    app()
