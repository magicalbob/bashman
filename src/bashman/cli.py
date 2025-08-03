#!/usr/bin/env python3
import os
import sys
import typer
import httpx

app = typer.Typer()
DEFAULT_URL = "http://127.0.0.1:8000"

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
    """Upload a .sh file to the server."""
    if not os.path.isfile(path) or not path.endswith(".sh"):
        typer.echo("Error: must point at an existing .sh file", err=True)
        raise typer.Exit(1)
    with open(path, "rb") as f:
        resp = httpx.post(f"{url}/scripts", files={"file": (os.path.basename(path), f)})
    if resp.status_code == 200:
        typer.echo(f"✓ Quarantined: {os.path.basename(path)}")
    else:
        typer.echo(f"✗ {resp.status_code} — {resp.text}", err=True)
        raise typer.Exit(1)

@app.command()
def list(url: str = DEFAULT_URL):
    """List scripts in quarantine."""
    resp = httpx.get(f"{url}/scripts")
    resp.raise_for_status()
    for name in resp.json():
        typer.echo(name)

if __name__ == "__main__":
    app()
