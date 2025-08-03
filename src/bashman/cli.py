#!/usr/bin/env python3

import os
import sys
import signal
import subprocess
from pathlib import Path

import typer
import httpx

app = typer.Typer()

API_HOST = "127.0.0.1"
API_PORT = 8000
API_BASE = f"http://{API_HOST}:{API_PORT}/api"

PID_FILE = Path.home() / ".bashman_server.pid"
LOG_FILE = Path.home() / ".bashman_server.log"


@app.command(help="Start the Bashman server in the background")
def start(host: str = API_HOST, port: int = API_PORT):
    if PID_FILE.exists():
        typer.echo("Server already running (PID file exists).", err=True)
        raise typer.Exit(1)

    cmd = [
        sys.executable, "-m", "uvicorn",
        "bashman.server.app:app",
        "--host", host, "--port", str(port)
    ]
    # Open (or create) the log file in append mode
    lf = open(LOG_FILE, "a")
    proc = subprocess.Popen(cmd, stdout=lf, stderr=lf, cwd=os.getcwd())

    PID_FILE.write_text(str(proc.pid))
    typer.echo(f"Server started (PID {proc.pid}); logs → {LOG_FILE}")


@app.command(help="Stop the Bashman server")
def stop():
    if not PID_FILE.exists():
        typer.echo("No PID file; is the server running?", err=True)
        raise typer.Exit(1)

    pid = int(PID_FILE.read_text())
    try:
        os.kill(pid, signal.SIGTERM)
        PID_FILE.unlink()
        typer.echo(f"Server (PID {pid}) stopped")
    except ProcessLookupError:
        typer.echo("Process not found; removing stale PID file.", err=True)
        PID_FILE.unlink()
        raise typer.Exit(1)


@app.command(help="Check if the Bashman server is running")
def status():
    if not PID_FILE.exists():
        typer.echo("Server not running.")
        raise typer.Exit(1)

    pid = int(PID_FILE.read_text())
    try:
        # signal 0 doesn't kill; it just checks for existence
        os.kill(pid, 0)
        typer.echo(f"Server running (PID {pid}); logs → {LOG_FILE}")
    except ProcessLookupError:
        typer.echo("PID file exists, but no process found. Cleaning up.", err=True)
        PID_FILE.unlink()
        raise typer.Exit(1)


@app.command(help="List all available packages")
def list():
    resp = httpx.get(f"{API_BASE}/packages")
    resp.raise_for_status()
    for pkg in resp.json():
        typer.echo(f"{pkg['name']}@{pkg['version']} — {pkg['description']}")


@app.command(help="Show details for a package")
def info(name: str):
    resp = httpx.get(f"{API_BASE}/packages/{name}")
    if resp.status_code == 404:
        typer.echo("✗ Package not found", err=True)
        raise typer.Exit(1)
    resp.raise_for_status()
    pkg = resp.json()
    typer.echo(f"Name:        {pkg['name']}")
    typer.echo(f"Version:     {pkg['version']}")
    typer.echo(f"Description: {pkg['description']}")


@app.command(help="Publish a new package")
def publish(name: str, version: str, description: str):
    payload = {"name": name, "version": version, "description": description}
    resp = httpx.post(f"{API_BASE}/packages", json=payload)
    resp.raise_for_status()
    typer.echo("✓ Published:", resp.json())


def main():
    app()


if __name__ == "__main__":
    main()
