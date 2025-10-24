Bashman: The Package Manager for Bash Scripts
=============================================

**Bashman** is a tiny registry + CLI for shipping single-file shell scripts with versioning and metadata.

-   Backend: FastAPI + SQLite (content stored as BLOBs, FTS5 search, basic download stats)

-   CLI: Typer (`init`, `start`, `publish`, `list`, `install`)

-   Optional request-signing (Ed25519 / RSA-PSS-SHA256 / ECDSA-SHA256)

> The server exposes JSON APIs under `/api/*`. Legacy endpoints (`/scripts`) exist for back-compat with older CLI flows.

Public Best Efforts Instance
----------------------------

**URL:** https://bashman.ellisbs.co.uk

-   **Best-efforts service only.** This public instance is provided as a convenience and is explicitly a development / staging instance.

-   **No guarantee of availability.** The instance may be offline, rate-limited, or periodically wiped without notice.

-   **No guarantee of persistence.** Packages published to this site should be considered ephemeral; do not rely on it as primary storage for production artifacts.

-   **Security and access.** While the CLI can interact with the site and sign requests, the site is operated in a best-efforts mode and should not be relied on for strict security guarantees or regulatory compliance.

-   **Recommendation.** Treat the public instance as a demonstration or temporary staging area only. For anything you depend on, run your own server or use a durable, managed service.

> The CLI defaults to using this best-efforts URL. You can override it during `init` or with `--server-url` when running commands.

Quickstart
----------

bash

```
# 1) install (dev)
python -m pip install --upgrade pip
pip install -e .

# 2) start server (localhost:8000)
bashman start

# 3) init client (registers your pubkey on the server)
bashman init --nickname you --key-file ~/.ssh/id_ed25519 --server-url http://127.0.0.1:8000

```

Publishing scripts
------------------

You now have two ways to publish from the CLI: legacy upload or rich upload. See the usage examples in other sections for full command forms.

-   Legacy upload: `bashman publish ./myscript.sh` → `POST /scripts`, version `0.1.0`, enters `quarantined`.

-   Rich upload: pass metadata flags or `--manifest` → `POST /api/packages` (multipart), full metadata populated, enters `quarantined`.

Best practice recommendations
-----------------------------

-   **Do not use the public site for production artifacts.** Host a private Bashman instance for production usage.

-   **Self-hosting** is simple: run `bashman start` on a server, configure `BASHMAN_DB_PATH` to a persisted path, and run behind HTTPS and a reverse proxy.

-   **Auth** (`BASHMAN_REQUIRE_AUTH=1`): ensure the server has the `cryptography` package installed and a stable deployment so signatures and nonce replay protection work reliably.

-   **Auto-publish** (`BASHMAN_AUTO_PUBLISH=1`) runs a background worker that processes queued packages; enable it on servers where background processing is acceptable.

-   **Backups and persistence**: SQLite is used by default; back up the DB file, enable WAL mode, and schedule vacuuming, or migrate to a more robust DB for higher scale.

-   **Observability**: add logging and metrics around publish queue depth, ShellCheck failures, publish successes/failures, and download counts for operational visibility.

Installing packages
-------------------

bash

```
# latest
bashman install hello-world

# specific version
bashman install hello-world -v 1.2.3

# override install dir / filename
bashman install hello-world --dest ~/.local/bin --as hello

```

-   The CLI defaults to the install dir you set during `init` (`--install-dir`).

-   SHA256 verification is enabled by default; use `--no-verify` to skip.

Environment configuration highlights
------------------------------------

-   **BASHMAN_SERVER_URL** --- CLI / client server URL (packaged CLI defaults to https://bashman.ellisbs.co.uk)

-   **BASHMAN_DB_PATH** --- SQLite file path for server storage

-   **BASHMAN_REQUIRE_AUTH** --- set `1` to enforce auth on legacy `/scripts` endpoints

-   **BASHMAN_AUTO_PUBLISH** --- set `1` to enable background auto-publish worker

-   **BASHMAN_SHELLCHECK_MODE** --- `off | best-effort | enforce`

-   **BASHMAN_SHELLCHECK_ARGS** --- additional args passed to `shellcheck`

Security and operational notes
------------------------------

-   The CLI signs requests when a private key is configured; the server verifies signatures only when auth is enforced.

-   Nonce replay protection is in-memory per server process; for multi-process or clustered deployments use a shared store or centralize the signer/verification service.

-   ShellCheck gating can block publishing in `enforce` mode; `best-effort` skips when ShellCheck is not installed. Log ShellCheck outcomes for visibility.

-   Algorithm labels should be consistent between CLI and server to avoid verification mismatches.

Disclaimer
----------

The public site at https://bashman.ellisbs.co.uk is provided on a best-efforts basis and is currently a development site. There is no SLA, no guarantee of uptime, and published content may not be persisted. For production use, run your own Bashman server or use other durable storage and hosting options.

Contributing and Support
------------------------

Contributions are welcome. Open issues or PRs for bugs and improvements. For production deployments, add monitoring, backups, and consider a more robust queue/backend for multi-process or high-scale scenarios.
