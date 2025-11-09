Bashman --- package manager for single-file shell scripts
=======================================================

Bashman provides a lightweight registry + CLI for shipping, versioning, and installing single-file shell scripts with searchable metadata and optional request signing. It's intended as a more structured alternative to ad-hoc GitHub gists or manual script distribution.

Key goals

-   Make publishing, discovering, and installing reusable shell scripts reproducible and auditable.

-   Keep the server small and self-hostable while supporting signing, search, and simple metrics.

-   Provide a CLI workflow that mirrors package managers (publish, list, install, rm) for scripts.

Highlights

-   **Backend:** FastAPI + SQLite (BLOB content storage; FTS5 full-text search; basic download stats)

-   **CLI:** Typer commands: `init`, `start`, `publish`, `list`, `install`, `rm`

-   **Signing:** Optional request signing (Ed25519, RSA-PSS-SHA256, ECDSA-SHA256) and nonce replay protections

-   **Compatibility:** JSON APIs under `/api/*`; legacy `/scripts` endpoints for older CLI flows

Quickstart
----------

1.  Install (development)


```bash
python -m pip install --upgrade pip
pip install -e .

```

1.  Start server (localhost:8000)


```bash
bashman start

```

1.  Initialize client (registers your pubkey on the server)

```bash
bashman init --nickname you --key-file ~/.ssh/id_ed25519 --server-url http://127.0.0.1:8000

```

Publish a script (two options)

-   Legacy: `bashman publish ./myscript.sh` → POST `/scripts`, auto-version `0.1.0`, status `quarantined`

-   Rich: `bashman publish --manifest ./manifest.json ./myscript.sh` → POST `/api/packages` (multipart) with full metadata, status `quarantined`

Install

```bash
# latest
bashman install hello-world

# specific version
bashman install hello-world -v 1.2.3

# custom destination and filename
bashman install hello-world --dest ~/.local/bin --as hello

```

-   Default install dir is set during `init`

-   SHA256 verification enabled by default; use `--no-verify` to skip

Remove packages (admin only)

```bash
# remove latest published version
bashman rm my-script

```

-   Only admin users may delete packages; set `admin = 1` in the server sqlite3 user record to grant access

Configuration and environment
-----------------------------

Important environment variables

-   **BASHMAN_SERVER_URL** --- CLI default server URL (packaged default: https://bashman.ellisbs.co.uk)

-   **BASHMAN_DB_PATH** --- SQLite file path used by the server

-   **BASHMAN_REQUIRE_AUTH** --- set `1` to enforce auth on legacy `/scripts` endpoints

-   **BASHMAN_AUTO_PUBLISH** --- set `1` to enable background auto-publish worker

-   **BASHMAN_SHELLCHECK_MODE** --- `off | best-effort | enforce`

-   **BASHMAN_SHELLCHECK_ARGS** --- extra args passed to shellcheck

Operational tips

-   Use WAL mode and regular backups for the SQLite DB; consider migrating to a server-grade DB at scale

-   For clustered/multi-process deployments, replace in-memory nonce store with a shared store for replay protection

-   Run server behind HTTPS + reverse proxy in production; ensure `cryptography` is installed when auth is required

Public instance and disclaimers
-------------------------------

Public demo site: https://bashman.ellisbs.co.uk

-   **Best-efforts development instance.** Do not rely on this site for production artifacts or guaranteed persistence.

-   **No SLA or uptime guarantee.** The instance may be offline, rate-limited, or periodically wiped.

-   For production use, self-host with persistent DB, backups, and monitoring.

Contributing and operations checklist
-------------------------------------

-   Add tests for publish and install flows, and ShellCheck gating behavior

-   CI: run ShellCheck, unit tests for signature verification, and sqlite WAL backup verification

-   Monitoring: publish queue depth, ShellCheck failures, publish success/failure counts, download metrics

-   Docs: add an example manifest schema, API examples for `/api/packages`, and a migration note for admins

### Rationale and small improvements

-   Lead with the problem and value proposition so new visitors immediately understand why Bashman exists.

-   Move the public-instance and disclaimer up front to prevent accidental reliance on demo site.

-   Condense environment and operational guidance into a compact section for operators.

-   Show the two publish modes (legacy vs rich) clearly and give command examples for common workflows.

-   Add a short contributing/ops checklist to guide production hardening.
