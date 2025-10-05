# Bashman: The Package Manager for Bash Scripts

**Bashman** is a tiny registry + CLI for shipping single-file shell scripts with versioning and metadata.

- Backend: FastAPI + SQLite (content stored as BLOBs, FTS5 search, basic download stats)
- CLI: Typer (`init`, `start`, `publish`, `list`, `install`)
- Optional request-signing (Ed25519 / RSA-PSS-SHA256 / ECDSA-SHA256)

> The server exposes JSON APIs under `/api/*`. Legacy endpoints (`/scripts`) exist for back-compat with older CLI flows.

---

## Quickstart

```bash
# 1) install (dev)
python -m pip install --upgrade pip
pip install -e .

# 2) start server (localhost:8000)
bashman start

# 3) init client (registers your pubkey on the server)
bashman init   --nickname you   --key-file ~/.ssh/id_ed25519   --server-url http://127.0.0.1:8000
```

---

## Publishing scripts (updated)

You now have **two ways** to publish from the CLI:

### A) Legacy upload (minimal; filename + version 0.1.0)

```bash
bashman publish ./myscript.sh
```

- Hits `POST /scripts`
- Package **name = filename**, **version = `0.1.0`**
- Enters **`quarantined`** status (see “Publish lifecycle” below)
- Populates only basic fields (description derives from filename). All “rich” metadata (author, homepage, etc.) stays empty.

This is intentionally simple to keep existing automation working.

### B) Rich upload (new; full metadata)

If you pass **any** metadata flags (or `--manifest`), the CLI uses the modern API:

```bash
bashman publish ./myscript.sh   --name hello-world   --version 1.2.3   --description "Say hello"   --author "Jane Smith"   --homepage "https://example.org"   --repository "https://git.example/you/hello-world"   --license MIT   --keyword hello --keyword demo   --dep coreutils=">=8.30" --dep curl="^7"   --platform linux --platform darwin   --shell-version "bash 5"
```

This hits `POST /api/packages` with a multipart form and **populates all metadata columns** (the fields you saw as `|||||||` in SQLite will be set when you publish this way).

#### Flags (CLI)

- `--name` (default: filename)  
- `--version` (default: `0.1.0` if you don’t pass metadata)  
- `--description`, `--author`, `--homepage`, `--repository`, `--license`, `--shell-version`  
- `--keyword` (repeatable)  
- `--dep` (repeatable) accepts `name=version`; bare `--dep name` becomes `{"name": "*"}`  
- `--platform` (repeatable)  
- `--manifest PATH` (optional JSON file; flags override manifest)

> The CLI takes care of JSON-encoding `keywords`, `dependencies`, and `platforms` into the exact form the server expects.

#### Manifest example

```json
{
  "name": "hello-world",
  "version": "1.2.3",
  "description": "Say hello",
  "author": "Jane Smith",
  "homepage": "https://example.org",
  "repository": "https://git.example/you/hello-world",
  "license": "MIT",
  "keywords": ["hello", "demo"],
  "dependencies": { "coreutils": ">=8.30" },
  "platforms": ["linux", "darwin"],
  "shell_version": "bash 5"
}
```

Use it with:

```bash
bashman publish ./myscript.sh --manifest ./bashman.json
```

Flags always override manifest fields.

---

## Publish lifecycle

- New uploads enter **`quarantined`**.
- You can move a package to **`published`** in two ways:

  1. **Manual publish** (API):  
     `POST /api/packages/<name>/<version>/publish`
  2. **Auto-publish queue** (server): set `BASHMAN_AUTO_PUBLISH=1`. The server picks jobs and changes status automatically.

- **ShellCheck gate** (optional):  
  The server can lint uploads before publishing. Configure with env vars:

  - `BASHMAN_SHELLCHECK_MODE`:  
    - `off` — never run  
    - `best-effort` *(default)* — run if available; missing tool does **not** block publishing  
    - `enforce` — require ShellCheck to pass; otherwise package is **rejected**
  - `BASHMAN_SHELLCHECK_ARGS`: e.g. `-x -S style`

If your package seems “stuck” in `quarantined`, check whether auto-publish is disabled or ShellCheck is in `enforce` mode and failing.

---

## Installing packages

```bash
# latest
bashman install hello-world

# specific version
bashman install hello-world -v 1.2.3

# override install dir / filename
bashman install hello-world --dest ~/.local/bin --as hello
```

- The CLI defaults to the install dir you set during `init` (`--install-dir`).
- SHA256 verification is enabled by default; use `--no-verify` to skip.

---

## Listing & searching

- CLI (published): `bashman list`  
- CLI (legacy quarantined): `bashman list --status quarantined`
- API search: `GET /api/search?q=term&limit=50` (published only)

---

## Auth model

The CLI signs requests **when it can** (after `init`):  
`X-Bashman-User`, `X-Bashman-Date`, `X-Bashman-Nonce`, `X-Bashman-Alg`, `Authorization: Bashman <sig>`

Server behavior:

- `BASHMAN_REQUIRE_AUTH=1` → **legacy** `/scripts` requires valid Bashman auth headers.
- `/api/*` endpoints currently **do not enforce** auth (subject to change).
- Key registration: `POST /api/users` with `{nickname, public_key}`. The CLI does this during `init`.

---

## Web UI (for humans)

- `/` — minimal landing page with published packages and search box  
- `/packages?q=term` — simple search  
- `/packages/<name>` — package detail + download link

If you hit legacy `/scripts` from a browser and get a 401/403, the server returns a small HTML page or redirects back to `/` for a friendlier experience; the CLI keeps getting JSON errors as before.

---

## API reference (relevant to publish)

- `POST /api/packages` (multipart):
  - **Required**: `name`, `version`, `description`, `file=@script.sh`
  - **Optional**: `author`, `homepage`, `repository`, `license`, `shell_version`
  - **JSON strings**: `keywords='[]'`, `dependencies='{}'`, `platforms='[]'`

- `POST /api/packages/{name}/{version}/publish`  
- `GET /api/packages[?status=published|quarantined]`  
- `GET /api/packages/{name}[?version=x.y.z]`  
- `GET /api/packages/{name}/versions`  
- `GET /api/packages/{name}/download[?version=x.y.z]`

`/scripts` (legacy): `GET` list (quarantined), `POST` upload (filename + `0.1.0`).

---

## Migration notes

- Existing `bashman publish ./file.sh` continues to work (legacy path).  
- To populate **author/homepage/repository/license/keywords/dependencies/platforms/shell_version**, use either flags or a manifest, which switches you to the modern `/api/packages` flow.
- “Latest” is chosen by **`created_at`**, not semver ordering (for now).

---

## Environment

Server knobs you’re most likely to touch:

- `BASHMAN_DB_PATH` — SQLite file path  
- `BASHMAN_REQUIRE_AUTH=1` — enforce auth on `/scripts`  
- `BASHMAN_AUTO_PUBLISH=1` — enable background auto-publish worker  
- `BASHMAN_SHELLCHECK_MODE` — `off | best-effort | enforce`  
- `BASHMAN_SHELLCHECK_ARGS` — passed to `shellcheck`  

---

### Example: curl rich publish (without the CLI)

```bash
BASE=http://127.0.0.1:8000

curl -X POST "$BASE/api/packages"   -F name=hello-world   -F version=1.0.0   -F description="A hello world script"   -F author="Your Name"   -F homepage="https://example.org"   -F repository="https://git.example/you/hello-world"   -F license="MIT"   -F keywords='["hello","demo"]'   -F dependencies='{"coreutils":">=8.30"}'   -F platforms='["linux","darwin"]'   -F shell_version="bash 5"   -F file=@./hello.sh
```

---

## Common pitfalls

- **Empty metadata in DB** → you used the legacy publish. Use flags or `--manifest`.
- **“Not published” on install** → publish manually or enable `BASHMAN_AUTO_PUBLISH=1`.
- **Rejected on publish** → ShellCheck is `enforce` and failed; check logs or relax the mode.
