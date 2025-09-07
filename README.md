Bashman: The Package Manager for Bash Scripts
=============================================

![Bashman Diagram](https://dev.ellisbs.co.uk/files/Bashman.png)

**Bashman** brings a PyPI-like experience to shell scripting: discover, publish, and (eventually) install Bash packages with versioning and metadata. The current MVP ships a **FastAPI** backend with **SQLite** storage (content as BLOBs), **FTS5** search, basic **download stats**, and a slim **Typer** CLI for bootstrap and legacy upload/list flows.

> **Status:** Server/API is usable; CLI covers `init`, `start`, and **legacy** `publish`/`list`. New `/api/*` endpoints are preferred for programmatic use. Request-signing is scaffolded; see **Auth** note under [Server Usage](#server-usage).

* * * * *

Table of Contents
-----------------

1.  [Quickstart](#quickstart)

2.  [CLI Commands](#cli-commands)

3.  [Server Usage](#server-usage)

4.  [Package metadata](#package-metadata)

5.  [Roadmap](#roadmap)

6.  [Contributing](#contributing)

* * * * *

Quickstart
----------

> If a `bashman` executable isn't on your PATH yet, you can run the CLI via:
>
> `python -m bashman.cli --help`

1.  **Install Bashman (local dev while private)**

    `python -m pip install --upgrade pip
    pip install -e .           # or: poetry install`

2.  **Initialize your workspace**

    `bashman init\
      --nickname <you>\
      --key-file ~/.ssh/id_ed25519\
      --server-url http://127.0.0.1:8000`

    The CLI default server URL is `https://bashman.ellisbs.co.uk`. For local dev, pass `--server-url` (or set `BASHMAN_SERVER_URL`).

3.  **Start the registry server** (localhost:8000 by default)

    `bashman start`

    *(No built-in daemonization/log PID files; use a supervisor if needed.)*

4.  **Publish a package (legacy endpoint)**

    `bashman publish ./myscript.sh`

    This uses the legacy `/scripts` flow and creates a **quarantined** package named after the filename with version `0.1.0`. For richer metadata, prefer the new HTTP form API below.

5.  **List (legacy, quarantined names)**

    `bashman list`

    Programmatic list/search of **published** packages is available via HTTP: `/api/packages`, `/api/search`.

* * * * *

CLI Commands
------------

### Server

`bashman start [--host HOST] [--port PORT]`

*(Legacy `stop`/`status` are not implemented.)*

### Registry Taps

`bashman tap add <name> <url>
bashman tap remove <name>
bashman tap list`

*Planned; not implemented in current code.*

### Discover & Manage

`bashman list                      # legacy: quarantined names from /scripts
# Planned (HTTP available today): search/new/trending/info/install/upgrade/uninstall`

### Authoring

`# Planned: bashman create <package>
bashman publish <path/to/script.sh>   # legacy upload to /scripts (quarantined)`

> A single local registry is assumed today. Remote taps beyond static endpoints are planned.

* * * * *

Server Usage
------------

The server exposes a **JSON API** under `/api/*`. Legacy endpoints remain for the current CLI.

### Endpoints (current)

-   `GET /api/packages` --- list (filter with `status=published|quarantined`, `limit`, `offset`)

-   `GET /api/packages/{name}` --- latest by `created_at` (or `?version=x.y.z`)

-   `GET /api/packages/{name}/versions` --- all versions

-   `POST /api/packages` --- **multipart form** (create; see example below)

-   `POST /api/packages/{name}/{version}/publish` --- set status to `published`

-   `DELETE /api/packages/{name}/{version}` --- soft delete

-   `GET /api/search?q=term&limit=50` --- full-text search (**published only**)

-   `GET /api/trending?days=7&limit=10`

-   `GET /api/packages/{name}/download` --- download (**published only**)

-   `GET /api/stats`

-   `POST /api/users` --- register `{nickname, public_key}`

**Legacy endpoints (still used by the CLI):**

-   `GET /scripts` --- list quarantined names

-   `POST /scripts` --- upload file → creates `0.1.0` **quarantined** entry

**Auth:** Request-signing headers are supported (Ed25519, RSA-PSS-SHA256, ECDSA-SHA256).\
When `BASHMAN_REQUIRE_AUTH=1`, the **legacy** `/scripts` routes require presence of Bashman auth headers. The new `/api/*` routes currently **do not enforce** auth.

### Create via HTTP (multipart form)

Fields `keywords`, `dependencies`, `platforms` must be JSON-encoded strings.

`BASE=http://127.0.0.1:8000

curl -X POST "$BASE/api/packages"\
  -F name=hello-world\
  -F version=1.0.0\
  -F description="A hello world script"\
  -F author="Your Name"\
  -F homepage="https://example.org"\
  -F repository="https://git.example/you/hello-world"\
  -F license="MIT"\
  -F keywords='["hello","demo"]'\
  -F dependencies='{}'\
  -F platforms='[]'\
  -F shell_version="bash 5"\
  -F file=@./hello.sh`

**Notes:**

-   The server **validates the shebang** of the uploaded file.

-   New packages enter **`quarantined`** status; publish via:

    `curl -X POST "$BASE/api/packages/hello-world/1.0.0/publish"`

-   "Latest" is selected by **`created_at`**, not by semver.

* * * * *

Package metadata
----------------

**Current reality:** there is **no manifest file**. The server does **not** read `bashman.json`.

-   **Legacy upload (`/scripts`)**: package **name = filename**, **version = `0.1.0`**, status `quarantined`.

-   **New API (`POST /api/packages`)**: send metadata via **multipart form**.

    -   **Required:** `name`, `version`, `description`, `file=@script.sh`

    -   **Optional (strings):** `author`, `homepage`, `repository`, `license`, `shell_version`

    -   **JSON-encoded strings:** `keywords='[]'`, `dependencies='{}'`, `platforms='[]'`

-   Script content is stored **in SQLite as a BLOB**. No dependency resolution or installer exists yet.

**Future (optional) manifest --- *not implemented***\
A small `bashman.json` (name, version, description, etc.) may be introduced later. It's intentionally not documented as supported until code exists.

* * * * *

Roadmap
-------

### Phase 1: Core Infrastructure

1.  **DB abstraction** --- SQLite backend (shipped), modular for future engines

2.  **Public-key registration + optional request-signing** --- `bashman init` (shipped)

3.  **Metadata storage** --- timestamps, author, descriptions (shipped)

4.  **Versioning** --- semver accepted; "latest" by `created_at` (current behavior)

### Phase 2: User Experience

1.  **Multi-tap support** *(planned)*

2.  **Search API** --- **exists** (`/api/search`); CLI wrapper *planned*

3.  **Web UI enhancements** *(planned)*

4.  **Package management** --- install/uninstall + dependencies *(planned)*

### Phase 3: Security & Quality

1.  **Security pipeline** --- quarantine → scan → publish *(planned)*

2.  **Linting** --- ShellCheck/shfmt *(planned)*

3.  **Sandbox** --- Docker/bwrap/firejail *(planned)*

4.  **Package signing** --- GPG verification *(planned)*

### Phase 4: Ecosystem

1.  **Functional tests** *(planned)*

2.  **Badges/classifiers/trending** *(planned)*

3.  **CI/CD integrations** *(planned)*

4.  **AI-assisted review** *(exploratory; when mature)*

**Current Status:** Phase 1 **in progress**. Core DB + API implemented; CLI covers `init`, `start`, and legacy `publish`/`list`.

* * * * *

Contributing
------------

-   See `CODE_OF_CONDUCT.md` and `SECURITY.md`

-   Issues/MRs: [https://gitlab.ellisbs.co.uk/ian/bashman/-/issues](https://gitlab.ellisbs.co.uk/ian/bashman/-/issues?utm_source=chatgpt.com)\
    Labels: `good first issue` - `enhancement` - `security` - `documentation`
