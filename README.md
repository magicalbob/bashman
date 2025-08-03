Bashman: The Package Manager for Bash Scripts
=============================================

**Bashman** brings a PyPI‑like experience to shell scripting: discover, install, and share Bash packages with full versioning, metadata, security scanning, and a unified registry model.

* * * * *

Table of Contents
-----------------

1.  [Quickstart](#quickstart)

2.  [CLI Commands](#cli-commands)

3.  [Server Usage](#server-usage)

4.  [Package Format](#package-format)

5.  [Roadmap](#roadmap)

6.  [Contributing](#contributing)

* * * * *

Quickstart
----------

1.  **Install Bashman**\
    pip install bashman

2.  **Initialize your workspace**\
    bashman init

3.  **Start the registry server** (localhost:8000 by default)\
    bashman start\
    Logs → ~/.bashman_server.log\
    PID → ~/.bashman_server.pid

4.  **Publish a package**\
    bashman publish myscript 0.1.0 "A brief description"

5.  **Explore packages**\
    bashman list\
    bashman search backup\
    bashman install myscript

* * * * *

CLI Commands
------------

### Server

bashman start [--host HOST] [--port PORT]\
bashman stop\
bashman status

### Registry Taps

bashman tap add <name> <url>\
bashman tap remove <name>\
bashman tap list

### Discover & Manage

bashman search <term> [--keywords] [--classifiers]\
bashman trending [--period=weekly|monthly]\
bashman new [--period=weekly|monthly]\
bashman install <pkg>[@<version>]\
bashman upgrade <pkg>[@<version>]\
bashman uninstall <pkg>\
bashman info <pkg>

### Authoring

bashman create <package> # scaffold new package\
bashman publish <name> <version> "<description>"

> **Note:** Currently only a single local registry (<http://127.0.0.1:8000>) is supported. Remote taps must point to static JSON endpoints.

* * * * *

Server Usage
------------

The server provides:

-   **Web UI** at `/`

-   **JSON API** under `/api/packages`

Endpoints:

GET /api/packages\
GET /api/packages/{name}\
POST /api/packages\
POST /api/packages/form

Use `/api/v1/search` (coming soon) for IDE or CI integrations.

* * * * *

Package Format
--------------

Every package root must include `bashman.json` with fields:

-   name: unique kebab-case identifier

-   version: semantic version

-   description: short summary

-   homepage: project URL

-   repository: Git repo URL

-   license: SPDX identifier

-   keywords: list of terms for discovery

-   dependencies: mapping of binaries or other packages to semver constraints

-   platforms: supported OSes

-   shell: required shell version

Typical layout:

my-script/\
├── bashman.json\
├── bin/ # executables\
│ └── myscript\
├── lib/ # helpers\
├── config/ # templates\
├── install.sh # optional installer\
└── uninstall.sh # optional uninstaller

* * * * *

Roadmap
-------

1.  Multi-tap support & remote registry

2.  Search API for IDE/CI

3.  Web UI polish

4.  Security pipelines

    -   Linting (ShellCheck, shfmt)

    -   Sandbox execution (Docker)

    -   AI-driven review (prototype)

    -   GPG signing

5.  Ecosystem tooling: badges, classifiers, GitHub Actions

*Is "AI-driven review" too early? Without formal audits it may mislead users---consider renaming or delaying.*

* * * * *

Contributing
------------

-   See CODE_OF_CONDUCT.md

-   See SECURITY.md

-   Report issues and MRs at <https://gitlab.ellisbs.co.uk/ian/bashman/-/issues>

We triage by labels: good first issue - enhancement - security - documentation
