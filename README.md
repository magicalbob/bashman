Bashman: The Package Manager for Bash Scripts
=============================================

![Bashman Diagram](https://dev.ellisbs.co.uk/files/Bashman.png)

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

### Phase 1: Core Infrastructure
1. **Database abstraction layer** - SQLite backend with modular interface for future database options
2. **API key-based identity system** - `bashman init` generates persistent user identity without personal data
3. **Enhanced metadata storage** - automatic timestamps, author tracking, package descriptions
4. **Time-based versioning** - monotonic version numbering with optional semantic tagging

### Phase 2: User Experience
5. **Multi-tap support** - connect to remote registries beyond local-only
6. **Search API** - programmatic search for IDE/CI integrations  
7. **Web UI enhancements** - improved package browsing and discovery
8. **Package management** - proper install/uninstall workflows with dependency tracking

### Phase 3: Security & Quality
9. **Security pipeline foundation** - quarantine → scan → publish workflow
10. **Basic linting integration** - ShellCheck and shfmt validation
11. **Sandbox execution** - Docker-based script testing and validation
12. **Package signing** - GPG-based package integrity verification

### Phase 4: Ecosystem
13. **Functional testing suite** - Selenium-based end-to-end workflow testing
14. **Advanced features** - badges, classifiers, trending packages
15. **CI/CD integrations** - GitHub Actions, GitLab CI templates
16. **Advanced security** - AI-assisted review (when mature enough to avoid false confidence)

**Current Status:** Phase 1 ready to begin. Complete CI/CD pipeline operational with unit testing, quality scanning, artifact publishing, and containerized deployment.

* * * * *

## Backlog Ideas

These features are not yet prioritized but may be explored in future iterations:

- **YAML Package Format Support**: Allow `bashman.yaml` as an alternative to `bashman.json` for greater flexibility and user preference.
- **Auto Tap Discovery**: Federation via `.well-known/bashman.json` endpoints or domain-based conventions for dynamic registry discovery.
- **Plugin System**:
  - Custom install/uninstall hooks
    - Tap source plugins (e.g. GitHub releases, GitLab snippets)
    - **Alternative Script Sandboxing**: Support for non-Docker sandboxes using tools like `bwrap` or `firejail` for script isolation.
    - **SPDX/SBOM Integration**: Emit SPDX-compliant Software Bill of Materials (SBOM) for packages to support traceability and compliance.
    - **Template-Driven Package Scaffolding**: Allow reusable templates for common Bash package types (e.g. CLI tools, config generators).
    - **Scheduled Tap Syncing**: Automatically refresh remote taps on a schedule for freshness without manual invocation.

    These backlog items are intended as inspiration or rainy-day enhancements and are not yet on the formal roadmap.
* * * * *

Contributing
------------

-   See CODE_OF_CONDUCT.md

-   See SECURITY.md

-   Report issues and MRs at <https://gitlab.ellisbs.co.uk/ian/bashman/-/issues>

We triage by labels: good first issue - enhancement - security - documentation
