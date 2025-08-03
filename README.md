Bashman: The Package Manager for Bash Scripts
=============================================

**Bashman** brings a PyPI‑like experience to shell scripting: discover, install, and share Bash packages with full versioning, metadata, security scanning, and a unified registry model.

* * * * *

Table of Contents
-----------------

1.  [Why Bashman?](https://gitlab.ellisbs.co.uk/ian/bashman#why-bashman)

2.  [Key Concepts](https://gitlab.ellisbs.co.uk/ian/bashman#key-concepts)

3.  [Package Format](https://gitlab.ellisbs.co.uk/ian/bashman#package-format)

4.  [CLI Reference](https://gitlab.ellisbs.co.uk/ian/bashman#cli-reference)

5.  [Registry & Discovery](https://gitlab.ellisbs.co.uk/ian/bashman#registry--discovery)

6.  [Security Model](https://gitlab.ellisbs.co.uk/ian/bashman#security-model)

7.  [Roadmap](https://gitlab.ellisbs.co.uk/ian/bashman#roadmap)

8.  [Governance & Contribution](https://gitlab.ellisbs.co.uk/ian/bashman#governance--contribution)

* * * * *

Why Bashman?
------------

-   **Formalize Your Scripts**: Move from ad‑hoc Gists or repos to a standardized package with metadata, versioning, and dependency declarations.

-   **Discoverability**: Browse, filter, and search by keywords, categories, or popularity---both on the web and via the CLI.

-   **Reproducible Installs**: Pin versions, resolve dependencies (e.g. `jq`, `curl`), and track exact install procedures.

-   **Security by Design**: Optional, pluggable pipelines for linting, sandboxed execution, and AI‑assisted review.

* * * * *

Key Concepts
------------

-   **Package**: A directory with a `bashman.json` manifest + subdirectories (`bin/`, `lib/`, etc.).

-   **Registry**: A CouchDB‑style index of packages (public or private). Provides search, metadata, and version resolution.

-   **Tap**: A user‑hosted registry (self‑hostable) that can be added with `bashman tap add <name> <url>`.

* * * * *

Package Format
--------------

Every Bashman package must include a **`bashman.json`** manifest at its root.

```
{
  "name": "myscript",                // unique identifier (kebab-case)
  "version": "1.2.3",               // semantic version
  "description": "Short summary.",
  "homepage": "https://...",          // project URL
  "repository": "https://...",        // Git repo
  "license": "MIT",
  "keywords": ["networking","cli"],
  "classifiers": [                    // free‑form or from a registry taxonomy
    "Topic :: System :: Monitoring",
    "Environment :: Console"
  ],
  "dependencies": {                   // external binaries or other bashman packages
    "jq": ">=1.6",
    "bash-utils": "^0.5"
  },
  "platforms": ["linux","macos"],
  "shell": ">=4.4"
}

```

Directory structure:

```
my-script/
├── bashman.json
├── bin/           # executables that go into $PATH
│   └── myscript
├── lib/           # helper scripts
├── config/        # default config templates
├── install.sh     # optional custom installer
└── uninstall.sh   # optional custom uninstaller

```

* * * * *

CLI Reference
-------------

### Global Commands

```
# Initialize your workspace (~/.bashman)
bashman init

# Add or remove registries (taps)
bashman tap add   <name> <url>
bashman tap remove <name>

# List all taps
tbashman tap list

```

### End‑User Commands

```
# Discover
bashman search <term> [--classifiers=... --keywords=...]  # full-text + filter
bashman trending [--period=weekly|monthly]               # most-installed recently
bashman new      [--period=weekly|monthly]               # latest published

# Install & Manageashman install   <package>[@<version>]   # default latest
bashman upgrade   <package>[@<version>]   # bump one or all
bashman list                                # show installed
bashman uninstall <package>                 # remove
bashman info     <package>                 # metadata dump

```

### Author Commands

```
bashman create <package>        # scaffold directory + bashman.jsonashman publish [--tap=<name>]  # push to registry + validation pipeline
bashman version bump [major|minor|patch]

```

* * * * *

Registry & Discovery
--------------------

1.  **Public Registry** at `registry.bashman.sh` (curated, security‑scored, official packages).

2.  **User Taps** -- self‑hosted CouchDB instances or simple static JSON indexes.

3.  **Search API** -- JSON endpoint for external tooling (IDEs, CI badges):

    ```
    GET /api/v1/search?q=backup&classifiers=Security&sort=downloads

    ```

4.  **Website** -- browse by category, filter by shell version, license, platform, or security score.

* * * * *

Security Model
--------------

Bashman's security pipeline is **opt‑in**. You choose which validators to run on `publish`:

1.  **Lint & Style** (`shellcheck`, `shfmt`)

2.  **Sandboxed Execution** (Docker sandbox + resource limits)

3.  **AI‑Assisted Review** (LLM checks for suspicious patterns)

4.  **Digital Signatures** (GPG signing of tarballs)

You can configure these steps in a `.bashmanci.yml` at root.

* * * * *

Roadmap
-------

1.  **MVP**: local install/list/uninstall + package creation + single‑registry search.

2.  **Registries**: support multiple taps, JSON API, and web UI.

3.  **Security**: integrate CI hooks, sandboxing, and signing.

4.  **Ecosystem**: create official classifiers, badges, and GitHub Actions.

* * * * *

Governance & Contribution
-------------------------

-   **Code of Conduct**: see `CODE_OF_CONDUCT.md`

-   **Security Policy**: see `SECURITY.md`

-   **Issue Tracker**: <https://gitlab.ellisbs.co.uk/ian/bashman/-/issues>

-   **Pull Requests**: fork, branch, test, and open a merge request. We review by label:

    -   `good first issue`, `enhancement`, `security`, `documentation`

Thanks for helping make Bashman the trusted package manager for Bash!
