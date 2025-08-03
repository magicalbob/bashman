### Bashman: The Package Manager for Bash Scripts

**Bashman** is an ambitious project to create a decentralized, secure, and community-driven package manager for shell scripts. Just as `pip` manages Python packages and `apt` handles system software, Bashman aims to bring a professional level of versioning, dependency management, and security to the world of Bash scripting.

* * * * *

### The Vision

Shell scripts are a vital part of the developer's toolkit, but they are often shared informally through Gists, forums, or simple Git repositories. This leads to issues with versioning, discoverability, and, most importantly, security.

Bashman addresses this by introducing a standardized **Bashman Package Format** and a set of tools to manage these packages. The goal is to build a centralized, trusted registry---dubbed **Bashman Central**---that validates and hosts community-created scripts. However, Bashman is also designed to be **self-hostable**, allowing organizations to run their own private registries for internal tool sharing.

### Key Features

-   **Standardized Package Format**: A package is not just a single file. Bashman defines a structure for multi-file scripts, including binaries, configuration files, and documentation.

-   **Decentralized by Design**: While a public registry will be available, any user can host their own Bashman server, offering the same push/search/pull services.

-   **Robust Security Model**: To build trust in a world of executable code, every package pushed to a Bashman server is subjected to a multi-stage security process:

    -   **Static Analysis**: Automated linting and code style checks with tools like `ShellCheck`.

    -   **Sandboxed Execution**: Scripts are run in an isolated Docker environment to monitor their behavior.

    -   **LLM-Powered Review**: An AI layer analyzes the script's intent, system calls, and network activity to flag potential security risks.

-   **Git-Centric Workflow**: Bashman leverages Git for versioning and distribution. A package's source code remains on Git, with the Bashman registry acting as a trusted index.

### Proposed CLI Commands

Bashman will offer a clean and intuitive command-line interface, separating the experience for end-users and package authors.

#### For the End-User:

-   `bashman init`: Initializes the local Bashman workspace, setting up a directory structure and configuring the user's shell environment.

-   `bashman install <package-name>`: Installs a package from a Bashman registry.

-   `bashman list`: Lists all packages currently installed on the local system.

-   `bashman uninstall <package-name>`: Removes an installed package.

-   `bashman search <term>`: Searches the Bashman registry for available packages.

#### For the Package Author:

-   `bashman create <package-name>`: Scaffolds a new Bashman package with the correct directory structure and manifest file.

-   `bashman publish`: Submits a new version of a package to a Bashman server for validation and inclusion in the registry.

### The Bashman Package Format

A Bashman package is a directory containing the following:

-   **`bashman.json`**: The manifest file that defines the package's metadata and instructions.

-   **`bin/`**: (Required) Executable scripts that will be placed in the user's `$PATH`.

-   **`config/`**: (Optional) Default configuration files for the script.

-   **`lib/`**: (Optional) Helper scripts, libraries, or other non-executable code.

-   **`install.sh`**: (Optional) A script for custom installation logic.

-   **`uninstall.sh`**: (Optional) A script for custom uninstallation logic.

### Tentative Roadmap

**Phase 1: The Core CLI (Local-First)**

-   Implement the `bashman init`, `install`, `list`, and `uninstall` commands.

-   Focus on local functionality: `bashman install` will initially work by cloning a Git repository directly.

-   Develop the `bashman create` command to establish the package format.

**Phase 2: The Self-Hostable Server**

-   Build the server-side component of Bashman.

-   Implement the `bashman publish` command, allowing packages to be pushed to a server.

-   Implement the core search/pull services. This will allow for private, in-house registries.

**Phase 3: The Public Registry & Advanced Security**

-   Integrate the security validation features: static analysis, Docker sandboxing, and LLM-powered review.

-   Launch **Bashman Central**, a public, curated registry of community-contributed Bash packages.

-   Add features for dependency management and version resolution.

* * * * *

### How to Contribute

Bashman is an open-source project and welcomes contributions from the community. If you are passionate about shell scripting and package management, we would love for you to get involved. Check out the [issues page](https://gitlab.ellisbs.co.uk/ian/bashman/-/issues) for ways to help, or visit the main repository at <https://gitlab.ellisbs.co.uk/ian/bashman>.
