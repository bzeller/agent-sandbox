# Agent Sandbox Manager (`agent-sandbox`)

A pluggable, distro-agnostic manager for **Rootless Podman** designed to provide isolated, project-specific development environments for various AI coding assistants (like **OpenCode**, **Aider**, and **Claude Code**).

By utilizing a class-based runtime plugin system and dynamic, hierarchical template resolution, `agent-sandbox` ensures absolute isolation of workspace state, configurations, and cache, while seamlessly sharing global identities and authentication tokens.

---

## 🗺️ Table of Contents
* [🚀 Key Features](#-key-features)
* [📦 Installation & Symlink Setups](#-installation--symlink-setups)
* [🐚 Basic Usage & CLI Examples](#-basic-usage--cli-examples)
* [🐚 Custom Commands & Shell Access](#-custom-commands--shell-access)
* [📖 Deep-Dive Documentation](#-deep-dive-documentation)

---

## 🚀 Key Features

* **Multi-Plugin Support:** Switch between different AI coding tools (`opencode`, `aider`, `claude`) seamlessly.
* **Symlink-Safe Auto-Detection:** Dynamically executes the correct plugin when symlinked to your `PATH` (e.g. calling `aider-sandbox` runs Aider, `claude-sandbox` runs Claude).
* **Workspace Isolation:** Project session logs, metadata, and caches are completely isolated per directory.
* **Private D-Bus & Runtime Sessions:** Prevents multi-instance collisions (such as JS `GType` errors) by wrapping standard container executions in private D-Bus and runtime sessions.
* **Targeted Image Pruning:** Automatically identifies and prunes older workspace-specific image layers upon successful tool upgrades to keep your host disk completely clean.

---

## 📦 Installation & Symlink Setups

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/bzeller/agent-sandbox.git ~/workspace/agent-sandbox
    ```

2.  **Make the script executable:**
    ```bash
    chmod +x ~/workspace/agent-sandbox/scripts/agent-sandbox.py
    ```

3.  **Setup Symlinks for Auto-Detection:**
    Create symlinks in your `PATH` (e.g., `~/bin` or `/usr/local/bin`). The script uses the calling binary's name to detect which plugin to launch:
    ```bash
    mkdir -p ~/bin
    ln -s ~/workspace/agent-sandbox/scripts/agent-sandbox.py ~/bin/opencode-sandbox
    ln -s ~/workspace/agent-sandbox/scripts/agent-sandbox.py ~/bin/aider-sandbox
    ln -s ~/workspace/agent-sandbox/scripts/agent-sandbox.py ~/bin/claude-sandbox
    ln -s ~/workspace/agent-sandbox/scripts/agent-sandbox.py ~/bin/agent-sandbox
    ```

---

## 🐚 Basic Usage & CLI Examples

Run the sandbox using any of your configured symlinks or CLI arguments:

```bash
# Launches the default plugin (OpenCode) or the symlinked plugin
opencode-sandbox
aider-sandbox
claude-sandbox

# Or explicitly select the plugin via CLI
agent-sandbox --plugin aider
```

### Key Options:
* `--rebuild`: Force an image rebuild.
* `--root`: Run the container as the root user.
* `--microvm`: Launch the container inside a hardware-isolated KVM microVM.
* `--update`: Check for and install the latest version of the plugin's tool from GitHub.
* `--include-dir`: Include additional directory (HostPath:ContainerPath or just HostPath for auto-mount in `/mnt`).
* `--debug`: Show paths, resolved sidecar config, generated Dockerfile, and podman commands.
* `--dry-run`: Output the generated Podman command without executing it.

---

## 🐚 Custom Commands & Shell Access

You can append custom commands to the sandbox to bypass the default tool and execute packages, scripts, or debug the shell:

### Run a specific direct command:
```bash
aider-sandbox aider --help
opencode-sandbox opencode run "Summarize this project"
```

### Access an interactive Bash shell:
```bash
aider-sandbox /bin/bash
```

### Mount extra directories via CLI:
```bash
agent-sandbox --include-dir ~/projects/shared-libs:/mnt/libs
# Auto-mounts to /mnt/my-data:
agent-sandbox --include-dir ~/my-data
```

---

## 📖 Deep-Dive Documentation

For advanced features, configurations, and extension blueprints, please check our dedicated documentation subfiles:

1.  **[Sidecar Configuration (config.json)](docs/SIDECAR_CONFIG.md):** Detailed explanations of configuration file resolution, layering rules, and JSON schema examples.
2.  **[Trust-On-First-Use (TOFU) & Security Model](docs/TRUST_MODEL.md):** Deep-dive into our security boundaries, safe/privileged keys, TOFU fingerprinting, and container-hardening flags.
3.  **[Plugging & Extending Plugins](docs/PLUGINS_AND_TEMPLATES.md):** Complete blueprints on how to add custom tools and customize hierarchical `Dockerfile.template` resolutions.
4.  **[Hardware-Isolated MicroVMs (krun)](docs/MICROVM.md):** Guide to hardware-enforced virtualization, dynamic host-aware allocations, and our runtime doctor checks.
