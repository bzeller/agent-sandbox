# Agent Sandbox Manager (`agent-sandbox`)

A pluggable, distro-agnostic manager for **Rootless Podman** designed to provide isolated, project-specific development environments for various AI coding assistants (like **OpenCode**, **Aider**, and **Claude Code**).

By utilizing a class-based runtime plugin system and dynamic, hierarchical template resolution, `agent-sandbox` keeps workspace state, configuration, and cache isolated per project, while seamlessly sharing global identities and authentication tokens. See [SELinux Labeling & Isolation Boundary](#-selinux-labeling--isolation-boundary) for the precise scope of that isolation.

---

## 🗺️ Table of Contents
* [🚀 Key Features](#-key-features)
* [🔐 SELinux Labeling & Isolation Boundary](#-selinux-labeling--isolation-boundary)
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
* **Non-Invasive Mounts:** Never rewrites SELinux labels on your host. Your workspace stays fully usable by host tools (editors, IDEs, `git`) while sandboxes are running.

---

## 🔐 SELinux Labeling & Isolation Boundary

`agent-sandbox` mounts every host path **without** an SELinux relabel suffix (`:z` / `:Z`) and instead runs containers with `--security-opt label=disable`.

**Why.** Both `:z` and `:Z` rewrite the host path's SELinux type to `container_file_t` **in place**, and that change *persists after the container exits* — permanently mutating your source tree and home directory. `:Z` is worse still: it assigns a private, per-container MCS category, so a second sandbox started concurrently steals the label and the first one fails with `EACCES`. This previously broke shared credential directories (e.g. `~/.config/gcloud`) for the host *and* for every other sandbox.

**What actually provides isolation.** The filesystem boundary is the **mount namespace**, not SELinux: a container can only see its own image plus the paths explicitly mounted into it. Combined with rootless Podman and `--userns=keep-id`, the container runs as your own unprivileged user, so an escape yields your privileges — not root. Access to host paths is further gated by the [trust model](docs/TRUST_MODEL.md), which requires explicit approval for privileged mounts.

**What this trades away.** With labeling disabled, SELinux no longer provides a *second* barrier if the mount namespace is escaped (via a kernel or runtime vulnerability, or a leaked file descriptor). Under `container_t` confinement such a process still could not read `user_home_t` files; now it could reach anything your user can. Containers also no longer receive MCS-based isolation from one another.

> [!IMPORTANT]
> This is a deliberate trade-off: SELinux never protected against the primary threat here — an agent misusing the access it was *deliberately granted* (your workspace and any mounted credentials). It only guarded against sandbox escape.
>
> **If you are running genuinely untrusted or hostile code, use `--microvm`.** That provides a hardware-enforced KVM boundary and is unaffected by container SELinux labeling. See [MicroVMs](docs/MICROVM.md).

### Repairing labels from earlier versions

Versions that used `:Z` left host paths permanently relabeled. To restore them:

```bash
restorecon -R -v ~/my-project          # any previously sandboxed workspace
restorecon -R -v ~/.config/gcloud      # and any mounted credential/config dirs

# Verify: expect user_home_t / config_home_t, with no container_file_t
# and no :cNNN,cMMM category suffix.
ls -ldZ ~/my-project ~/.config/gcloud
```


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
