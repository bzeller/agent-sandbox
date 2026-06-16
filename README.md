# Agent Sandbox Manager (`agent-sandbox`)

A pluggable, distro-agnostic wrapper for **Rootless Podman** designed to provide isolated, project-specific development environments for various AI coding assistants (like **OpenCode**, **Aider**, and others).

By utilizing a class-based runtime plugin system and dynamic, hierarchical template resolution, `agent-sandbox` ensures absolute isolation of workspace state, configurations, and cache, while seamlessly sharing global identities and authentication tokens.

---

## 🚀 Key Features

* **Multi-Plugin Support:** Easily run and switch between different AI coding tools (e.g., `opencode`, `aider`) in the same workspace.
* **Symlink-Safe Auto-Detection:** Automatically executes the correct plugin when symlinked to your `PATH` (e.g., calling `aider-sandbox` runs Aider, `opencode-sandbox` runs OpenCode).
* **Workspace Isolation:** Project session logs, metadata, and caches are completely isolated under `${XDG_DATA_HOME}/agent-sandbox/ws-<hash>/<plugin_name>`.
* **Private D-Bus & Runtime Sessions:** Prevents multi-instance collisions (such as JS `GType` errors) by wrapping every command execution in a private `dbus-run-session` and an isolated `XDG_RUNTIME_DIR`.
* **Hierarchical Customization:** Complete environment overrides from the global machine level down to individual workspace folders.

---

## 🛠️ Installation & Symlinks

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/youruser/agent-sandbox.git ~/workspace/agent-sandbox
    ```

2.  **Make the script executable:**
    ```bash
    chmod +x ~/workspace/agent-sandbox/scripts/agent-sandbox
    ```

3.  **Setup Symlinks for Auto-Detection:**
    Create symlinks in your `PATH` (e.g., `~/bin` or `/usr/local/bin`). The script uses the calling binary's name to detect which plugin to launch:
    ```bash
    mkdir -p ~/bin
    ln -s ~/workspace/agent-sandbox/scripts/agent-sandbox ~/bin/opencode-sandbox
    ln -s ~/workspace/agent-sandbox/scripts/agent-sandbox ~/bin/aider-sandbox
    ln -s ~/workspace/agent-sandbox/scripts/agent-sandbox ~/bin/agent-sandbox
    ```

---

## 📂 Hierarchical Workspace Configurations

Each project workspace can cleanly organize its sandbox settings under a hidden folder `.{plugin_name}-sandbox/` without polluting your project root.

### 1. Sidecar Config Resolution (Highest to Lowest)
1.  **Workspace Directory Config (No Ext):** `.{plugin_name}-sandbox/config`
2.  **Workspace Directory Config (JSON):** `.{plugin_name}-sandbox/config.json`
3.  **Workspace Flat File:** `.{plugin_name}-sandbox.json`
4.  **Generic Workspace Flat File:** `.agent-sandbox.json`
5.  **Legacy Flat File:** `.opencode-sandbox.json` *(Backward compatibility)*

#### Example sidecar configuration (`.aider-sandbox/config.json` or `.aider-sandbox/config`):
```json
{
  "base_image": "opensuse/tumbleweed:latest",
  "install": [
    "cmake",
    "ninja",
    "gcc-c++",
    "python3-pip"
  ],
  "mounts": [
    { "host": "~/.gitconfig", "container": "/home/developer/.gitconfig" }
  ],
  "forward_env": [
    "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY"
  ],
  "set_env": {
    "AIDER_DARK_MODE": "true",
    "EDITOR": "vim"
  },
  "ssh_auth_sock": true
}
```

### 2. Dockerfile Template Resolution (Highest to Lowest)
If you need custom system packages or an entirely custom build for a project, you can place a custom template inside your workspace:
1.  **Workspace Custom Template:** `.{plugin_name}-sandbox/Dockerfile.template`
2.  **Global User Template:** `${XDG_CONFIG_HOME}/agent-sandbox/{plugin_name}.template`
3.  **Legacy Global Fallback:** `${XDG_CONFIG_HOME}/opencode-sandbox/Dockerfile.template`
4.  **Built-in Fallback:** `plugins/{plugin_name}/Dockerfile.template`

---

## 🔌 Creating & Extending Plugins

To add a new tool (e.g., `cline`), simply create a subdirectory inside the `plugins/` directory:

```
plugins/
└── cline/
    ├── Dockerfile.template    # The default Dockerfile blueprint for Cline
    └── plugin.py              # The Python class declaring paths, mounts, and commands
```

#### Example Plugin Python Class (`plugins/cline/plugin.py`):
```python
from plugins.base import BasePlugin

class Plugin(BasePlugin):
    name = "cline"
    github_repo = "cline/cline" # (Optional: used to track & run updates)
    
    # Machine namespaces on the host
    host_config_subdir = "cline-sandbox"
    host_data_subdir = "cline-sandbox"
    image_prefix = "cline-ws"
    container_prefix = "cline"
    
    # Default execution behaviors
    default_cmd = ["cline"]
    internal_config_dir = "/home/developer/.config/cline"
    internal_data_dir = "/home/developer/.local/share/cline"
    
    # Dynamically mount global configuration files/dirs into container config
    shared_config_dirs = []
    shared_config_files = [".clinerc"]

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, global_auth, internal_home):
        # Extend podman run mounts specifically for this plugin
        for f in self.shared_config_files:
            podman_cmd.extend(["-v", f"{xdg_config / f}:{internal_home}/{f}:Z"])
```

The main `agent-sandbox` orchestrator automatically scans, imports, and executes this plugin at runtime!

---

## 📖 Usage & Options

Run the sandbox using any of your configured symlinks or CLI arguments:

```bash
# Launches default plugin (OpenCode) or the symlinked plugin
opencode-sandbox
aider-sandbox

# Or explicitly select the plugin via CLI
agent-sandbox --plugin aider
```

### Key Options:
* `--rebuild`: Force an image rebuild.
* `--root`: Run the container as the root user.
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
