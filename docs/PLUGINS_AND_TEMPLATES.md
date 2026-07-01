# Plugins & Dockerfile Templates

`agent-sandbox` is built with a highly extensible, modular class-based plugin architecture. You can easily add entirely new tools (such as `cline`, `continue`, or your own custom tools) simply by declaring a subclass of `BasePlugin` and writing a `Dockerfile.template`.

---

## 🔌 Creating and Extending Plugins

To add a new tool (e.g., `cline`), simply create a subdirectory inside the `plugins/` directory:

```
plugins/
└── cline/
    ├── Dockerfile.template    # The default Dockerfile blueprint for Cline
    └── plugin.py              # The Python class declaring paths, mounts, and commands
```

### Example Plugin Class (`plugins/cline/plugin.py`)
```python
from plugins.base import BasePlugin

class Plugin(BasePlugin):
    name = "cline"
    github_repo = "cline/cline" # (Optional: used to track & run updates)
    
    # Machine namespaces on the host under config/ and local/share/
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

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, internal_home):
        # Extend podman run mounts specifically for this plugin
        for f in self.shared_config_files:
            podman_cmd.extend(["-v", f"{xdg_config / f}:{internal_home}/{f}:Z"])
```

### The Orchestrator Hook Lifecycle:
When executing a plugin, `scripts/agent-sandbox.py` dynamically scans, imports, and executes these lifecycle hooks:
*   `initialize(ws_meta_dir, xdg_config)`: Sets up initial directories and default shared files.
*   `mount_config(podman_cmd, ws_meta_dir, xdg_config, internal_home)`: Appends custom file mounts to Podman.
*   `get_installed_version(podman_cmd, image_tag)`: Runs version sniffing against the container.
*   `get_latest_version(debug)`: Queries GitHub releases to check for updates.

---

## 🧱 Dockerfile Template Resolution (Highest to Lowest)

If you need custom system packages or an entirely custom build for a project, you can override the Dockerfile blueprint dynamically. The orchestrator resolves templates in this order:

1.  **Workspace Custom Template:** `.{plugin_name}-sandbox/Dockerfile.template`
2.  **Global User Override:** `${XDG_CONFIG_HOME}/agent-sandbox/{plugin_name}.template`
3.  **Legacy Global Fallback:** `${XDG_CONFIG_HOME}/opencode-sandbox/Dockerfile.template`
4.  **Built-in Default blueprint:** `plugins/{plugin_name}/Dockerfile.template`
