# Sidecar Configuration (`config.json`)

`agent-sandbox` uses a highly flexible, tiered JSON configuration system to declare customized execution environments, environment variables, packages, and host mounts.

---

## 📂 Sidecar File Resolution (First Match Wins)

Each project workspace can cleanly organize its sandbox settings under a hidden directory without polluting your project root:

1.  **Workspace Directory Config (No Ext):** `.{plugin_name}-sandbox/config`
2.  **Workspace Directory Config (JSON):** `.{plugin_name}-sandbox/config.json`
3.  **Workspace Flat File:** `.{plugin_name}-sandbox.json`
4.  **Generic Workspace Flat File:** `.agent-sandbox.json`

---

## 🎚️ Layering & Merging Rules

Your configurations are cleanly layered. Lists (such as `install` packages, `mounts`, and `forward_env` variables) are combined dynamically avoiding duplicates, while flat options (such as `base_image` or `ssh_auth_sock`) are cleanly overwritten:

```
[Built-in Defaults] < [Global Trusted Config] < [Workspace Config (Safe keys automatically; Privileged once approved)]
```

### 1. Global Trusted Configs (No Prompts)
You can define global, personal presets that apply across all workspaces automatically without ever triggering trust prompts:
*   `${XDG_CONFIG_HOME}/agent-sandbox/config.json` (Generic)
*   `${XDG_CONFIG_HOME}/{plugin_name}-sandbox/config.json` (Specific)
*   `${XDG_CONFIG_HOME}/agent-sandbox/{plugin_name}.json` (Alternate specific)

---

## 📋 JSON Sidecar Examples

### Workspace Sidecar Example (`.aider-sandbox/config.json`)
```json
{
  "base_image": "opensuse/tumbleweed:latest",
  "install": [
    "cmake",
    "ninja",
    "gcc-c++",
    "python3-pip"
  ],
  "set_env": {
    "AIDER_DARK_MODE": "true",
    "EDITOR": "vim"
  },
  "mounts": [
    { "host": "~/.gitconfig", "container": "/home/developer/.gitconfig" }
  ],
  "forward_env": [
    "GH_TOKEN"
  ],
  "ssh_auth_sock": true
}
```

### Global Trusted Config Example (`~/.config/aider-sandbox/config.json`)
```json
{
  "mounts": [
    { "host": "~/.gitconfig", "container": "/home/developer/.gitconfig" }
  ],
  "forward_env": [
    "GH_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY"
  ],
  "ports": [
    "8501:8501"
  ],
  "ssh_auth_sock": true
}
```

---

## 📐 Design Note: String Lists vs. JSON Objects for Ports

For declarative port descriptions, `agent-sandbox` uses a **list of strings** (e.g., `"ports": ["8501:8501"]`) rather than structured JSON objects (e.g. `{"host": 8501, "container": 8501}`). 

The key technical benefits of this approach:
1.  **Familiarity & Conventions:** Aligns perfectly with standard Docker/Podman CLI flag formats (`-p host:container`), making it instantly readable for developers.
2.  **Implicit Port Allocation:** Natively supports Podman's single-port binding (e.g., `"ports": ["8501"]` binds container `8501` to a random, high-range host port) without needing verbose `null` key handling or complex fallback parsing in the schemas.
3.  **Lossless Deep Merging:** Allows the `_merge_config` engine to perform highly reliable, duplicate-free list concatenations. Merging lists of complex dictionaries requires nested collision and equality-comparison code, which increases codebase complexity and bugs.
