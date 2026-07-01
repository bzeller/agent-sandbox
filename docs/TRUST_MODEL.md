# Trust-On-First-Use (TOFU) & Security Model

`agent-sandbox` is engineered around strict, defensive sandboxing. Since workspace directories can contain freshly cloned, untrusted code, the orchestrator employs a **granular trust-on-first-use (TOFU)** security store to prevent configurations from silently compromising your host system.

---

## 🧭 Blast Radius: Safe vs. Privileged Keys

Configuration keys are divided into two tiers based on their potential impact on your host machine:

| Tier | Keys | How it's honored from a workspace file |
|------|------|----------------------------------------|
| **Safe** (affects only the disposable container) | `base_image`, `install`, `set_env`, `microvm`, `microvm_cpus`, `microvm_ram_mib` | Honored automatically |
| **Privileged** (reaches *out* to your host) | `mounts`, `forward_env`, `ssh_auth_sock`, `ports` | Honored **only after you explicitly approve them** |

*   **Safe Keys:** A malicious base image or dependency can at worst compromise the disposable container, which is already considered untrusted. Thus, projects may declare these freely.
*   **Privileged Keys:** Bind-mounting host paths, forwarding host environment variables (secrets!), forwarding your SSH agent, or exposing host ports punch holes *through* the sandbox to your host. They are locked down by default.

---

## 🔒 TOFU Fingerprint Tracking

Trust is tracked at the granularity of an **individual configuration item** — each mount entry, each `forward_env` name, each port mapping, and the `ssh_auth_sock` flag are approved independently.

1.  **First-Use Prompt:** The first time a workspace config requests a privileged item, you are shown exactly what it wants and prompted to approve:
    ```
    ⚠️ This workspace's config requests NEW host-level access from inside the sandbox:
       • bind-mount host path '~/.ssh' -> container '/home/developer/.ssh'
       
       Source: /home/user/project/.aider-sandbox/config.json
       These reach OUT of the sandbox to your host. Only approve if you trust this workspace.
       
       Trust this workspace and grant the above? [y/N]:
    ```
2.  **Fingerprint Persistence:** Approving stores a cryptographic SHA-256 fingerprint **per item** in `${XDG_CONFIG_HOME}/agent-sandbox/trusted_workspaces.json` (created with owner-only permissions `0600`).
3.  **Silent Re-runs:** Subsequent runs honor already-approved items silently, and **prompt only for items you haven't approved yet**.
4.  **Granular Prompts:** Modifying or adding a single mount (e.g. a `git pull` adds a config item) prompts *only* for that new/changed item; your existing approvals stay trusted.
5.  **Strict Demotions:** Removing a privileged key from your sidecar configuration drops its fingerprint from the trust store. If a collaborator re-introduces that key later, the sandbox is guaranteed to **prompt you again**, preventing silent security regressions.
6.  **Non-Interactive Defaults:** In headless environments (CI/CD or no TTY), unapproved privileged keys are **denied by default**. Pass `--trust-workspace` to force-grant approvals.
7.  **Dry-run Safety:** Under `--dry-run`, no approvals are written or modified. Already-approved items are honored in the preview, and any new items are shown as "would prompt".

To clear all trusted fingerprints for a workspace, run:
```bash
agent-sandbox --forget-workspace-trust
```

---

## 🛡️ Container Security Hardening

To enforce strict isolation, the orchestrator configures Podman with several enterprise-grade security flags by default:

*   **`--tmpfs /tmp:rw,nosuid,size=1g`:** Mounts `/tmp` inside the container as a 1GB in-memory temporary filesystem. This keeps temporary files fast, prevents disk-filling attacks, and blocks `setuid` binary executions via `/tmp`.
*   **`--security-opt no-new-privileges`:** Sets the kernel-level `PR_SET_NO_NEW_PRIVS` flag, preventing any process inside the container or its children from ever escalating privileges (even if a system `setuid` binary is found).
*   **`--pids-limit 1024`:** Caps the maximum number of concurrent processes to 1024, protecting your host system from **fork-bomb** attacks or runaway loops.
*   **System-Wide Git Safety:** Configures Git system-wide inside the container image layer (`/etc/gitconfig`) to trust all directories (`safe.directory '*'`). This solves Git's "dubious ownership" blocks on host mounts natively inside the container, with **zero modifications to your host-side personal `~/.gitconfig`**.
