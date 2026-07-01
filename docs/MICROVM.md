# Hardware-Virtualized MicroVM Runtime (`krun`)

`agent-sandbox` supports running standard container images inside a hardware-virtualized **MicroVM** using **`crun` + `libkrun` (invoked via the `krun` runtime)**. 

This represents the absolute gold standard of sandboxing security. Instead of sharing your host's Linux kernel (traditional namespace containers), the guest processes execute on a **completely isolated guest Linux kernel** inside a lightweight virtual machine.

---

## 🚀 Running in a MicroVM

To promote any sandbox session to a hardware-isolated MicroVM, simply run:

```bash
# Pass the command line flag
aider-sandbox --microvm
```

Or declare it permanently inside your trusted configuration (`~/.config/aider-sandbox/config.json`) or your project's sidecar:

```json
{
  "microvm": true
}
```

---

## 🧠 Sane Dynamic Hardware Allocations

You don't need to worry about manually sizing CPU and RAM allocations for your MicroVMs. `agent-sandbox` dynamically queries your host's physical hardware on startup and configures sane defaults:

*   **vCPUs:** Allocates **50% of your host's physical cores** (minimum 1 core), keeping compilation and AI logic incredibly fast while leaving plenty of capacity for your host IDE and background tasks.
*   **Memory (RAM):** Allocates **20% of your host's total physical memory** (minimum 1024 MiB), providing ample headroom without starving host-side editors.

### Custom Resource Overrides
If you want to pin allocations manually, you can override these defaults in your configuration (only valid when `"microvm": true` is enabled):

```json
{
  "microvm": true,
  "microvm_cpus": 4,
  "microvm_ram_mib": 4096
}
```

---

## 🩺 The MicroVM Capability Doctor

To prevent obscure, low-level virtualization crashes, `agent-sandbox` runs a graceful capability scan whenever `--microvm` is requested, checking:

1.  **BIOS KVM Virtualization:** Verifies `/dev/kvm` exists and that the CPU virtualization module (`kvm_intel` or `kvm_amd`) is loaded.
2.  **Host Permissions:** Verifies your host user has read/write access to `/dev/kvm`. If not, it outputs a clean, helpful message prompting you to inspect your local `/dev/kvm` group permissions.
3.  **OCI Runtime Configuration:** Verifies `krun` is configured as a valid OCI runtime in Podman, falling back to verifying `crun` availability (since `krun` is simply a specialized handler for `crun`).

If any check fails, the script performs a clean exit and prints **clear, actionable, and distro-agnostic instructions** in your terminal to resolve the issue!
