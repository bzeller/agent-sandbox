#!/usr/bin/env python3
import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

# --- PATH RESOLUTION (Symlink-Safe) ---
SCRIPT_DIR = Path(__file__).resolve().parent

# Add the project root to sys.path so we can do relative/package imports within plugins
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from plugins.base import version_tuple


# XDG Compliance with fallbacks for empty or unset variables.
# Validate that any explicitly set value is an absolute path to prevent an
# attacker (or misconfigured environment) from redirecting config/credential
# reads and writes to arbitrary locations.
def _validated_xdg(env_var, default):
    raw = os.environ.get(env_var, "").strip()
    if not raw:
        return default
    p = Path(raw)
    if not p.is_absolute():
        print(
            f"⚠️ Warning: {env_var}={raw!r} is not an absolute path — ignoring and using default."
        )
        return default
    return p


XDG_CONFIG_HOME = _validated_xdg("XDG_CONFIG_HOME", Path.home() / ".config")
XDG_DATA_HOME = _validated_xdg("XDG_DATA_HOME", Path.home() / ".local/share")

# --- RUNTIME PLUGIN DETECTION ---


def discover_plugins():
    plugins = {}
    plugins_dir = PROJECT_ROOT / "plugins"
    if not plugins_dir.exists():
        return plugins

    for path in plugins_dir.iterdir():
        if path.is_dir():
            plugin_file = path / "plugin.py"
            if plugin_file.exists():
                module_name = f"plugins.{path.name}.plugin"
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    try:
                        spec.loader.exec_module(module)
                        if hasattr(module, "Plugin"):
                            plugin_class = getattr(module, "Plugin")
                            plugin_instance = plugin_class()
                            plugins[plugin_instance.name] = plugin_instance
                    except Exception as e:
                        print(
                            f"⚠️ Warning: Failed to load plugin from {plugin_file}: {e}"
                        )
    return plugins


PLUGINS = discover_plugins()

# --- RESOLUTION UTILITIES ---


def find_template(work_dir, plugin_name):
    """Hierarchical resolution of the Dockerfile template."""
    possible_paths = [
        work_dir / f".{plugin_name}-sandbox" / "Dockerfile.template",
        XDG_CONFIG_HOME / f"{plugin_name}-sandbox" / "Dockerfile.template",
        XDG_CONFIG_HOME / "agent-sandbox" / f"{plugin_name}.template",
        XDG_CONFIG_HOME / "opencode-sandbox" / "Dockerfile.template",  # legacy fallback
        PROJECT_ROOT / "plugins" / plugin_name / "Dockerfile.template",
    ]
    for p in possible_paths:
        if p.exists():
            return p
    return None


# --- SIDECAR CONFIG TRUST MODEL ---
#
# Config can come from two classes of location:
#   * TRUSTED   — under the user's own ~/.config (only the user can write here).
#   * UNTRUSTED — inside the workspace directory.  A workspace can be a freshly
#                 cloned repo, so its config is attacker-controlled and is the
#                 very thing the sandbox is meant to contain.
#
# Keys are tiered by blast radius:
#   * SAFE_KEYS       — only affect what happens *inside* the disposable
#                       container (the image contents / in-container env).  A
#                       malicious value can at worst compromise the sandbox,
#                       which is already untrusted, so these are honored from
#                       the workspace file.  This preserves the core feature:
#                       a project declaring the packages / base image it needs.
#   * PRIVILEGED_KEYS — reach *out* of the sandbox and touch the host (bind
#                       mounts, host env forwarding, SSH-agent forwarding).
#                       From a trusted location they apply directly. From a
#                       workspace file they are honored only after explicit
#                       trust-on-first-use approval (see the trust store below);
#                       non-interactively they are denied unless --trust-workspace
#                       is given.
SAFE_KEYS = {"base_image", "install", "set_env"}
PRIVILEGED_KEYS = {"mounts", "forward_env", "ssh_auth_sock", "ports"}

DEFAULT_CFG = {
    "base_image": "opensuse/tumbleweed:latest",
    "install": [],
    "mounts": [],
    "forward_env": [],
    "set_env": {},
    "ssh_auth_sock": False,
    "ports": [],
}


def _trusted_config_paths(plugin_name):
    """Trusted sidecar locations under the user's own config dir.

    Ordered least-specific first so that more specific files applied later win
    (general config.json < plugin-specific files).
    """
    return [
        XDG_CONFIG_HOME / "agent-sandbox" / "config.json",
        XDG_CONFIG_HOME / f"{plugin_name}-sandbox" / "config.json",
        XDG_CONFIG_HOME / "agent-sandbox" / f"{plugin_name}.json",
    ]


def _workspace_config_path(work_dir, plugin_name):
    """The (untrusted) workspace sidecar location, first match wins."""
    possible = [
        work_dir / f".{plugin_name}-sandbox" / "config",
        work_dir / f".{plugin_name}-sandbox" / "config.json",
        work_dir / f".{plugin_name}-sandbox.json",
        work_dir / ".agent-sandbox.json",
    ]
    for p in possible:
        if p.exists():
            return p
    return None


def _read_json_config(path):
    """Read and JSON-parse a config file; return {} and warn on failure."""
    try:
        with open(path, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            print(
                f"⚠️ Warning: Ignoring config {path}: top-level value must be an object."
            )
            return {}
        return data
    except Exception as e:
        print(f"⚠️ Warning: Failed to parse config {path}: {e}")
        return {}


# --- WORKSPACE TRUST STORE (TOFU, per-item) ---
#
# Privileged keys (mounts/forward_env/ssh_auth_sock) reach the host. They are
# never honored from a workspace file *unless the user explicitly approves them*.
#
# Approval is trust-on-first-use at the granularity of an individual ITEM (each
# mount entry, each forward_env name, the ssh_auth_sock flag). The trust store
# maps a workspace config path to the set of approved item fingerprints:
#
#     { "/path/to/.agent-sandbox.json": ["<sha256>", "<sha256>", ...] }
#
# On each run we honor items already in the set, prompt only for NEW items, and
# prune the set to exactly the items present-and-approved this run. Consequences:
#   * Adding or changing an item prompts only for that item.
#   * Removing an item never prompts (it is a reduced privilege)…
#   * …but it drops that item from the store, so RE-introducing it later prompts
#     again — a revoked privilege cannot silently come back.


def _trust_store_path():
    return XDG_CONFIG_HOME / "agent-sandbox" / "trusted_workspaces.json"


def _privileged_subset(cfg):
    """The privileged-only view of a config."""
    return {k: cfg[k] for k in sorted(PRIVILEGED_KEYS) if k in cfg}


def _privileged_items(priv_subset):
    """Decompose a privileged subset into individual, independently-trustable items.

    Privileged keys are list-valued (``mounts``, ``forward_env``) or a single
    boolean (``ssh_auth_sock``). Each *element* is its own item so that adding,
    removing, or changing a single element only affects that element's trust.
    Duplicate elements (e.g. ``forward_env: ["A", "A"]``) naturally collapse to
    one fingerprint, which is correct: trusting "forward A" covers all of them.

    Precondition: ``priv_subset`` must already have passed
    ``_validate_sidecar_cfg`` (every mount is a dict with 'host'/'container',
    forward_env is a list of strings, etc.). This relies on that invariant and
    does not re-check shapes; do not call it with unvalidated config.

    Returns a list of (label, fingerprint) tuples in display order.
    """
    items = []

    def fp(kind, value):
        canonical = json.dumps([kind, value], sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    for m in priv_subset.get("mounts", []):
        label = f"bind-mount host path '{m['host']}'  →  container '{m['container']}'"
        items.append((label, fp("mount", m)))

    for env in priv_subset.get("forward_env", []):
        label = f"forward host environment variable '{env}' into the container"
        items.append((label, fp("forward_env", env)))

    for p in priv_subset.get("ports", []):
        label = f"forward container port to host '{p}'"
        items.append((label, fp("port", p)))

    if priv_subset.get("ssh_auth_sock"):
        items.append(
            ("forward your SSH agent socket into the container", fp("ssh_auth_sock", True))
        )

    return items


def _trust_key(config_path):
    """Identity for an approval entry: the resolved workspace config file path."""
    return str(Path(config_path).resolve())


def _load_trust_store():
    p = _trust_store_path()
    if not p.exists():
        return {}
    try:
        with open(p, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_trust_store(store):
    p = _trust_store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    # Owner-only: the approval list reveals which configs were trusted.
    tmp = p.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(store, indent=2))
    tmp.replace(p)
    try:
        p.chmod(0o600)
    except OSError:
        pass


def _load_approved_fingerprints(config_path):
    """The set of individually-approved item fingerprints for a config path."""
    entry = _load_trust_store().get(_trust_key(config_path))
    if isinstance(entry, list):
        return set(entry)
    return set()


def _store_approved_fingerprints(config_path, fingerprints):
    """Persist the approved item fingerprints for a config path (or drop the entry)."""
    store = _load_trust_store()
    key = _trust_key(config_path)
    if fingerprints:
        store[key] = sorted(fingerprints)
    else:
        store.pop(key, None)
    _save_trust_store(store)


def _forget_workspace_trust(config_path):
    store = _load_trust_store()
    if store.pop(_trust_key(config_path), None) is not None:
        _save_trust_store(store)
        return True
    return False


def _resolve_privileged_trust(
    config_path, priv_subset, trust_flag, debug=False, dry_run=False
):
    """Return the set of approved item fingerprints to honor for this config.

    Per-item trust-on-first-use:
      * Items whose fingerprint is already stored are honored without a prompt.
      * Only items NOT yet approved trigger a prompt (or are granted by
        --trust-workspace). Approving adds just those items to the store.
      * The stored set is pruned to exactly the items present-and-approved this
        run, so REMOVING an item revokes its approval and RE-ADDING it later
        re-prompts (a reduced privilege never re-prompts; a re-introduced one
        does).

    Under --dry-run nothing is persisted (preview must be side-effect-free):
    already-approved items are honored, not-yet-approved items are shown but
    treated as denied for the preview.

    Returns the set of fingerprints that should be honored this run.
    """
    items = _privileged_items(priv_subset)
    all_fps = {fp for _, fp in items}
    previously_approved = _load_approved_fingerprints(config_path)

    already = {fp for fp in all_fps if fp in previously_approved}
    new_items = [(label, fp) for (label, fp) in items if fp not in previously_approved]

    def _describe(item_list):
        return "\n".join(f"    • {label}" for label, _ in item_list)

    # Nothing new to approve: honor the already-approved items. Prune the store
    # to the currently-present approved set (drops removed items).
    if not new_items:
        if not dry_run:
            _store_approved_fingerprints(config_path, already)
        if debug and already:
            print(
                f"DEBUG: all requested privileged items previously approved for {config_path}"
            )
        return already

    requested = _describe(new_items)

    # --trust-workspace: grant the new items explicitly.
    if trust_flag:
        granted = already | {fp for _, fp in new_items}
        if dry_run:
            # Preview WITH the items honored (so the previewed command reflects
            # what --trust-workspace would do), but do not persist the approval.
            print(
                f"ℹ️  [dry-run] Would trust new workspace privileged item(s) "
                f"(per --trust-workspace):\n{requested}"
            )
            return granted
        _store_approved_fingerprints(config_path, granted)
        print(
            f"✅ Trusting new workspace privileged item(s) (per --trust-workspace):\n{requested}"
        )
        return granted

    # Dry-run, not pre-approved: show but do not prompt/persist.
    if dry_run:
        print(
            "ℹ️  [dry-run] Workspace requests host-level access not yet trusted; "
            "it would be prompted for on a real run. Showing command WITHOUT it:\n"
            f"{requested}"
        )
        return already

    # Interactive consent only if we actually have a terminal to ask at.
    if sys.stdin.isatty() and sys.stdout.isatty():
        print(
            "\n⚠️  This workspace's config requests NEW host-level access from inside the sandbox:\n"
            f"{requested}\n"
            f"   Source: {config_path}\n"
            "   These reach OUT of the sandbox to your host. Only approve if you trust this workspace."
        )
        try:
            answer = (
                input("   Trust this workspace and grant the above? [y/N]: ")
                .strip()
                .lower()
            )
        except (EOFError, KeyboardInterrupt):
            print("\n   No response — denying.")
            # Persist pruning of removed items even on denial of new ones.
            _store_approved_fingerprints(config_path, already)
            return already
        if answer in ("y", "yes"):
            granted = already | {fp for _, fp in new_items}
            _store_approved_fingerprints(config_path, granted)
            print("   Approved and remembered (will re-ask if the request changes).")
            return granted
        print("   Denied — new privileged items ignored for this run.")
        _store_approved_fingerprints(config_path, already)
        return already

    # Non-interactive and not explicitly trusted: deny the new items by default.
    labels = ", ".join(label for label, _ in new_items)
    print(
        f"⚠️  SECURITY: workspace config {config_path} requests new host-level access "
        f"({labels}) but no terminal is available to confirm. "
        f"Ignoring those item(s). Re-run interactively or pass --trust-workspace to approve."
    )
    if not dry_run:
        _store_approved_fingerprints(config_path, already)
    return already


def _filter_priv_subset_by_fingerprints(priv_subset, approved_fps):
    """Rebuild a privileged subset containing only individually-approved items.

    Built from the *current* config (preserving element order and duplicates),
    keeping only elements whose fingerprint is in ``approved_fps``.

    Precondition: ``priv_subset`` must already have passed
    ``_validate_sidecar_cfg`` (same shape invariant as ``_privileged_items``).
    """

    def fp(kind, value):
        canonical = json.dumps([kind, value], sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    result = {}

    mounts = [m for m in priv_subset.get("mounts", []) if fp("mount", m) in approved_fps]
    if mounts:
        result["mounts"] = mounts

    envs = [
        e for e in priv_subset.get("forward_env", []) if fp("forward_env", e) in approved_fps
    ]
    if envs:
        result["forward_env"] = envs

    ports = [
        p for p in priv_subset.get("ports", []) if fp("port", p) in approved_fps
    ]
    if ports:
        result["ports"] = ports

    if priv_subset.get("ssh_auth_sock") and fp("ssh_auth_sock", True) in approved_fps:
        result["ssh_auth_sock"] = True

    return result


def _merge_config(dest, src):
    """Perform a deep-ish merge of src into dest for specific config keys."""
    for k, v in src.items():
        if k in ("install", "mounts", "forward_env", "ports"):
            if k not in dest or not isinstance(dest[k], list):
                dest[k] = []
            if isinstance(v, list):
                for item in v:
                    if item not in dest[k]:
                        dest[k].append(item)
        elif k == "set_env":
            if k not in dest or not isinstance(dest[k], dict):
                dest[k] = {}
            if isinstance(v, dict):
                dest[k].update(v)
        else:
            # Flat keys like base_image, ssh_auth_sock are simply overwritten
            dest[k] = v


def load_sidecar_config(
    work_dir, plugin_name, debug=False, trust_flag=False, dry_run=False
):
    """Resolve sidecar configuration using the trust-tiered model.

    Layering (lowest precedence first):
      1. built-in defaults
      2. trusted config from ~/.config  (ALL keys honored)
      3. workspace config               (SAFE_KEYS honored; PRIVILEGED_KEYS only
                                          honored if the user approves them via
                                          trust-on-first-use)
    """
    # Deep copy the defaults so that modifying lists/dicts during merge
    # does not mutate the global DEFAULT_CFG.
    cfg = {
        "base_image": DEFAULT_CFG["base_image"],
        "install": list(DEFAULT_CFG["install"]),
        "mounts": list(DEFAULT_CFG["mounts"]),
        "forward_env": list(DEFAULT_CFG["forward_env"]),
        "set_env": dict(DEFAULT_CFG["set_env"]),
        "ssh_auth_sock": DEFAULT_CFG["ssh_auth_sock"],
        "ports": list(DEFAULT_CFG["ports"]),
    }

    # 2. Trusted layer — user-owned, all keys allowed.
    for tp in _trusted_config_paths(plugin_name):
        if tp.exists():
            trusted = _read_json_config(tp)
            if trusted:
                try:
                    _validate_sidecar_cfg(trusted, allow_privileged=True)
                except ValueError as e:
                    print(f"❌ Error: Invalid trusted config in {tp}: {e}")
                    sys.exit(1)
                _merge_config(cfg, trusted)
                if debug:
                    print(f"📦 Loaded trusted config: {tp}")

    # 3. Workspace layer — untrusted.
    wp = _workspace_config_path(work_dir, plugin_name)
    if wp:
        workspace = _read_json_config(wp)
        if workspace:
            # Validate the whole workspace dict (type checks for all keys).
            try:
                _validate_sidecar_cfg(workspace, allow_privileged=True)
            except ValueError as e:
                print(f"❌ Error: Invalid workspace config in {wp}: {e}")
                sys.exit(1)

            unknown = sorted(
                k for k in workspace if k not in SAFE_KEYS and k not in PRIVILEGED_KEYS
            )
            if unknown and debug:
                print(
                    f"DEBUG: Ignoring unknown key(s) in workspace config: {', '.join(unknown)}"
                )

            # Safe keys: always honored.
            safe_subset = {k: v for k, v in workspace.items() if k in SAFE_KEYS}
            _merge_config(cfg, safe_subset)

            # Privileged keys: honored per-item, only for items the user has
            # approved (trust-on-first-use). _resolve_privileged_trust handles
            # prompting for new items, pruning removed ones, and persistence
            # (subject to --dry-run). We then merge in only the approved items.
            priv_subset = _privileged_subset(workspace)
            if priv_subset:
                approved_fps = _resolve_privileged_trust(
                    wp, priv_subset, trust_flag, debug=debug, dry_run=dry_run
                )
                honored = _filter_priv_subset_by_fingerprints(priv_subset, approved_fps)
                if honored:
                    _merge_config(cfg, honored)
            else:
                # No privileged keys currently requested. Drop any stored
                # approvals for this config so that re-introducing a privileged
                # item later forces a fresh prompt. (Persistence skipped under
                # --dry-run to keep previews side-effect-free.)
                if not dry_run:
                    _forget_workspace_trust(wp)


            if debug:
                print(f"📦 Loaded workspace config: {wp}")

    return cfg


def _validate_sidecar_cfg(cfg, allow_privileged=True):
    """Validate sidecar config values to prevent injection / type errors.

    Only keys actually present in ``cfg`` are validated, so this works for both
    a full trusted config and a safe-key-only workspace subset.

    ``allow_privileged`` is a defensive guard: when False, the presence of any
    PRIVILEGED_KEYS is itself an error (the caller should have stripped them).

    Raises ValueError with a human-readable message on any violation.
    """
    if not allow_privileged:
        present_priv = PRIVILEGED_KEYS & set(cfg)
        if present_priv:
            raise ValueError(
                f"privileged key(s) {', '.join(sorted(present_priv))} are not allowed here"
            )

    # NOTE on SAFE keys (base_image, install, set_env): these only affect the
    # disposable container, which is already untrusted, so we do NOT police
    # their *contents* for security. We only type-check them so the rest of the
    # script doesn't crash, plus one build-correctness guard on base_image
    # (it is interpolated unquoted into `FROM <base_image>`, so a newline there
    # would silently inject a broken Dockerfile instruction). Shell-injection in
    # `install` is already neutralized by shlex.quote() at render time.

    # base_image (SAFE): just needs to be a single-line string.
    if "base_image" in cfg:
        base_image = cfg["base_image"]
        if not isinstance(base_image, str):
            raise ValueError("'base_image' must be a string.")
        if "\n" in base_image or "\r" in base_image:
            raise ValueError("'base_image' must not contain newlines.")

    # install (SAFE): just needs to be a list of strings.
    if "install" in cfg:
        install = cfg["install"]
        if not isinstance(install, list) or not all(
            isinstance(p, str) for p in install
        ):
            raise ValueError("'install' must be a list of strings.")

    # set_env (SAFE): dict of string → string.
    if "set_env" in cfg:
        set_env = cfg["set_env"]
        if not isinstance(set_env, dict):
            raise ValueError("'set_env' must be an object.")
        for k, v in set_env.items():
            if not isinstance(k, str) or not isinstance(v, str):
                raise ValueError("'set_env' keys and values must all be strings.")

    # mounts (PRIVILEGED): list of dicts with 'host' and 'container' keys.
    if "mounts" in cfg:
        mounts = cfg["mounts"]
        if not isinstance(mounts, list):
            raise ValueError("'mounts' must be a list.")
        for m in mounts:
            if not isinstance(m, dict):
                raise ValueError(
                    "Each entry in 'mounts' must be an object with 'host' and 'container' keys."
                )
            if "host" not in m or "container" not in m:
                raise ValueError("Each mount must have 'host' and 'container' keys.")

    # forward_env (PRIVILEGED): list of strings.
    if "forward_env" in cfg:
        forward_env = cfg["forward_env"]
        if not isinstance(forward_env, list) or not all(
            isinstance(e, str) for e in forward_env
        ):
            raise ValueError("'forward_env' must be a list of strings.")

    # ports (PRIVILEGED): list of strings (e.g. "8501:8501" or "8501")
    if "ports" in cfg:
        ports = cfg["ports"]
        if not isinstance(ports, list) or not all(isinstance(p, str) for p in ports):
            raise ValueError("'ports' must be a list of strings.")
        for p in ports:
            if not re.fullmatch(r"([0-9]+:)?([0-9]+)", p):
                raise ValueError(f"Invalid port mapping format: {p!r}. Expected format: 'host_port:container_port' or 'container_port'.")
            parts = p.split(":")
            for part in parts:
                port_val = int(part)
                if port_val < 1 or port_val > 65535:
                    raise ValueError(f"Port value {port_val} out of range (1-65535) inside mapping: {p!r}")

    # ssh_auth_sock (PRIVILEGED): boolean.
    if "ssh_auth_sock" in cfg:
        if not isinstance(cfg["ssh_auth_sock"], bool):
            raise ValueError("'ssh_auth_sock' must be a boolean.")


def _validate_container_path(path_str, source="sidecar"):
    """Validate and normalise a container-side mount destination.

    Requires an absolute path and returns its normalised form. Interior '..'
    segments in an absolute path are resolved by normalisation (they cannot
    escape '/', e.g. '/home/../etc' -> '/etc'), so the result is always a
    concrete absolute path. Relative paths and empty strings are rejected.
    """
    if not path_str or not path_str.startswith("/"):
        raise ValueError(
            f"Container mount path from {source} must be an absolute path, got: {path_str!r}"
        )
    normalised = os.path.normpath(path_str)
    # Defensive: an absolute path cannot retain leading '..' after normpath,
    # but guard anyway in case of unusual inputs.
    if ".." in normalised.split(os.sep):
        raise ValueError(
            f"Container mount path from {source} contains '..' traversal: {path_str!r}"
        )
    return normalised


def _looks_like_secret_env(name):
    """Heuristic: does this environment variable name look like a secret?

    forward_env now comes either from trusted config or from a workspace file
    the user has explicitly approved, so this is a secondary "did you really
    mean to?" sanity check, not the primary defense (that is the trust prompt).
    """
    upper = name.upper()
    needles = (
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "APIKEY",
        "API_KEY",
        "ACCESS_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
        "AUTH",
    )
    return any(n in upper for n in needles)


def _warn_if_sensitive_host_mount(host_path, source="sidecar"):
    """Print a warning if a host path being bind-mounted is security-sensitive.

    Mounts come from trusted config, an explicit --include-dir, or a workspace
    file the user has approved via the trust prompt, so this is a secondary
    "are you sure?" sanity check rather than the primary defense.
    """
    try:
        resolved = Path(host_path).expanduser().resolve()
    except Exception:
        return
    home = Path.home().resolve()
    sensitive_names = {
        ".ssh",
        ".aws",
        ".gnupg",
        ".config",
        ".kube",
        ".docker",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
    }
    is_sensitive = False
    reason = ""
    # Mounting the filesystem root or the entire home directory
    if resolved == Path(resolved.anchor):
        is_sensitive, reason = True, "the entire filesystem root"
    elif resolved == home:
        is_sensitive, reason = True, "your entire home directory"
    else:
        # Any path whose first component under $HOME is a known-sensitive dir
        try:
            rel_parts = resolved.relative_to(home).parts
            if rel_parts and rel_parts[0] in sensitive_names:
                is_sensitive, reason = True, f"a sensitive location (~/{rel_parts[0]})"
        except ValueError:
            pass  # not under home
    if is_sensitive:
        print(
            f"⚠️  SECURITY WARNING: {source} is bind-mounting {reason} "
            f"({resolved}) into the sandbox. Anything running inside the container "
            f"will have access to it. Only proceed if you trust this config."
        )


def doctor_check(template_path):
    """Verify the environment is sane."""
    try:
        subprocess.run(["podman", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Error: 'podman' not found. Please install it first.")
        sys.exit(1)

    if not template_path:
        print("❌ Error: Dockerfile.template not found in any resolved locations.")
        sys.exit(1)


def get_workspace_hash(path):
    """Generates a unique short hash based on the absolute path.

    Uses SHA-256 (truncated to 12 hex chars / 48 bits) instead of MD5.
    MD5 is cryptographically broken and its 8-char truncation left only
    32 bits of collision space — trivially exhaustible by birthday attack.
    """
    return hashlib.sha256(str(path.resolve()).encode()).hexdigest()[:12]


def get_legacy_workspace_hash(path):
    """DEPRECATED: the pre-SHA-256 workspace hash (MD5, 8 chars).

    Only used to locate and migrate session data created before the switch to
    SHA-256.  Do not use for anything new.  Safe to remove once enough time has
    passed that no legacy ``ws-<md5>`` directories remain in the wild
    (target removal: a couple of releases after the SHA-256 switch).
    """
    return hashlib.md5(str(path.resolve()).encode()).hexdigest()[:8]


def migrate_legacy_workspace_dir(xdg_data, work_dir):
    """Move a legacy MD5-named session dir to its SHA-256 name, if needed.

    Returns the path to the (current) SHA-256 meta dir. The image tag is not
    migrated, so the first run after an upgrade may rebuild the image once;
    session/state data under the meta dir is preserved.
    """
    new_dir = xdg_data / f"ws-{get_workspace_hash(work_dir)}"
    old_dir = xdg_data / f"ws-{get_legacy_workspace_hash(work_dir)}"

    if not old_dir.exists() or old_dir == new_dir:
        return new_dir

    # Consider the new dir "already migrated" only if it actually holds data.
    # A stale, empty new dir (e.g. left by a crashed earlier run) must not
    # cause us to silently strand the populated legacy dir.
    new_has_data = new_dir.exists() and any(new_dir.iterdir())
    if new_has_data:
        print(
            f"⚠️ Warning: Found legacy session dir {old_dir.name} but {new_dir.name} "
            f"already contains data; leaving the legacy dir in place (not merging). "
            f"You can remove {old_dir} manually if it is no longer needed."
        )
        return new_dir

    # If an empty new dir exists, drop it so rename can take the name.
    if new_dir.exists():
        try:
            new_dir.rmdir()  # only succeeds if empty — intentional
        except OSError as e:
            print(
                f"⚠️ Warning: Could not clear stale {new_dir.name} before migration: {e}"
            )
            return new_dir

    print(f"🔄 Upgrading workspace hash namespace: {old_dir.name} ➔ {new_dir.name}")
    try:
        old_dir.rename(new_dir)
    except Exception as e:
        print(f"⚠️ Warning: Failed to migrate legacy workspace meta directory: {e}")
    return new_dir


# --- MAIN ORCHESTRATOR ---


def main():
    if not PLUGINS:
        print("❌ Error: No plugins discovered inside the plugins/ directory.")
        sys.exit(1)

    # Auto-detect default plugin from executable/symlink name.
    # Fall back to the first discovered plugin rather than the hardcoded
    # string "opencode", which would cause a KeyError if the opencode plugin
    # failed to load.
    exec_name = Path(sys.argv[0]).name
    default_plugin = next(iter(PLUGINS))  # first available plugin
    for name in PLUGINS:
        if name in exec_name:
            default_plugin = name
            break

    parser = argparse.ArgumentParser(description="Agent Sandbox (Podman + openSUSE)")
    parser.add_argument(
        "--plugin",
        "-p",
        choices=list(PLUGINS.keys()),
        default=default_plugin,
        help="The sandbox plugin to launch",
    )
    parser.add_argument("--rebuild", action="store_true", help="Force image rebuild")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show command without running"
    )
    parser.add_argument("--debug", action="store_true", help="Show debug information")
    parser.add_argument("--root", action="store_true", help="Run container as root")
    parser.add_argument(
        "--update",
        action="store_true",
        help="Check for and install updates for the plugin",
    )
    parser.add_argument(
        "--include-dir",
        action="append",
        help="Include additional directory in /mnt (HostPath:ContainerPath or just HostPath)",
    )
    parser.add_argument(
        "--trust-workspace",
        action="store_true",
        help="Approve privileged keys (mounts/forward_env/ssh_auth_sock) in this workspace's config without prompting, and remember the approval",
    )
    parser.add_argument(
        "--forget-workspace-trust",
        action="store_true",
        help="Forget any remembered trust approval for this workspace's config, then exit",
    )
    parser.add_argument(
        "cmd_args",
        nargs=argparse.REMAINDER,
        help="Arguments to pass to the plugin tool",
    )
    args = parser.parse_args()

    plugin = PLUGINS[args.plugin]

    # 1. Resolve Paths & Configuration
    work_dir = Path.cwd().resolve()

    # Handle --forget-workspace-trust early: clear any remembered approval for
    # this workspace's config and exit, without needing podman or a build.
    if args.forget_workspace_trust:
        wp = _workspace_config_path(work_dir, plugin.name)
        if wp and _forget_workspace_trust(wp):
            print(f"🗑️  Forgot workspace trust approval for: {wp}")
        else:
            print("ℹ️  No workspace trust approval was stored for this workspace.")
        sys.exit(0)

    # Resolve Dockerfile template
    template_path = find_template(work_dir, plugin.name)
    doctor_check(template_path)

    # Namespaces
    xdg_config = XDG_CONFIG_HOME / plugin.host_config_subdir
    xdg_data = XDG_DATA_HOME / plugin.host_data_subdir

    # Seamless migration of legacy (MD5-named) session data to the SHA-256
    # name. Preserves session/state under the meta dir; the image tag is not
    # migrated, so the first post-upgrade run may rebuild the image once.
    ws_meta_dir = migrate_legacy_workspace_dir(xdg_data, work_dir)
    ws_hash = get_workspace_hash(work_dir)
    ws_config_dir = ws_meta_dir / "config"
    ws_run_dir = ws_meta_dir / "run"

    # Pre-create host dirs with correct permissions
    ws_meta_dir.mkdir(parents=True, exist_ok=True)
    ws_config_dir.mkdir(parents=True, exist_ok=True)
    ws_run_dir.mkdir(parents=True, exist_ok=True)
    xdg_config.mkdir(parents=True, exist_ok=True)

    # Let the plugin dynamically initialize its own folders, files, and migrations
    plugin.initialize(ws_meta_dir, xdg_config)

    # Load sidecar configuration
    cfg = load_sidecar_config(
        work_dir,
        plugin.name,
        debug=args.debug,
        trust_flag=args.trust_workspace,
        dry_run=args.dry_run,
    )
    template_content = template_path.read_text()

    # Render Dockerfile
    dockerfile_content = template_content.format(
        base_image=cfg.get("base_image", "opensuse/tumbleweed:latest"),
        extra_packages=" ".join(shlex.quote(p) for p in cfg.get("install", [])),
    )

    if args.dry_run or args.debug:
        print(f"--- RESOLVED TEMPLATE: {template_path.resolve()} ---")
        print(
            f"--- GENERATED DOCKERFILE ---\n{dockerfile_content}\n----------------------------"
        )

    # 2. Image Versioning — use SHA-256 (not MD5) with a 12-char prefix for
    # sufficient collision resistance (48 bits vs the original 32 bits).
    #
    # The image identity is derived ONLY from dockerfile_content, which already
    # bakes in the only image-relevant config (base_image + install). We must
    # NOT mix the rest of cfg into the hash: mounts/forward_env/set_env/
    # ssh_auth_sock are runtime `podman run` flags that never affect the built
    # image. Including them (as earlier versions did) made the tag flip whenever
    # a workspace's privileged keys were approved vs. denied, forcing pointless
    # rebuilds. Keying on dockerfile_content keeps the tag stable across trust
    # decisions.
    content_hash = hashlib.sha256(dockerfile_content.encode()).hexdigest()[:12]
    image_tag = f"localhost/{plugin.image_prefix}:{ws_hash}-{content_hash}"

    image_check = subprocess.run(
        ["podman", "images", "-q", image_tag], capture_output=True
    ).stdout

    tool_version = "latest"
    if args.update:
        if not image_check:
            print(f"ℹ️ Workspace image does not exist yet — building fresh which installs the latest version.")
            args.rebuild = True
        else:
            latest_v = plugin.get_latest_version(debug=args.debug)
            if not latest_v:
                print(f"⚠️ Skipping update: Could not fetch latest version info for {plugin.name}.")
            else:
                try:
                    current_v = plugin.get_installed_version(None, image_tag)
                    if version_tuple(current_v) >= version_tuple(latest_v):
                        print(f"✅ {plugin.name} is already up to date (v{current_v}).")
                    else:
                        print(f"🔄 Upgrading {plugin.name}: v{current_v} -> v{latest_v}...")
                        tool_version = latest_v
                        args.rebuild = True
                except Exception as e:
                    print(f"⚠️ Warning: Could not verify versions: {e}. Rebuilding to ensure latest version.")
                    args.rebuild = True

    # Check if this is the first run for this workspace
    init_file = ws_meta_dir / ".initialized"
    is_first_run = not init_file.exists()

    if not image_check or args.rebuild:
        print(f"🔨 Building workspace image: {image_tag}")
        df_path = ws_meta_dir / "Dockerfile"
        df_path.write_text(dockerfile_content)
        
        # Reset first-run status on a new build or update so migrations can run/warn again
        if init_file.exists():
            try:
                init_file.unlink()
                is_first_run = True
            except OSError:
                pass

        try:
            # Use ws_meta_dir as the build context instead of CWD ('.').
            # CWD is the user's project workspace; passing it as context sends
            # potentially gigabytes of source files to the Podman build daemon
            # and could allow unintended COPY/ADD instructions to pick up
            # workspace files.  The generated Dockerfile lives in ws_meta_dir
            # and needs no files from outside it.
            subprocess.run(
                [
                    "podman",
                    "build",
                    "-t",
                    image_tag,
                    "-f",
                    str(df_path),
                    "--build-arg",
                    f"TOOL_VERSION={tool_version}",
                    str(ws_meta_dir),
                ],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"❌ Error: 'podman build' failed for {image_tag}")
            sys.exit(e.returncode)

    # 3. Execute Sandbox Setup
    internal_home = "/home/developer"
    podman_cmd = [
        "podman",
        "run",
        "-it",
        "--rm",
        "--name",
        f"{plugin.container_prefix}-{ws_hash}-{int(datetime.now().timestamp())}",
        "--userns=keep-id",
        "--env",
        f"XDG_RUNTIME_DIR={plugin.internal_data_dir}/run",
        "--workdir",
        "/workspace",
        "-v",
        f"{work_dir}:/workspace:Z",
        "-v",
        f"{ws_config_dir}:{plugin.internal_config_dir}:Z",
        "-v",
        f"{ws_meta_dir}:{plugin.internal_data_dir}:Z",
    ]

    # Let the plugin append its own configuration mounts
    plugin.mount_config(podman_cmd, ws_meta_dir, xdg_config, internal_home)

    # Add custom mounts from sidecar
    for m in cfg.get("mounts", []):
        try:
            host_p = Path(m["host"]).expanduser().resolve()
            cont_p = _validate_container_path(m["container"], source="sidecar")
            _warn_if_sensitive_host_mount(host_p, source="sidecar config")
            podman_cmd.extend(["-v", f"{host_p}:{cont_p}:Z"])
        except (KeyError, ValueError) as e:
            print(f"❌ Error: Invalid mount configuration: {e}")
            sys.exit(1)

    # Forward generic environment variables declared in sidecar
    for env_var in cfg.get("forward_env", []):
        if env_var in os.environ:
            if _looks_like_secret_env(env_var):
                print(
                    f"⚠️  Note: forwarding host env var '{env_var}' (looks like a "
                    f"credential) into the sandbox."
                )
            podman_cmd.extend(["--env", f"{env_var}={os.environ[env_var]}"])
        elif args.debug:
            print(
                f"DEBUG: '{env_var}' requested in forward_env but not set on the host."
            )

    # Set static environment variables declared in sidecar
    for k, v in cfg.get("set_env", {}).items():
        podman_cmd.extend(["--env", f"{k}={v}"])

    # Add port mappings from sidecar (optional, specified in sidecar)
    for port_mapping in cfg.get("ports", []):
        podman_cmd.extend(["-p", port_mapping])

    # Secure SSH Agent Forwarding (optional, specified in sidecar)
    if cfg.get("ssh_auth_sock", False):
        host_ssh_sock = os.environ.get("SSH_AUTH_SOCK")
        if host_ssh_sock and Path(host_ssh_sock).exists():
            container_ssh_sock = "/tmp/ssh-agent.sock"
            podman_cmd.extend(
                [
                    "-v",
                    f"{host_ssh_sock}:{container_ssh_sock}:Z",
                    "--env",
                    f"SSH_AUTH_SOCK={container_ssh_sock}",
                ]
            )
        elif args.debug:
            print(
                "DEBUG: ssh_auth_sock enabled in config, but SSH_AUTH_SOCK is not set or valid on the host."
            )

    # Add extra directories from CLI
    if args.include_dir:
        for inc in args.include_dir:
            if ":" in inc:
                h_p, c_p = inc.split(":", 1)
                h_p = Path(h_p).expanduser().resolve()
                try:
                    c_p = _validate_container_path(c_p, source="--include-dir")
                except ValueError as e:
                    print(f"❌ Error: {e}")
                    sys.exit(1)
                _warn_if_sensitive_host_mount(h_p, source="--include-dir")
                podman_cmd.extend(["-v", f"{h_p}:{c_p}:Z"])
            else:
                h_p = Path(inc).expanduser().resolve()
                _warn_if_sensitive_host_mount(h_p, source="--include-dir")
                podman_cmd.extend(["-v", f"{h_p}:/mnt/{h_p.name}:Z"])

    if args.root:
        podman_cmd.extend(["--user", "root"])

    # Normal Execution
    podman_cmd.append(image_tag)

    # Wrap target command in login shell and private D-Bus session.
    # shlex.quote() is applied to every argument unconditionally so that
    # shell metacharacters (backticks, $(), ;, &&, |, quotes …) cannot
    # break out of the argument boundary and execute on the host.
    target_cmd = args.cmd_args if args.cmd_args else plugin.default_cmd
    cmd_str = " ".join(shlex.quote(arg) for arg in target_cmd)

    wrapped_cmd = ["/bin/bash", "--login", "-c", f"dbus-run-session -- {cmd_str}"]
    podman_cmd.extend(wrapped_cmd)

    if args.dry_run:
        print(f"\n[DRY RUN] Command:\n{' '.join(podman_cmd)}\n")
    else:
        print(
            f"🚀 Sandbox Active | Plugin: {plugin.name} | Project: {work_dir.name} ({ws_hash})"
        )
        if is_first_run and plugin.first_run_message:
            print(plugin.first_run_message)
            try:
                init_file.touch(exist_ok=True)
            except OSError:
                pass
        if args.debug:
            print(f"DEBUG: podman_cmd={' '.join(podman_cmd)}")
        subprocess.run(podman_cmd)


if __name__ == "__main__":
    main()
