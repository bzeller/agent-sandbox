import urllib.request
import subprocess
import json
import re


def version_tuple(v):
    """Parse a version string into a comparable tuple of ints.

    A single leading 'v'/'V' and pre-release/build suffixes (e.g. '-beta.1',
    '+build.5') are stripped, so 'v1.2.3' and '1.2.3-beta' both parse to
    (1, 2, 3). Parsing stops at the first non-numeric dotted component so that
    e.g. '1.2.x' -> (1, 2) rather than silently skipping the bad part. An empty
    or entirely non-numeric version returns (0,) so any real version compares
    greater.
    """
    if not v or not isinstance(v, str):
        return (0,)
    s = v.strip()
    # Strip a single leading version marker.
    if s[:1] in ("v", "V"):
        s = s[1:]
    # Drop pre-release / build-metadata suffixes.
    s = re.split(r"[-+]", s, maxsplit=1)[0]
    parts = []
    for component in s.split("."):
        if component.isdigit():
            parts.append(int(component))
        else:
            break  # stop at first non-numeric component
    if not parts:
        return (0,)
    return tuple(parts)


class BasePlugin:
    name = ""
    github_repo = None
    first_run_message = None

    host_config_subdir = ""
    host_data_subdir = ""
    image_prefix = ""
    container_prefix = ""

    default_cmd = []
    internal_config_dir = ""
    internal_data_dir = ""

    shared_config_dirs = []
    shared_config_files = []

    def get_latest_version(self, debug=False):
        if not self.github_repo:
            return None
        # Validate github_repo is in the form "owner/repo" before building URL
        if not re.fullmatch(r"[a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+", self.github_repo):
            print(f"⚠️ Warning: Plugin '{self.name}' has an invalid github_repo value: {self.github_repo!r}")
            return None
        url = f"https://api.github.com/repos/{self.github_repo}/releases/latest"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "agent-sandbox-cli"})
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                latest = data.get("tag_name", "").lstrip("v")
                if debug:
                    print(f"DEBUG [{self.name}]: Latest version on GitHub: v{latest}")
                return latest
        except Exception as e:
            print(f"⚠️ Warning: Could not check for latest version of {self.name}: {e}")
        return None

    # Flags that consume the following argv token (value-taking options) which
    # must be dropped together with their value when sanitising podman_cmd for
    # a one-shot helper container.
    _VALUE_FLAGS = {"--name"}
    # Boolean flags to drop entirely from a one-shot helper command.
    _SKIP_FLAGS = {"-it", "-i", "-t", "--rm"}

    def _sanitise_podman_cmd(self, podman_cmd, drop_mounts=False):
        """Return a copy of podman_cmd suitable for a one-shot helper container.

        The main podman_cmd is built for an interactive session and contains
        '-it', '--rm', a unique '--name <value>', and the workspace '-v' mounts.
        Reusing it verbatim for a helper run causes problems:
          - '-it' breaks subprocess.run(capture_output=True) (no TTY)
          - a second '--name' added by the caller collides with the existing
            one (podman rejects duplicate --name)
          - '--rm' destroys the container before it can be committed

        Parameters
        ----------
        drop_mounts:
            When True, '-v'/'--volume' bind mounts are removed.  This is used
            for `run_update` so the install script's writes land in the image
            layer being committed rather than in a (never-committed) bind mount.
        """
        result = []
        i = 0
        n = len(podman_cmd)
        while i < n:
            token = podman_cmd[i]
            if token in self._SKIP_FLAGS:
                i += 1
                continue
            if token in self._VALUE_FLAGS:
                i += 2  # skip the flag and its value
                continue
            if drop_mounts and token in ("-v", "--volume"):
                i += 2  # skip the flag and its mount spec
                continue
            result.append(token)
            i += 1
        return result

    def get_installed_version(self, podman_cmd, image_tag):
        # Sanitise so capture_output=True works and there is no stray --name.
        # Keep mounts: a version check is harmless and needs no commit.
        cmd = self._sanitise_podman_cmd(podman_cmd, drop_mounts=False)
        v_check_cmd = cmd + [image_tag, "/bin/bash", "--login", "-c", f"{self.name} --version"]
        try:
            result = subprocess.run(v_check_cmd, capture_output=True, text=True, check=True)
            output = result.stdout.strip()
            if not output:
                raise RuntimeError("version command produced no output")
            return output.split()[-1].lstrip("v")
        except Exception as e:
            raise RuntimeError(f"Could not retrieve installed version: {e}")

    def initialize(self, ws_meta_dir, xdg_config):
        """Plugin initialization step to pre-create files, folders, or run migrations."""
        # Default generic implementation: pre-create shared config dirs & files
        for d in self.shared_config_dirs:
            (xdg_config / d).mkdir(parents=True, exist_ok=True)
        for f in self.shared_config_files:
            p = xdg_config / f
            is_empty = p.exists() and p.stat().st_size == 0
            if not p.exists() or is_empty:
                if f.endswith(".json") or f.endswith(".yml") or f.endswith(".yaml"):
                    p.write_text("{}")
                elif not p.exists():
                    p.touch()

    def migrate_config(self, ws_meta_dir, xdg_config):
        pass

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, internal_home):
        pass

