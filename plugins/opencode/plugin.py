import json
import urllib.request
from plugins.base import BasePlugin

class Plugin(BasePlugin):
    name = "opencode"
    github_repo = "anomalyco/opencode"
    # The GitHub releases feed is pinned to 1.x; 2.x is only announced here.
    latest_version_url = "https://opencode.ai/update/api/latest/cli/npm"
    first_run_message = "💡 First run for this workspace: OpenCode may perform a one-time database migration. Please wait..."

    host_config_subdir = "opencode-sandbox"
    host_data_subdir = "opencode-sandbox"
    image_prefix = "opencode-ws"
    container_prefix = "opencode"

    default_cmd = ["opencode"]
    internal_config_dir = "/home/developer/.config/opencode"
    internal_data_dir = "/home/developer/.local/share/opencode"

    shared_config_dirs = ["modes"]

    # NOTE: there is intentionally no shared auth.json. OpenCode 2 keeps saved
    # credentials in the per-workspace SQLite database (opencode.db in the
    # workspace data dir). auth.json is only imported by a one-time migration of
    # an *existing* database and is never written back, so a globally shared
    # file cannot provide credentials to new workspaces. Connect providers once
    # per workspace with /connect (or `opencode auth login`); the login is kept
    # in the workspace's state directory.

    def get_latest_version(self, debug=False):
        """Ask upstream's update endpoint, since GitHub releases/latest stays on 1.x."""
        try:
            req = urllib.request.Request(
                self.latest_version_url, headers={"User-Agent": "agent-sandbox-cli"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                latest = json.loads(response.read().decode()).get("version", "")
            if not latest:
                print(f"⚠️ Warning: update endpoint returned no version for {self.name}.")
                return None
            if debug:
                print(f"DEBUG [{self.name}]: Latest version upstream: v{latest}")
            return latest
        except Exception as e:
            print(f"⚠️ Warning: Could not check for latest version of {self.name}: {e}")
        return None

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, internal_home):
        # No SELinux relabel suffix (':z'/':Z'). These live under the plugin-level
        # xdg_config and are shared across ALL workspaces and with the host. Any
        # relabel rewrites the host path's type in place and persists after exit;
        # ':Z' additionally assigns a private per-container category, so a second
        # concurrent sandbox would steal the label and break the first with EACCES.
        # SELinux labeling is disabled for the container, so no relabel is needed.
        for d in self.shared_config_dirs:
            podman_cmd.extend(["-v", f"{xdg_config / d}:{internal_home}/.config/opencode/{d}"])
