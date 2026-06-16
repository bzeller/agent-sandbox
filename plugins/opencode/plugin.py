import json
import sys
from plugins.base import BasePlugin

class Plugin(BasePlugin):
    name = "opencode"
    github_repo = "anomalyco/opencode"
    
    host_config_subdir = "opencode-sandbox"
    host_data_subdir = "opencode-sandbox"
    image_prefix = "opencode-ws"
    container_prefix = "opencode"
    
    default_cmd = ["opencode"]
    internal_config_dir = "/home/developer/.config/opencode"
    internal_data_dir = "/home/developer/.local/share/opencode"
    
    shared_config_dirs = ["modes"]
    shared_config_files = ["auth.json"]

    def get_update_command(self, latest_version):
        return "curl -fsSL https://opencode.ai/install | bash"

    def migrate_config(self, ws_meta_dir, xdg_config):
        local_auth = ws_meta_dir / "auth.json"
        global_auth = xdg_config / "auth.json"
        if local_auth.exists() and not local_auth.is_symlink():
            try:
                local_content = local_auth.read_text().strip()
                local_data = json.loads(local_content or "{}")
                if local_data:
                    global_data = {}
                    if global_auth.exists():
                        try:
                            global_content = global_auth.read_text().strip()
                            global_data = json.loads(global_content or "{}")
                        except json.JSONDecodeError:
                            print(f"❌ Error: Global auth.json ({global_auth}) is not valid JSON.")
                            sys.exit(1)
                    
                    conflicts = set(local_data.keys()) & set(global_data.keys())
                    if conflicts:
                        print(f"❌ Error: Conflict detected in auth.json!")
                        print(f"The following keys already exist in your global config ({global_auth.resolve()}):")
                        for k in conflicts:
                            print(f"  - {k}")
                        sys.exit(1)
                    
                    if global_data or not global_auth.exists():
                        print(f"🔄 Merging workspace auth keys into global config: {global_auth}")
                        updated_global = {**global_data, **local_data}
                        global_auth.write_text(json.dumps(updated_global, indent=2))
                    
                    local_auth.unlink()
            except Exception as e:
                if isinstance(e, SystemExit): raise
                print(f"⚠️ Warning: Failed to migrate auth.json: {e}")

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, global_auth, internal_home):
        for d in self.shared_config_dirs:
            podman_cmd.extend(["-v", f"{xdg_config / d}:{internal_home}/.config/opencode/{d}:Z"])
        podman_cmd.extend([
            "-v", f"{global_auth}:{internal_home}/.local/share/opencode/auth.json:Z"
        ])
