import urllib.request
import subprocess
import json

def version_tuple(v):
    try:
        return tuple(map(int, (part for part in v.split('.') if part.isdigit())))
    except:
        return (0, 0, 0)

class BasePlugin:
    name = ""
    github_repo = None
    
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

    def get_installed_version(self, podman_cmd, image_tag):
        v_check_cmd = podman_cmd + [image_tag, "/bin/bash", "--login", "-c", f"{self.name} --version"]
        try:
            current_v_raw = subprocess.run(v_check_cmd, capture_output=True, text=True, check=True).stdout
            return current_v_raw.strip().split()[-1].lstrip("v")
        except Exception as e:
            raise RuntimeError(f"Could not retrieve installed version: {e}")

    def get_update_command(self, latest_version):
        raise NotImplementedError()

    def run_update(self, podman_cmd, image_tag, latest_v):
        print(f"🔄 Updating {self.name} to v{latest_v}...")
        update_cmd = podman_cmd + [image_tag, "/bin/bash", "-c", self.get_update_command(latest_v)]
        subprocess.run(update_cmd, check=True)

    def migrate_config(self, ws_meta_dir, xdg_config):
        pass

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, global_auth, internal_home):
        pass
