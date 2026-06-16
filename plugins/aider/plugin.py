from plugins.base import BasePlugin

class Plugin(BasePlugin):
    name = "aider"
    github_repo = "Aider-AI/aider"
    
    host_config_subdir = "aider-sandbox"
    host_data_subdir = "aider-sandbox"
    image_prefix = "aider-ws"
    container_prefix = "aider"
    
    default_cmd = ["aider"]
    internal_config_dir = "/home/developer/.config/aider"
    internal_data_dir = "/home/developer/.local/share/aider"
    
    shared_config_dirs = []
    shared_config_files = [".aider.conf.yml"]

    def get_update_command(self, latest_version):
        return "curl -LsSf https://aider.chat/install.sh | sh"

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, global_auth, internal_home):
        for f in self.shared_config_files:
            podman_cmd.extend(["-v", f"{xdg_config / f}:{internal_home}/{f}:Z"])
