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

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, internal_home):
        # No SELinux relabel suffix (':z'/':Z'). These live under the plugin-level
        # xdg_config, shared across ALL workspaces and with the host. Any relabel
        # rewrites the host path's type in place and persists after exit; ':Z'
        # additionally assigns a private per-container category, so a second
        # concurrent sandbox would steal the label and break the first with
        # EACCES. Labeling is disabled for the container, so none is needed.
        for f in self.shared_config_files:
            podman_cmd.extend(["-v", f"{xdg_config / f}:{internal_home}/{f}"])
