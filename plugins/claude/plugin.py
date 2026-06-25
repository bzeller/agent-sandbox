import json
import os
import sys
from plugins.base import BasePlugin

class Plugin(BasePlugin):
    name = "claude"
    github_repo = "anthropics/claude-code"
    
    host_config_subdir = "claude-sandbox"
    host_data_subdir = "claude-sandbox"
    image_prefix = "claude-ws"
    container_prefix = "claude"
    
    default_cmd = ["claude"]
    internal_config_dir = "/home/developer/.claude"
    # We leave internal_data_dir empty to prevent masking Claude Code's compiled program 
    # files (which land in ~/.local/share/claude in the image layer) with an empty host mount.
    internal_data_dir = ""
    
    shared_config_dirs = []
    shared_config_files = ["settings.json"]

    def initialize(self, ws_meta_dir, xdg_config):
        # Pre-create global session file with owner-only permissions (0o600).
        global_session = xdg_config / "claude.json"
        if not global_session.exists():
            global_session.touch(mode=0o600, exist_ok=True)
            global_session.write_text("{}")
        else:
            global_session.chmod(0o600)

        # Call default initialize for shared files/dirs (creates settings.json)
        super().initialize(ws_meta_dir, xdg_config)

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, internal_home):
        # Mount the shared settings.json file into .claude/settings.json
        for f in self.shared_config_files:
            podman_cmd.extend(["-v", f"{xdg_config / f}:{self.internal_config_dir}/{f}:Z"])
            
        # Mount the shared global login session file directly to ~/.claude.json
        global_session = xdg_config / "claude.json"
        podman_cmd.extend(["-v", f"{global_session}:{internal_home}/.claude.json:Z"])
