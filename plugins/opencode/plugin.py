import json
import os
import sys
from pathlib import Path
from plugins.base import BasePlugin

class Plugin(BasePlugin):
    name = "opencode"
    github_repo = "anomalyco/opencode"
    first_run_message = "💡 First run for this workspace: OpenCode may perform a one-time database migration. Please wait..."

    host_config_subdir = "opencode-sandbox"
    host_data_subdir = "opencode-sandbox"
    image_prefix = "opencode-ws"
    container_prefix = "opencode"

    default_cmd = ["opencode"]
    internal_config_dir = "/home/developer/.config/opencode"
    internal_data_dir = "/home/developer/.local/share/opencode"

    shared_config_dirs = ["modes"]
    shared_config_files = ["auth.json"]

    def initialize(self, ws_meta_dir, xdg_config):
        # Pre-create global auth file with owner-only permissions (0o600).
        global_auth = xdg_config / "auth.json"
        if not global_auth.exists():
            global_auth.touch(mode=0o600, exist_ok=True)
            global_auth.write_text("{}")
        else:
            global_auth.chmod(0o600)

        # Call default initialize for shared files/dirs
        super().initialize(ws_meta_dir, xdg_config)

        # Trigger workspace-to-global config migration
        self.migrate_config(ws_meta_dir, xdg_config)

    def get_update_command(self, latest_version):
        # Force HTTPS-only and TLS 1.2+ to mitigate protocol-downgrade attacks.
        # Pinning to a specific release with a checksum would be more secure;
        # see the Dockerfile.template comment for details.
        return "curl --proto '=https' --tlsv1.2 -fsSL https://opencode.ai/install | bash"

    def migrate_config(self, ws_meta_dir, xdg_config):
        local_auth = ws_meta_dir / "auth.json"
        global_auth = xdg_config / "auth.json"

        # Snapshot the inode of local_auth *before* reading it to detect
        # TOCTOU races: if the inode changes between check and unlink we
        # refuse to delete the file.
        try:
            initial_stat = os.lstat(str(local_auth))
        except FileNotFoundError:
            return  # Nothing to migrate

        if initial_stat.st_nlink == 0 or not local_auth.exists():
            return

        # Reject symlinks at the point of reading (not just checking)
        if os.path.islink(str(local_auth)):
            print(f"⚠️ Warning: Skipping migration — local auth.json is a symlink: {local_auth}")
            return

        try:
            # O_NOFOLLOW ensures we open the regular file, not a symlink target
            fd = os.open(str(local_auth), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "r") as fh:
                local_content = fh.read().strip()
            local_data = json.loads(local_content or "{}")

            if not local_data:
                return  # Nothing meaningful to migrate

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

            # Always write when there is local data to migrate.
            # The previous condition `global_data or not global_auth.exists()`
            # was inverted: when global_auth existed but was empty (the
            # common first-run case) it evaluated to False and skipped the
            # write while still deleting local_auth, causing silent data loss.
            print(f"🔄 Merging workspace auth keys into global config: {global_auth}")
            updated_global = {**global_data, **local_data}

            # Atomic write: use O_EXCL to fail if temp file already exists (prevents
            # symlink attacks). Open with O_CREAT|O_WRONLY|mode 0o600 so it is never
            # world-readable even transiently, then rename into place.
            import tempfile
            tmp_fd, tmp_path = tempfile.mkstemp(
                dir=global_auth.parent,
                prefix=".auth-",
                suffix=".tmp"
            )
            try:
                os.chmod(tmp_fd, 0o600)
                with os.fdopen(tmp_fd, "w") as fh:
                    fh.write(json.dumps(updated_global, indent=2))
                Path(tmp_path).replace(global_auth)
                global_auth.chmod(0o600)
            except Exception:
                # Clean up temp file on failure
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise

            # TOCTOU guard: verify the inode hasn't changed since our initial
            # stat.  If it has (e.g. a race replaced the file with a symlink),
            # we abort rather than deleting an unintended file.
            # Use unlink with dir_fd to make the check and delete atomic.
            try:
                parent_fd = os.open(str(local_auth.parent), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    current_stat = os.fstat(os.open(str(local_auth), os.O_RDONLY | os.O_NOFOLLOW))
                    if (current_stat.st_ino != initial_stat.st_ino or
                            current_stat.st_dev != initial_stat.st_dev):
                        print(f"⚠️ Warning: local auth.json changed during migration (possible race). "
                              f"Migration written to global config but local file NOT deleted.")
                        return
                    # Unlink using the parent directory fd for atomicity
                    os.unlink(local_auth.name, dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
            except Exception as e:
                print(f"⚠️ Warning: Could not safely delete local auth.json: {e}")

        except Exception as e:
            if isinstance(e, SystemExit):
                raise
            print(f"⚠️ Warning: Failed to migrate auth.json: {e}")

    def mount_config(self, podman_cmd, ws_meta_dir, xdg_config, internal_home):
        global_auth = xdg_config / "auth.json"
        for d in self.shared_config_dirs:
            podman_cmd.extend(["-v", f"{xdg_config / d}:{internal_home}/.config/opencode/{d}:Z"])
        podman_cmd.extend([
            "-v", f"{global_auth}:{internal_home}/.local/share/opencode/auth.json:Z"
        ])

