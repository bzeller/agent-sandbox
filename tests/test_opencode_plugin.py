import tempfile
import unittest
from pathlib import Path

from helpers import load_agent_sandbox


class NoSharedAuthTests(unittest.TestCase):
    """OpenCode 2 keeps credentials in the per-workspace database, so the
    plugin must not create or mount a global auth.json."""

    def setUp(self):
        self.plugin = load_agent_sandbox().PLUGINS["opencode"]
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.ws = root / "ws"
        self.cfg = root / "cfg"
        self.ws.mkdir()
        self.cfg.mkdir()

    def test_initialize_does_not_create_auth_json(self):
        self.plugin.initialize(self.ws, self.cfg)
        self.assertFalse((self.cfg / "auth.json").exists())
        self.assertFalse((self.ws / "auth.json").exists())

    def test_initialize_creates_shared_dirs(self):
        self.plugin.initialize(self.ws, self.cfg)
        self.assertTrue((self.cfg / "modes").is_dir())

    def test_initialize_leaves_existing_workspace_auth_json_alone(self):
        local = self.ws / "auth.json"
        local.write_text('{"anthropic": {"type": "api", "key": "x"}}')
        self.plugin.initialize(self.ws, self.cfg)
        self.assertEqual(local.read_text(), '{"anthropic": {"type": "api", "key": "x"}}')

    def test_mount_config_does_not_mount_auth_json(self):
        cmd = []
        self.plugin.mount_config(cmd, self.ws, self.cfg, "/home/developer")
        self.assertFalse(any("auth.json" in part for part in cmd))

    def test_mount_config_mounts_modes_dir(self):
        cmd = []
        self.plugin.mount_config(cmd, self.ws, self.cfg, "/home/developer")
        self.assertIn(
            f"{self.cfg / 'modes'}:/home/developer/.config/opencode/modes", cmd
        )


if __name__ == "__main__":
    unittest.main()
