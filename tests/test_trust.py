"""Tests for the workspace trust model (TOFU) and sidecar config loading."""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from helpers import load_agent_sandbox, quiet


class _TrustTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.xdg_config = self.tmp / "config"
        self.xdg_data = self.tmp / "data"
        self.mod = load_agent_sandbox(self.xdg_config, self.xdg_data)
        self.ws = self.tmp / "ws"
        self.ws.mkdir(parents=True)

    def write_ws_config(self, cfg):
        path = self.ws / ".agent-sandbox.json"
        path.write_text(json.dumps(cfg))
        return path

    def load(self, trust_flag=False, dry_run=False, tty=False):
        # quiet(tty=...) controls what the (redirected) stdout reports for
        # isatty(); we still patch stdin's isatty since it isn't redirected.
        with mock.patch.object(sys.stdin, "isatty", return_value=tty), quiet(tty=tty):
            return self.mod.load_sidecar_config(
                self.ws, "opencode",
                trust_flag=trust_flag, dry_run=dry_run,
            )


class FingerprintTests(_TrustTestBase):
    def test_fingerprint_stable_across_key_order(self):
        a = {"mounts": [{"host": "~/.gitconfig", "container": "/c"}], "forward_env": ["X"]}
        b = {"forward_env": ["X"], "mounts": [{"host": "~/.gitconfig", "container": "/c"}]}
        fa = self.mod._privileged_fingerprint(self.mod._privileged_subset(a))
        fb = self.mod._privileged_fingerprint(self.mod._privileged_subset(b))
        self.assertEqual(fa, fb)

    def test_privileged_subset_excludes_safe_keys(self):
        cfg = {"install": ["x"], "base_image": "y", "mounts": [], "ssh_auth_sock": True}
        subset = self.mod._privileged_subset(cfg)
        self.assertNotIn("install", subset)
        self.assertNotIn("base_image", subset)
        self.assertIn("mounts", subset)
        self.assertIn("ssh_auth_sock", subset)


class TrustStoreTests(_TrustTestBase):
    def test_round_trip_and_change_detection(self):
        path = "/some/ws/.agent-sandbox.json"
        fp = "abc123"
        self.assertFalse(self.mod._is_workspace_trusted(path, fp))
        self.mod._remember_workspace_trust(path, fp)
        self.assertTrue(self.mod._is_workspace_trusted(path, fp))
        # A different fingerprint (config changed) must NOT be considered trusted.
        self.assertFalse(self.mod._is_workspace_trusted(path, "different"))

    def test_forget(self):
        path = "/some/ws/.agent-sandbox.json"
        self.mod._remember_workspace_trust(path, "fp")
        self.assertTrue(self.mod._forget_workspace_trust(path))
        self.assertFalse(self.mod._is_workspace_trusted(path, "fp"))
        # Forgetting an unknown entry returns False.
        self.assertFalse(self.mod._forget_workspace_trust(path))

    def test_store_is_owner_only(self):
        self.mod._remember_workspace_trust("/p", "fp")
        store = self.mod._trust_store_path()
        self.assertTrue(store.exists())
        self.assertEqual(store.stat().st_mode & 0o777, 0o600)


class LoadSidecarTrustTests(_TrustTestBase):
    FULL_CFG = {
        "base_image": "opensuse/tumbleweed:latest",
        "install": ["ripgrep", "pkgconfig(libudev)"],
        "set_env": {"EDITOR": "vim"},
        "mounts": [{"host": "~/.gitconfig", "container": "/home/developer/.gitconfig"}],
        "forward_env": ["GH_TOKEN"],
        "ssh_auth_sock": True,
    }

    def test_safe_keys_always_honored(self):
        self.write_ws_config(self.FULL_CFG)
        cfg = self.load(tty=False)  # non-interactive
        self.assertEqual(cfg["install"], ["ripgrep", "pkgconfig(libudev)"])
        self.assertEqual(cfg["set_env"], {"EDITOR": "vim"})

    def test_privileged_denied_non_interactive(self):
        self.write_ws_config(self.FULL_CFG)
        cfg = self.load(tty=False)
        self.assertEqual(cfg["mounts"], [])
        self.assertEqual(cfg["forward_env"], [])
        self.assertFalse(cfg["ssh_auth_sock"])

    def test_trust_flag_honors_and_remembers(self):
        path = self.write_ws_config(self.FULL_CFG)
        cfg = self.load(trust_flag=True, tty=False)
        self.assertEqual(cfg["mounts"], self.FULL_CFG["mounts"])
        # Remembered: a subsequent run without the flag still honors.
        cfg2 = self.load(trust_flag=False, tty=False)
        self.assertEqual(cfg2["mounts"], self.FULL_CFG["mounts"])

    def test_changed_privileged_config_revokes_prior_approval(self):
        self.write_ws_config(self.FULL_CFG)
        self.load(trust_flag=True, tty=False)  # approve
        # Now change the mount target and re-run non-interactively.
        changed = dict(self.FULL_CFG)
        changed["mounts"] = [{"host": "~/.ssh", "container": "/home/developer/.ssh"}]
        self.write_ws_config(changed)
        cfg = self.load(trust_flag=False, tty=False)
        self.assertEqual(cfg["mounts"], [], "changed config must not inherit old approval")

    def test_interactive_yes_honors_and_remembers(self):
        self.write_ws_config(self.FULL_CFG)
        with mock.patch("builtins.input", return_value="y"):
            cfg = self.load(tty=True)
        self.assertEqual(cfg["mounts"], self.FULL_CFG["mounts"])

    def test_interactive_no_denies(self):
        self.write_ws_config(self.FULL_CFG)
        with mock.patch("builtins.input", return_value="n"):
            cfg = self.load(tty=True)
        self.assertEqual(cfg["mounts"], [])

    def test_interactive_eof_denies(self):
        self.write_ws_config(self.FULL_CFG)
        with mock.patch("builtins.input", side_effect=EOFError):
            cfg = self.load(tty=True)
        self.assertEqual(cfg["mounts"], [])

    def test_dry_run_does_not_prompt_or_persist(self):
        self.write_ws_config(self.FULL_CFG)
        with mock.patch("builtins.input", side_effect=AssertionError("must not prompt in dry-run")):
            cfg = self.load(dry_run=True, tty=True)
        self.assertEqual(cfg["mounts"], [])
        self.assertFalse(self.mod._trust_store_path().exists())

    def test_dry_run_with_trust_flag_honors_for_preview_but_does_not_persist(self):
        self.write_ws_config(self.FULL_CFG)
        cfg = self.load(trust_flag=True, dry_run=True, tty=True)
        self.assertEqual(cfg["mounts"], self.FULL_CFG["mounts"])
        self.assertFalse(self.mod._trust_store_path().exists())


class TrustedConfigTests(_TrustTestBase):
    def test_trusted_config_honors_privileged_without_prompt(self):
        trusted_dir = self.xdg_config / "agent-sandbox"
        trusted_dir.mkdir(parents=True)
        (trusted_dir / "opencode.json").write_text(json.dumps({
            "mounts": [{"host": "~/.gitconfig", "container": "/c"}],
            "ssh_auth_sock": True,
        }))
        self.write_ws_config({"install": ["ripgrep"]})
        with mock.patch("builtins.input", side_effect=AssertionError("trusted config must not prompt")):
            cfg = self.load(tty=True)
        self.assertEqual(cfg["mounts"], [{"host": "~/.gitconfig", "container": "/c"}])
        self.assertTrue(cfg["ssh_auth_sock"])
        # Workspace safe key still merges on top of trusted config.
        self.assertEqual(cfg["install"], ["ripgrep"])


if __name__ == "__main__":
    unittest.main()
