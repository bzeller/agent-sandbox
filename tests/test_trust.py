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

    def write_global_config(self, cfg):
        path = self.xdg_config / "agent-sandbox" / "opencode.json"
        path.parent.mkdir(parents=True, exist_ok=True)
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


class PrivilegedItemTests(_TrustTestBase):
    def test_items_are_per_element(self):
        subset = {
            "mounts": [{"host": "~/.a", "container": "/a"},
                       {"host": "~/.b", "container": "/b"}],
            "forward_env": ["E1", "E2"],
            "ssh_auth_sock": True,
        }
        items = self.mod._privileged_items(subset)
        # 2 mounts + 2 env + 1 ssh = 5 distinct items.
        self.assertEqual(len(items), 5)
        fps = [fp for _, fp in items]
        self.assertEqual(len(set(fps)), 5, "distinct items have distinct fingerprints")

    def test_duplicate_forward_env_collapse_to_one_fingerprint(self):
        items = self.mod._privileged_items({"forward_env": ["DUP", "DUP"]})
        fps = {fp for _, fp in items}
        self.assertEqual(len(fps), 1, "identical items share a fingerprint")

    def test_item_fingerprint_changes_with_value(self):
        a = self.mod._privileged_items({"forward_env": ["A"]})[0][1]
        b = self.mod._privileged_items({"forward_env": ["B"]})[0][1]
        self.assertNotEqual(a, b)

    def test_mount_and_env_with_same_string_do_not_collide(self):
        # A mount and a forward_env both involving "x" must not share a fingerprint.
        m = self.mod._privileged_items({"mounts": [{"host": "x", "container": "x"}]})[0][1]
        e = self.mod._privileged_items({"forward_env": ["x"]})[0][1]
        self.assertNotEqual(m, e)

    def test_privileged_subset_excludes_safe_keys(self):
        cfg = {"install": ["x"], "base_image": "y", "mounts": [], "ssh_auth_sock": True}
        subset = self.mod._privileged_subset(cfg)
        self.assertNotIn("install", subset)
        self.assertNotIn("base_image", subset)
        self.assertIn("mounts", subset)
        self.assertIn("ssh_auth_sock", subset)

    def test_ports_fingerprint_generation(self):
        items = self.mod._privileged_items({"ports": ["8501:8501"]})
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][0], "forward container port to host '8501:8501'")

    def test_ports_validation_rejects_invalid_formats(self):
        # Valid cases should pass silently
        for p in ["8501:8501", "8501", "12345:6789"]:
            self.mod._validate_sidecar_cfg({"ports": [p]})
            
        # Invalid cases should raise ValueError
        for p in ["abc", "8501:abc", "abc:8501", "", "123456:789"]:
            with self.assertRaises(ValueError):
                self.mod._validate_sidecar_cfg({"ports": [p]})


class TrustStoreTests(_TrustTestBase):
    def test_round_trip_and_membership(self):
        path = "/some/ws/.agent-sandbox.json"
        self.assertEqual(self.mod._load_approved_fingerprints(path), set())
        self.mod._store_approved_fingerprints(path, {"fp1", "fp2"})
        self.assertEqual(self.mod._load_approved_fingerprints(path), {"fp1", "fp2"})
        # A fingerprint that was never approved is not a member.
        self.assertNotIn("fp3", self.mod._load_approved_fingerprints(path))

    def test_storing_empty_set_drops_entry(self):
        path = "/some/ws/.agent-sandbox.json"
        self.mod._store_approved_fingerprints(path, {"fp1"})
        self.mod._store_approved_fingerprints(path, set())
        self.assertEqual(self.mod._load_approved_fingerprints(path), set())

    def test_forget(self):
        path = "/some/ws/.agent-sandbox.json"
        self.mod._store_approved_fingerprints(path, {"fp"})
        self.assertTrue(self.mod._forget_workspace_trust(path))
        self.assertEqual(self.mod._load_approved_fingerprints(path), set())
        # Forgetting an unknown entry returns False.
        self.assertFalse(self.mod._forget_workspace_trust(path))

    def test_store_is_owner_only(self):
        self.mod._store_approved_fingerprints("/p", {"fp"})
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

    def test_removing_then_readding_privilege_reprompts(self):
        # Regression: granting a privilege, removing it, then re-adding the
        # *identical* privilege must prompt again. Previously the stored
        # fingerprint still matched, so re-introduction was silently honored.
        self.write_ws_config({"install": ["x"], "ssh_auth_sock": True})
        with mock.patch("builtins.input", return_value="y"), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            cfg = self.mod.load_sidecar_config(self.ws, "opencode")
        self.assertTrue(cfg["ssh_auth_sock"], "granted on first approval")

        # Remove the privilege and run: this should forget the approval.
        self.write_ws_config({"install": ["x"]})
        self.load(tty=False)

        # Re-add the identical privilege: must prompt again (not silently grant).
        self.write_ws_config({"install": ["x"], "ssh_auth_sock": True})
        with mock.patch("builtins.input", side_effect=AssertionError("must re-prompt")) , \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            with self.assertRaises(AssertionError):
                self.mod.load_sidecar_config(self.ws, "opencode")

    def test_unchanged_privilege_is_not_reprompted(self):
        # Counterpart to the regression test: an unchanged, still-present
        # privileged config must NOT re-prompt on subsequent runs.
        self.write_ws_config({"install": ["x"], "ssh_auth_sock": True})
        self.load(trust_flag=True, tty=False)  # approve + remember
        with mock.patch("builtins.input", side_effect=AssertionError("must not re-prompt")), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            cfg = self.mod.load_sidecar_config(self.ws, "opencode")
        self.assertTrue(cfg["ssh_auth_sock"], "unchanged approved config stays granted")

    def test_dry_run_with_privilege_removed_does_not_forget(self):
        # A dry-run must be side-effect-free: removing the privilege under
        # --dry-run must NOT revoke a stored approval.
        self.write_ws_config({"ssh_auth_sock": True})
        self.load(trust_flag=True, tty=False)  # approve
        self.write_ws_config({"install": ["x"]})
        self.load(dry_run=True, tty=False)  # dry-run, privilege absent
        # Re-add and real-run: approval must still be intact (no re-prompt).
        self.write_ws_config({"ssh_auth_sock": True})
        with mock.patch("builtins.input", side_effect=AssertionError("dry-run must not have revoked")), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            cfg = self.mod.load_sidecar_config(self.ws, "opencode")
        self.assertTrue(cfg["ssh_auth_sock"])

    # --- Per-item trust behavior (multiple items of the same kind) ---

    def _approve_all(self, cfg):
        """Write cfg and approve everything via --trust-workspace (non-interactive)."""
        self.write_ws_config(cfg)
        self.load(trust_flag=True, tty=False)

    def test_removing_one_of_many_does_not_reprompt(self):
        # Your scenario: trust 5 items, remove one. The remaining four were each
        # individually approved, so re-running must NOT prompt, and the removed
        # item must simply be absent.
        cfg = {
            "mounts": [{"host": "~/.a", "container": "/a"},
                       {"host": "~/.b", "container": "/b"}],
            "forward_env": ["E1", "E2"],
            "ssh_auth_sock": True,
        }
        self._approve_all(cfg)
        reduced = {
            "mounts": [{"host": "~/.a", "container": "/a"},
                       {"host": "~/.b", "container": "/b"}],
            "forward_env": ["E1"],            # removed E2
            "ssh_auth_sock": True,
        }
        self.write_ws_config(reduced)
        with mock.patch("builtins.input", side_effect=AssertionError("must not reprompt on removal")), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            result = self.mod.load_sidecar_config(self.ws, "opencode")
        self.assertEqual(result["forward_env"], ["E1"])
        self.assertEqual(len(result["mounts"]), 2)
        self.assertTrue(result["ssh_auth_sock"])

    def test_adding_one_item_prompts_only_for_that_item(self):
        # Trust 2 env vars, then add a third. Only the new one needs approval;
        # the previously-approved ones must still be honored.
        self._approve_all({"forward_env": ["E1", "E2"]})
        self.write_ws_config({"forward_env": ["E1", "E2", "E3"]})
        seen = {}
        def fake_input(prompt=""):
            seen["prompt"] = prompt
            return "y"
        with mock.patch("builtins.input", side_effect=fake_input), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            result = self.mod.load_sidecar_config(self.ws, "opencode")
        # All three end up honored (two pre-approved + the just-approved one).
        self.assertEqual(result["forward_env"], ["E1", "E2", "E3"])
        self.assertIn("prompt", seen, "a prompt must have been shown for the new item")

    def test_adding_item_denied_keeps_previously_approved(self):
        # Add a new item but DENY it: the new item is dropped, the previously
        # approved items remain honored.
        self._approve_all({"forward_env": ["E1"]})
        self.write_ws_config({"forward_env": ["E1", "E2"]})
        with mock.patch("builtins.input", return_value="n"), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            result = self.mod.load_sidecar_config(self.ws, "opencode")
        self.assertEqual(result["forward_env"], ["E1"], "denied new item dropped, old kept")

    def test_changing_one_item_reprompts_only_for_changed_item(self):
        # Changing a mount's host path is a NEW item (different fingerprint).
        self._approve_all({"mounts": [{"host": "~/.a", "container": "/a"}],
                           "forward_env": ["E1"]})
        self.write_ws_config({"mounts": [{"host": "~/.EVIL", "container": "/a"}],
                              "forward_env": ["E1"]})
        with mock.patch("builtins.input", return_value="n"), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            result = self.mod.load_sidecar_config(self.ws, "opencode")
        # Changed mount denied -> absent; unchanged forward_env still honored.
        self.assertEqual(result["mounts"], [])
        self.assertEqual(result["forward_env"], ["E1"])

    def test_removing_item_then_readding_reprompts_only_for_it(self):
        # Per-item version of the re-introduction bug: remove one item, re-add
        # it; only that item re-prompts, the others stay silently trusted.
        self._approve_all({"forward_env": ["E1", "E2"]})
        # Remove E2, run (prunes E2's approval); E1 still trusted.
        self.write_ws_config({"forward_env": ["E1"]})
        with mock.patch("builtins.input", side_effect=AssertionError("E1 must stay trusted")), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            self.mod.load_sidecar_config(self.ws, "opencode")
        # Re-add E2: must prompt (only for E2). Deny it; E1 remains honored.
        self.write_ws_config({"forward_env": ["E1", "E2"]})
        with mock.patch("builtins.input", return_value="n"), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            result = self.mod.load_sidecar_config(self.ws, "opencode")
        self.assertEqual(result["forward_env"], ["E1"], "re-added E2 denied; E1 still trusted")


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

    def test_merged_config_privileged_key_only_in_global_config(self):
        # Trusted key (forward_env) only in global config, not in project config
        # -> Should NOT ask permission and expected value should be applied.
        self.write_global_config({"forward_env": ["GLOBAL_KEY"]})
        self.write_ws_config({"install": ["cmake"]})
        with mock.patch("builtins.input", side_effect=AssertionError("Should not ask permission for global config")), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            cfg = self.mod.load_sidecar_config(self.ws, "opencode")
        self.assertEqual(cfg["forward_env"], ["GLOBAL_KEY"])
        self.assertEqual(cfg["install"], ["cmake"])

    def test_merged_config_privileged_key_only_in_project_config(self):
        # Trusted key (forward_env) only in project config
        # -> Should ask permission. Verify expected value is applied if approved.
        self.write_global_config({"install": ["git"]})
        self.write_ws_config({"forward_env": ["PROJECT_KEY"]})
        seen_prompts = []
        def fake_input(prompt=""):
            seen_prompts.append(prompt)
            return "y"
        with mock.patch("builtins.input", side_effect=fake_input), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            cfg = self.mod.load_sidecar_config(self.ws, "opencode")
        self.assertTrue(seen_prompts, "Should have asked permission for the workspace privileged key")
        self.assertEqual(cfg["forward_env"], ["PROJECT_KEY"])
        self.assertEqual(cfg["install"], ["git"])

    def test_merged_config_privileged_key_in_both(self):
        # Trusted key (forward_env) in both configs
        # -> Should ask permission (for the workspace addition).
        # -> Approved project value should combine with/override the global value.
        self.write_global_config({"forward_env": ["GLOBAL_KEY"]})
        self.write_ws_config({"forward_env": ["GLOBAL_KEY", "PROJECT_KEY"]})
        seen_prompts = []
        def fake_input(prompt=""):
            seen_prompts.append(prompt)
            return "y"
        with mock.patch("builtins.input", side_effect=fake_input), \
             mock.patch.object(sys.stdin, "isatty", return_value=True), quiet(tty=True):
            cfg = self.mod.load_sidecar_config(self.ws, "opencode")
        self.assertTrue(seen_prompts, "Should have asked permission for the workspace-level key addition")
        # Combining: GLOBAL_KEY from global, and approved PROJECT_KEY from project should both be present
        self.assertEqual(sorted(cfg["forward_env"]), ["GLOBAL_KEY", "PROJECT_KEY"])


if __name__ == "__main__":
    unittest.main()
