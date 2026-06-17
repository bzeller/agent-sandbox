"""Tests for sidecar config validation and image-tag derivation."""

import hashlib
import shlex
import tempfile
import unittest
from pathlib import Path

from helpers import load_agent_sandbox


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.mod = load_agent_sandbox(self.tmp / "config", self.tmp / "data")

    def test_accepts_zypper_capability_specs(self):
        # Regression: capability specs like pkgconfig(libudev) were wrongly
        # rejected by an over-strict package-name allowlist.
        cfg = {"install": ["ripgrep", "pkgconfig(libudev)", "cmake(Qt5)", "perl(Foo::Bar)"]}
        self.mod._validate_sidecar_cfg(cfg, allow_privileged=True)  # must not raise

    def test_rejects_non_string_install_entries(self):
        with self.assertRaises(ValueError):
            self.mod._validate_sidecar_cfg({"install": ["ok", 123]}, allow_privileged=True)

    def test_rejects_newline_in_base_image(self):
        # base_image is interpolated unquoted into `FROM <x>`; a newline there
        # would inject a Dockerfile instruction.
        with self.assertRaises(ValueError):
            self.mod._validate_sidecar_cfg(
                {"base_image": "ubuntu\nRUN evil"}, allow_privileged=True)

    def test_accepts_normal_image_reference(self):
        self.mod._validate_sidecar_cfg(
            {"base_image": "registry.example.com:5000/img@sha256:abc"},
            allow_privileged=True)

    def test_set_env_must_be_string_to_string(self):
        with self.assertRaises(ValueError):
            self.mod._validate_sidecar_cfg({"set_env": {"K": 1}}, allow_privileged=True)

    def test_disallow_privileged_guard(self):
        # With allow_privileged=False, presence of a privileged key is an error.
        with self.assertRaises(ValueError):
            self.mod._validate_sidecar_cfg({"mounts": []}, allow_privileged=False)

    def test_mounts_require_host_and_container(self):
        with self.assertRaises(ValueError):
            self.mod._validate_sidecar_cfg({"mounts": [{"host": "~/x"}]}, allow_privileged=True)


class ContainerPathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.mod = load_agent_sandbox(self.tmp / "config", self.tmp / "data")

    def test_rejects_relative_path(self):
        with self.assertRaises(ValueError):
            self.mod._validate_container_path("relative/path")

    def test_normalizes_interior_dotdot_to_absolute(self):
        # An absolute path containing '..' is normalized to a concrete absolute
        # path (it cannot escape the root), e.g. /home/../etc -> /etc. This is a
        # valid container destination, so it is accepted (normalized).
        self.assertEqual(self.mod._validate_container_path("/home/../etc"), "/etc")

    def test_rejects_empty(self):
        with self.assertRaises(ValueError):
            self.mod._validate_container_path("")

    def test_accepts_absolute_path(self):
        self.assertEqual(self.mod._validate_container_path("/home/developer/x"),
                         "/home/developer/x")


class ImageTagStabilityTests(unittest.TestCase):
    """The image tag must depend only on image-relevant inputs.

    Regression: when mounts/forward_env/etc. were mixed into the image hash,
    approving vs. denying a workspace's privileged keys flipped the tag and
    forced pointless rebuilds, even though those keys are runtime-only.
    """

    TEMPLATE = "FROM {base_image}\nRUN install {extra_packages}\n"

    def _render(self, cfg):
        return self.TEMPLATE.format(
            base_image=cfg.get("base_image", "opensuse/tumbleweed:latest"),
            extra_packages=" ".join(shlex.quote(p) for p in cfg.get("install", [])),
        )

    def _tag(self, cfg):
        # Mirror the production hashing: SHA-256 of dockerfile_content only.
        return hashlib.sha256(self._render(cfg).encode()).hexdigest()[:12]

    def test_tag_stable_across_trust_decisions(self):
        denied = {"base_image": "opensuse/tumbleweed:latest", "install": ["ripgrep"], "mounts": []}
        approved = {"base_image": "opensuse/tumbleweed:latest", "install": ["ripgrep"],
                    "mounts": [{"host": "~/.x", "container": "/x"}]}
        self.assertEqual(self._tag(denied), self._tag(approved))

    def test_tag_changes_when_install_changes(self):
        a = {"base_image": "opensuse/tumbleweed:latest", "install": ["ripgrep"]}
        b = {"base_image": "opensuse/tumbleweed:latest", "install": ["ripgrep", "fd"]}
        self.assertNotEqual(self._tag(a), self._tag(b))

    def test_tag_changes_when_base_image_changes(self):
        a = {"base_image": "opensuse/tumbleweed:latest", "install": []}
        b = {"base_image": "opensuse/leap:15.6", "install": []}
        self.assertNotEqual(self._tag(a), self._tag(b))

    def test_production_hash_excludes_runtime_keys(self):
        # Guard against re-introducing json.dumps(cfg) into the image hash:
        # assert the script source hashes dockerfile_content alone.
        src = (Path(__file__).resolve().parent.parent / "scripts" / "agent-sandbox.py").read_text()
        self.assertIn("hashlib.sha256(dockerfile_content.encode())", src)
        self.assertNotIn("dockerfile_content + json.dumps(cfg", src)


if __name__ == "__main__":
    unittest.main()
