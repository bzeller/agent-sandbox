"""Tests for plugins/base.py: version parsing and podman command sanitising."""

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from plugins.base import version_tuple, BasePlugin  # noqa: E402


class VersionTupleTests(unittest.TestCase):
    def test_plain_version(self):
        self.assertEqual(version_tuple("1.2.3"), (1, 2, 3))

    def test_leading_v_is_stripped(self):
        # Regression: a leading 'v' previously yielded (2, 3) for "v1.2.3"
        # because the first component "v1" was silently dropped.
        self.assertEqual(version_tuple("v1.2.3"), (1, 2, 3))
        self.assertEqual(version_tuple("V2.0"), (2, 0))

    def test_prerelease_and_build_suffixes_stripped(self):
        self.assertEqual(version_tuple("1.2.3-beta.1"), (1, 2, 3))
        self.assertEqual(version_tuple("1.2.3+build.5"), (1, 2, 3))

    def test_stops_at_first_non_numeric_component(self):
        # "1.2.x" must not become (1, 2) by skipping bad parts in the middle;
        # it stops at the first non-numeric component.
        self.assertEqual(version_tuple("1.2.x"), (1, 2))

    def test_empty_or_garbage_returns_zero_tuple(self):
        self.assertEqual(version_tuple(""), (0,))
        self.assertEqual(version_tuple("garbage"), (0,))
        self.assertEqual(version_tuple(None), (0,))

    def test_ordering_is_numeric_not_lexicographic(self):
        self.assertGreater(version_tuple("1.10.0"), version_tuple("1.9.0"))
        self.assertGreater(version_tuple("v2.0.0"), version_tuple("1.9.9"))

    def test_prerelease_equals_release_for_comparison(self):
        self.assertEqual(version_tuple("1.2.3"), version_tuple("1.2.3-rc1"))


class SanitisePodmanCmdTests(unittest.TestCase):
    def setUp(self):
        self.bp = BasePlugin()
        self.cmd = [
            "podman", "run", "-it", "--rm",
            "--name", "foo-123",
            "--userns=keep-id",
            "-v", "/a:/b:Z",
            "--env", "X=1",
            "-v", "/c:/d:Z",
        ]

    def test_strips_interactive_and_rm_flags(self):
        out = self.bp._sanitise_podman_cmd(self.cmd, drop_mounts=False)
        self.assertNotIn("-it", out)
        self.assertNotIn("--rm", out)

    def test_strips_name_flag_and_its_value(self):
        # Regression: a stray inherited --name collided with the helper --name
        # that run_update appends, which podman rejects.
        out = self.bp._sanitise_podman_cmd(self.cmd, drop_mounts=False)
        self.assertNotIn("--name", out)
        self.assertNotIn("foo-123", out)

    def test_keeps_non_targeted_flags(self):
        out = self.bp._sanitise_podman_cmd(self.cmd, drop_mounts=False)
        self.assertIn("--userns=keep-id", out)
        self.assertIn("--env", out)
        self.assertIn("X=1", out)

    def test_keeps_mounts_by_default(self):
        out = self.bp._sanitise_podman_cmd(self.cmd, drop_mounts=False)
        self.assertEqual(out.count("-v"), 2)

    def test_drops_mounts_when_requested(self):
        out = self.bp._sanitise_podman_cmd(self.cmd, drop_mounts=True)
        self.assertNotIn("-v", out)
        self.assertNotIn("/a:/b:Z", out)
        self.assertNotIn("/c:/d:Z", out)
        # Non-mount flags must survive the mount stripping.
        self.assertIn("--env", out)
        self.assertIn("X=1", out)


if __name__ == "__main__":
    unittest.main()
