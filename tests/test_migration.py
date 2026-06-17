"""Tests for the legacy (MD5) -> SHA-256 workspace-dir migration."""

import hashlib
import tempfile
import unittest
from pathlib import Path

from helpers import load_agent_sandbox, quiet


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.mod = load_agent_sandbox(self.tmp / "config", self.tmp / "data")
        self.xdg_data = self.tmp / "data" / "opencode-sandbox"
        self.xdg_data.mkdir(parents=True)
        # A representative workspace path.
        self.work_dir = self.tmp / "project"
        self.work_dir.mkdir()

    def _legacy_dir(self):
        h = hashlib.md5(str(self.work_dir.resolve()).encode()).hexdigest()[:8]
        return self.xdg_data / f"ws-{h}"

    def _new_dir(self):
        h = hashlib.sha256(str(self.work_dir.resolve()).encode()).hexdigest()[:12]
        return self.xdg_data / f"ws-{h}"

    def _migrate(self):
        with quiet():
            return self.mod.migrate_legacy_workspace_dir(self.xdg_data, self.work_dir)

    def test_legacy_hash_matches_old_algorithm(self):
        self.assertEqual(
            self.mod.get_legacy_workspace_hash(self.work_dir),
            hashlib.md5(str(self.work_dir.resolve()).encode()).hexdigest()[:8],
        )

    def test_migrates_populated_legacy_dir(self):
        legacy = self._legacy_dir()
        legacy.mkdir()
        (legacy / "session.db").write_text("data")
        result = self._migrate()
        self.assertEqual(result, self._new_dir())
        self.assertTrue((self._new_dir() / "session.db").exists())
        self.assertFalse(legacy.exists(), "legacy dir should be renamed away")

    def test_no_legacy_dir_is_noop(self):
        result = self._migrate()
        self.assertEqual(result, self._new_dir())
        self.assertFalse(self._new_dir().exists(), "must not create dirs when nothing to migrate")

    def test_stale_empty_new_dir_does_not_strand_legacy_data(self):
        # A crashed earlier run can leave an empty new dir. Migration must still
        # move the populated legacy data into it (not silently skip).
        legacy = self._legacy_dir()
        legacy.mkdir()
        (legacy / "session.db").write_text("data")
        self._new_dir().mkdir()  # empty stale dir
        result = self._migrate()
        self.assertEqual(result, self._new_dir())
        self.assertTrue((self._new_dir() / "session.db").exists())
        self.assertFalse(legacy.exists())

    def test_populated_new_dir_is_left_intact(self):
        # If the new dir already has data, we must NOT overwrite it; the legacy
        # dir is left in place for manual handling.
        legacy = self._legacy_dir()
        legacy.mkdir()
        (legacy / "old.db").write_text("old")
        new = self._new_dir()
        new.mkdir()
        (new / "current.db").write_text("current")
        result = self._migrate()
        self.assertEqual(result, new)
        self.assertTrue((new / "current.db").exists())
        self.assertEqual((new / "current.db").read_text(), "current")
        self.assertTrue(legacy.exists(), "legacy dir left in place, not merged/deleted")


if __name__ == "__main__":
    unittest.main()
