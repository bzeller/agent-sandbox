import subprocess
import unittest
from unittest import mock

from helpers import load_agent_sandbox, quiet


def _podman_result(version_output):
    return subprocess.CompletedProcess(
        args=["podman", "--version"], returncode=0, stdout=version_output, stderr=""
    )


class UsernsFlagTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_agent_sandbox()

    def test_flag_maps_host_user_to_developer(self):
        self.assertEqual(
            self.mod._userns_flag(), "--userns=keep-id:uid=1000,gid=1000"
        )


class ParsePodmanVersionTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_agent_sandbox()

    def test_plain_version(self):
        self.assertEqual(
            self.mod._parse_podman_version("podman version 5.2.3"), (5, 2, 3)
        )

    def test_minimum_version(self):
        self.assertEqual(
            self.mod._parse_podman_version("podman version 4.3.0"), (4, 3, 0)
        )

    def test_distro_suffix(self):
        self.assertEqual(
            self.mod._parse_podman_version("podman version 4.9.4-rhel"), (4, 9, 4)
        )

    def test_unparsable_returns_none(self):
        self.assertIsNone(self.mod._parse_podman_version("garbage"))

    def test_empty_returns_none(self):
        self.assertIsNone(self.mod._parse_podman_version(""))


class DoctorCheckTests(unittest.TestCase):
    def setUp(self):
        self.mod = load_agent_sandbox()
        self.template = object()

    def _run(self, version_output, euid=1000, template=None):
        template = self.template if template is None else template
        with mock.patch.object(
            self.mod.subprocess, "run", return_value=_podman_result(version_output)
        ), mock.patch.object(self.mod.os, "geteuid", return_value=euid), quiet():
            self.mod.doctor_check(template)

    def test_old_podman_exits(self):
        with self.assertRaises(SystemExit):
            self._run("podman version 4.2.0")

    def test_minimum_podman_passes(self):
        self._run("podman version 4.3.0")

    def test_newer_podman_passes(self):
        self._run("podman version 5.2.3")

    def test_root_exits(self):
        with self.assertRaises(SystemExit):
            self._run("podman version 5.2.3", euid=0)

    def test_unparsable_version_does_not_exit(self):
        self._run("something unexpected")

    def test_missing_template_exits(self):
        with mock.patch.object(
            self.mod.subprocess, "run", return_value=_podman_result("podman version 5.2.3")
        ), mock.patch.object(self.mod.os, "geteuid", return_value=1000), quiet():
            with self.assertRaises(SystemExit):
                self.mod.doctor_check(None)

    def test_missing_podman_exits(self):
        with mock.patch.object(
            self.mod.subprocess, "run", side_effect=FileNotFoundError
        ), quiet():
            with self.assertRaises(SystemExit):
                self.mod.doctor_check(self.template)


if __name__ == "__main__":
    unittest.main()
