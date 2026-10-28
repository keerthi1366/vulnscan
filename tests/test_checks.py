import unittest
from unittest.mock import patch

from vulnscan import checks


class FirewallCheckTests(unittest.TestCase):
    def test_windows_profiles_on_are_not_reported_as_finding(self):
        output = "Domain Profile Settings:\nState                                 ON\nPrivate Profile Settings:\nState                                 ON\nPublic Profile Settings:\nState                                 ON"
        with patch.object(checks.platform, "system", return_value="Windows"), \
             patch.object(checks, "_command", return_value=output):
            observations = checks.collect_observations()
        firewall = observations[0]
        self.assertEqual(firewall.status, "pass")
        self.assertEqual(firewall.evidence, "State ON; State ON; State ON")

    def test_windows_profile_off_is_reported(self):
        output = "Domain Profile Settings:\nState                                 ON\nPrivate Profile Settings:\nState                                 OFF\nPublic Profile Settings:\nState                                 ON"
        with patch.object(checks.platform, "system", return_value="Windows"), \
             patch.object(checks, "_command", return_value=output):
            observations = checks.collect_observations()
        self.assertEqual(observations[0].status, "finding")


class ServiceCheckTests(unittest.TestCase):
    def test_windows_service_results_are_observations_only(self):
        payload = '[{"Name":"WinRM","State":"Running","StartMode":"Manual"}]'
        with patch.object(checks, "_command", return_value=payload):
            observations = checks.collect_service_observations("Windows")
        winrm = next(item for item in observations if item.check == "service:WinRM")
        self.assertEqual(winrm.status, "info")
        self.assertIn("Running", winrm.evidence)
        self.assertIn("does not change it", winrm.remediation)
        self.assertTrue(all(item.status == "info" for item in observations))

    def test_linux_service_states_are_read_only_observations(self):
        with patch.object(checks, "_command", return_value="Id=ssh.service\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled"):
            observations = checks.collect_service_observations("Linux")
        ssh = observations[0]
        self.assertEqual(ssh.check, "service:ssh")
        self.assertEqual(ssh.status, "info")
        self.assertIn("active", ssh.summary)


if __name__ == "__main__":
    unittest.main()
