import unittest

from maher_bounty.orchestrator import _run_loaded, active_discovery_enabled


class ActiveDiscoveryAuthorizationTests(unittest.TestCase):
    def test_authorization_enables_active_when_rule_is_unspecified(self):
        self.assertTrue(active_discovery_enabled({}, authorized=True))
        self.assertFalse(active_discovery_enabled({}, authorized=False))

    def test_explicit_false_rule_remains_passive_even_when_authorized(self):
        self.assertFalse(active_discovery_enabled({"allow_active_discovery": False}, authorized=True))

    def test_explicit_true_rule_requires_authorization_at_run_boundary(self):
        self.assertTrue(active_discovery_enabled({"allow_active_discovery": True}, authorized=True))
        with self.assertRaisesRegex(SystemExit, "--authorized"):
            _run_loaded({}, {"authorization_required": True, "allow_active_discovery": True}, authorized=False)


if __name__ == "__main__":
    unittest.main()
