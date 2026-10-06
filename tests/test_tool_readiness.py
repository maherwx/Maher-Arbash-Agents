import unittest

from maher_bounty.tool_readiness import agent_tool_availability_context


class AgentToolAvailabilityContextTests(unittest.TestCase):
    def test_browser_dependency_is_not_reported_as_launch_ready(self):
        snapshot = {"tools": [
            {"tool": "browser-xss", "status": "dependency_present_browser_unverified", "available": True},
            {"tool": "nuclei", "status": "available", "available": True},
            {"tool": "nmap", "status": "missing", "available": False},
        ]}

        result = agent_tool_availability_context(snapshot, {"browser-xss", "nuclei", "nmap"}, "web")

        self.assertEqual(result["executable_on_path"], ["nuclei"])
        self.assertEqual(result["prerequisite_present_but_unverified"], ["browser-xss"])
        self.assertEqual(result["unavailable_or_unverified"], ["browser-xss", "nmap"])
        self.assertIn("browsers are not launched", result["basis"])
