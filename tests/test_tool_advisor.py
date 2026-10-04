import unittest
from unittest.mock import patch

from maher_bounty.tool_advisor import infer_areas, recommend_tools


class ToolAdvisorTests(unittest.TestCase):
    def test_detects_web_api_javascript_and_cms_signals(self):
        inventory = {
            "http": [{"url": "https://app.example.test", "tech": ["Next.js", "Node.js", "nginx"]}],
            "endpoints": [{"value": "https://app.example.test/graphql"}],
            "technology_counts": {"wordpress": 1},
        }
        areas = infer_areas(inventory)
        self.assertTrue({"domain", "web", "api", "javascript", "tls", "cms", "source"} <= areas)

    @patch("maher_bounty.tool_advisor.shutil.which")
    def test_recommends_tools_by_stack_and_gates_active_tools(self, which):
        which.return_value = "/usr/bin/tool"
        result = recommend_tools({"http": [{"tech": ["FastAPI", "Python"]}]})
        tools = {row["name"]: row for row in result["tools"]}
        self.assertIn("Bandit", tools)
        self.assertIn("Burp Suite", tools)
        self.assertEqual(tools["Burp Suite"]["state"], "manual_or_report_import")
        self.assertEqual(tools["nuclei"]["state"], "authorization_required")
        self.assertEqual(result["execution"], "recommendations_only")

        active = recommend_tools({"http": [{"tech": ["FastAPI", "Python"]}]}, include_active=True)
        active_tools = {row["name"]: row for row in active["tools"]}
        self.assertEqual(active_tools["nuclei"]["state"], "available")


if __name__ == "__main__":
    unittest.main()
