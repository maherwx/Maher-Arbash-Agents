import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from maher_bounty.tool_orchestration import _domain, plan_tools, collect_target_inventory


class ToolOrchestrationTests(unittest.TestCase):
    def test_domain_parsing(self):
        self.assertEqual(_domain("https://app.example.com/path"), "app.example.com")
        self.assertEqual(_domain("example.com"), "example.com")

    def test_safe_plan_does_not_enable_active_discovery(self):
        plan=plan_tools("https://example.com", {})
        self.assertFalse(plan["active_discovery_enabled"])
        self.assertIn("subfinder", plan["selected"])
        self.assertTrue(any(x["tool"]=="nmap" for x in plan["skipped"]))

    def test_active_plan_requires_explicit_rule(self):
        plan=plan_tools("https://example.com", {"allow_active_discovery":True})
        self.assertTrue(plan["active_discovery_enabled"])
        self.assertIn("nmap", plan["selected"])

    @patch("maher_bounty.tool_orchestration._run")
    @patch("maher_bounty.tool_orchestration.shutil.which")
    def test_inventory_is_built_from_collected_files(self, which, run):
        which.return_value="/bin/tool"
        def fake_run(cmd, stdout_path=None, timeout=30):
            if stdout_path:
                stdout_path.parent.mkdir(parents=True,exist_ok=True)
                if cmd[0]=="subfinder":
                    stdout_path.write_text("a.example.com\n",encoding="utf-8")
                elif cmd[0]=="assetfinder":
                    stdout_path.write_text("b.example.com\n",encoding="utf-8")
                elif cmd[0]=="waybackurls":
                    stdout_path.write_text("https://example.com/a\n",encoding="utf-8")
                elif cmd[0]=="gau":
                    stdout_path.write_text("https://example.com/b\n",encoding="utf-8")
            if cmd[0]=="httpx":
                p=Path(cmd[-1]); p.write_text('{"url":"https://a.example.com","status_code":200,"title":"A","tech":["x"]}\n',encoding="utf-8")
            return {"tool":cmd[0],"status":"ok","command":cmd}
        run.side_effect=fake_run
        with tempfile.TemporaryDirectory() as td:
            inv=collect_target_inventory("https://example.com",td)
            # exact target is seeded in addition to discovered assets
            self.assertEqual(inv["counts"]["hosts"],3)
            self.assertEqual(inv["counts"]["endpoints"],3)
            self.assertEqual(inv["counts"]["http"],1)
            self.assertEqual(inv["target"],"https://example.com")
            self.assertTrue((Path(td)/"tool-orchestration.json").is_file())


if __name__=="__main__":
    unittest.main()
