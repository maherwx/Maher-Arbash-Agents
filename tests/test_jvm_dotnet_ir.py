import tempfile
import unittest
from pathlib import Path

from maher_bounty.jvm_dotnet_ir import analyze_java, analyze_csharp
from maher_bounty.unified_ir import from_structural_ir, merge_ir


class JvmDotnetIRTests(unittest.TestCase):
    def test_java_and_csharp_join_unified_ir(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            (root/'Users.java').write_text('''
class Users {
  public User loadUser(String id) { return repo.find(id); }
  @GetMapping("/users/{id}")
  public User getUser(String id) { if (id == null) throw new RuntimeException(); return loadUser(id); }
}
''',encoding='utf-8')
            (root/'UsersController.cs').write_text('''
class UsersController {
  public User LoadUser(string id) { return repo.Find(id); }
  [HttpGet("/users/{id}")]
  public async Task<User> GetUser(string id) { if (id == null) throw new Exception(); return LoadUser(id); }
}
''',encoding='utf-8')
            java=analyze_java(root); cs=analyze_csharp(root)
            merged=merge_ir(from_structural_ir(java),from_structural_ir(cs))
            self.assertGreaterEqual(java['function_count'],2)
            self.assertGreaterEqual(cs['function_count'],2)
            self.assertEqual(set(merged['languages']),{'java','csharp'})
            self.assertGreaterEqual(merged['route_function_count'],2)
            self.assertGreaterEqual(len(merged['call_edges']),2)
            self.assertEqual(merged['schema_version'],'1.3')


if __name__=='__main__':
    unittest.main()
