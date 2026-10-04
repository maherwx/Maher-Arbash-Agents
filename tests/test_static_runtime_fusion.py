import unittest
from maher_bounty.static_runtime_fusion import fuse_static_runtime


class StaticRuntimeFusionTests(unittest.TestCase):
    def test_runtime_route_maps_to_static_function_and_flow(self):
        static={"ir":{"functions":[{"id":"api:get_account","file":"api.py","language":"python","route_bindings":[{"kind":"http_route","path":"/account"}]}]},"flow":{"functions":{"api:get_account":{"transitive_reads":["request.user"],"transitive_writes":["db.account"]}}}}
        runtime={"protocols":{"signals":[{"protocol":"graphql","metadata":{"url":"https://api.example.test/account"}}]}}
        result=fuse_static_runtime(static,runtime)
        self.assertEqual(result["match_count"],1)
        match=result["matches"][0]
        self.assertEqual(match["function"],"api:get_account")
        self.assertIn("request.user",match["transitive_reads"])
        self.assertIn("db.account",match["transitive_writes"])

    def test_unmatched_runtime_signal_is_retained(self):
        static={"ir":{"functions":[]},"flow":{"functions":{}}}
        runtime={"protocols":{"signals":[{"protocol":"grpc","metadata":{"url":"https://api.example.test/pkg.Service/Method"}}]}}
        result=fuse_static_runtime(static,runtime)
        self.assertEqual(result["match_count"],0)
        self.assertEqual(len(result["unmatched_runtime"]),1)

    def test_prefix_route_matching(self):
        static={"ir":{"functions":[{"id":"api:user","file":"api.ts","language":"javascript_typescript","route_bindings":[{"kind":"http_route","path":"/users"}]}]},"flow":{"functions":{"api:user":{"transitive_reads":[],"transitive_writes":[]}}}}
        runtime={"signals":[{"protocol":"openapi","metadata":{"url":"https://api.example.test/users/42"}}]}
        self.assertEqual(fuse_static_runtime(static,runtime)["match_count"],1)


if __name__=="__main__":unittest.main()
