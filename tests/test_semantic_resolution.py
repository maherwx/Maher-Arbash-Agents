import unittest
from maher_bounty.semantic_resolution import build_semantic_model, rank_call_candidates


class SemanticResolutionTests(unittest.TestCase):
    def test_context_ranks_candidate(self):
        caller={"id":"a","file":"svc/api.py","language":"python","reads":["account.id"],"writes":[],"route_bindings":[{"path":"/account"}]}
        candidates=[{"id":"b","file":"svc/store.py","language":"python","reads":["account.id"],"writes":["db.account"],"route_bindings":[{"path":"/account"}]},{"id":"c","file":"other/cache.go","language":"go","reads":[],"writes":["cache"],"route_bindings":[]}]
        ranked=rank_call_candidates(caller,"lookup",candidates)
        self.assertEqual(ranked[0]["id"],"b")
        self.assertGreater(ranked[0]["confidence"],ranked[1]["confidence"])

    def test_model_resolves_clear_winner(self):
        ir={"functions":[{"id":"a","file":"svc/api.py","language":"python","reads":["account.id"],"writes":[],"route_bindings":[{"path":"/account"}]},{"id":"b","file":"svc/store.py","language":"python","reads":["account.id"],"writes":[],"route_bindings":[{"path":"/account"}]},{"id":"c","file":"x/cache.go","language":"go","reads":[],"writes":[],"route_bindings":[]}],"unresolved_calls":[{"caller":"a","symbol":"lookup","candidates":["b","c"]}]}
        result=build_semantic_model(ir)
        self.assertEqual(result["resolution_count"],1)
        self.assertEqual(result["call_resolutions"][0]["resolved"],"b")

    def test_close_candidates_are_deferred(self):
        ir={"functions":[{"id":"a","file":"api.py","language":"python","reads":[],"writes":[],"route_bindings":[]},{"id":"b","file":"b.py","language":"python","reads":[],"writes":[],"route_bindings":[]},{"id":"c","file":"c.py","language":"python","reads":[],"writes":[],"route_bindings":[]}],"unresolved_calls":[{"caller":"a","symbol":"lookup","candidates":["b","c"]}]}
        result=build_semantic_model(ir)
        self.assertEqual(result["resolution_count"],0)
        self.assertEqual(result["deferred_count"],1)


if __name__=="__main__":unittest.main()
