import unittest

from maher_bounty.scope_policy import filter_in_scope_urls, is_in_scope_url, scope_seed_targets, scope_target_urls


class ScopePolicyTests(unittest.TestCase):
    def test_exact_asset_does_not_expand_to_subdomains(self):
        scope = {"assets": ["example.test"]}
        self.assertTrue(is_in_scope_url("https://example.test/a", scope))
        self.assertFalse(is_in_scope_url("https://api.example.test/a", scope))

    def test_wildcard_asset_allows_only_subdomains(self):
        scope = {"assets": ["*.example.test"]}
        self.assertTrue(is_in_scope_url("https://api.example.test/a", scope))
        self.assertFalse(is_in_scope_url("https://example.test/a", scope))
        self.assertFalse(is_in_scope_url("https://example.test.evil/a", scope))

    def test_out_of_scope_overrides_allowlist(self):
        scope = {"assets": ["*.example.test"], "out_of_scope": ["admin.example.test"]}
        self.assertFalse(is_in_scope_url("https://admin.example.test/", scope))
        self.assertTrue(is_in_scope_url("https://api.example.test/", scope))

    def test_rejects_non_http_and_credentials(self):
        scope = {"assets": ["example.test"]}
        self.assertFalse(is_in_scope_url("file:///etc/passwd", scope))
        self.assertFalse(is_in_scope_url("https://user:pass@example.test/", scope))

    def test_target_is_an_exact_fallback_allow_rule(self):
        self.assertTrue(is_in_scope_url("https://example.test/", {}, target="https://example.test"))
        self.assertFalse(is_in_scope_url("https://sub.example.test/", {}, target="https://example.test"))

    def test_filter_returns_rejected_candidates_for_audit(self):
        allowed, rejected = filter_in_scope_urls(
            ["https://example.test/", "https://other.test/", "https://example.test/"],
            {"assets": ["example.test"]},
        )
        self.assertEqual(allowed, ["https://example.test/"])
        self.assertEqual(rejected, ["https://other.test/"])

    def test_wildcard_scope_discovers_and_admits_all_matching_hosts(self):
        scope = {"assets": ["*.example.test"], "out_of_scope": ["admin.example.test"]}
        inventory = {"hosts": [
            {"value": "app.example.test"},
            {"value": "api.example.test"},
            {"value": "admin.example.test"},
            {"value": "outside.test"},
        ]}
        targets, _ = scope_target_urls(scope, inventory, target="example.test")
        self.assertEqual(targets, ["https://app.example.test", "https://api.example.test"])

    def test_seed_targets_include_wildcard_parent_for_passive_enumeration(self):
        self.assertEqual(
            scope_seed_targets({"assets": ["*.example.test", "https://app.other.test"]}),
            ["https://example.test", "https://app.other.test"],
        )


if __name__ == "__main__":
    unittest.main()
