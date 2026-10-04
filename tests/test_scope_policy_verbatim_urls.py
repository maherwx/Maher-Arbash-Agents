import unittest

from maher_bounty.scope_policy import filter_in_scope_urls, scope_seed_targets, scope_target_urls


class VerbatimUrlTests(unittest.TestCase):
    def test_scope_assets_and_endpoint_urls_are_preserved_exactly(self):
        asset = "HTTPS://app.example.test:8443/a%2Fb/?next=%2Fhome#part"
        endpoint = "https://app.example.test/api/v2?q=a%2Fb&x=1"
        scope = {"assets": [asset]}
        inventory = {"endpoints": [{"value": endpoint}]}

        allowed, rejected = scope_target_urls(scope, inventory)

        self.assertEqual(allowed, [asset, endpoint])
        self.assertEqual(rejected, [])

    def test_filter_does_not_trim_or_rewrite_candidate_urls(self):
        url = "https://app.example.test/a%2Fb/?q=%2F"
        allowed, rejected = filter_in_scope_urls([url], {"assets": ["app.example.test"]})
        self.assertEqual(allowed, [url])
        self.assertEqual(rejected, [])

        spaced = " " + url
        allowed, rejected = filter_in_scope_urls([spaced], {"assets": ["app.example.test"]})
        self.assertEqual(allowed, [])
        self.assertEqual(rejected, [spaced])

    def test_explicit_seed_keeps_path_and_wildcard_seed_is_generated(self):
        explicit = "https://app.example.test/start?mode=full"
        self.assertEqual(scope_seed_targets({"assets": [explicit]}), [explicit])
        self.assertEqual(scope_seed_targets({"assets": ["*.example.test"]}), ["https://example.test"])


if __name__ == "__main__":
    unittest.main()
