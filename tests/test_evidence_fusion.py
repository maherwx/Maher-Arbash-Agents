import unittest

from maher_bounty.evidence_fusion import fuse_sources, normalize_source


class EvidenceFusionTests(unittest.TestCase):
    def signal(self, protocol, url):
        return {"protocol":protocol,"key":"x","metadata":{"url":url}}

    def test_normalizes_protocol_source(self):
        result=normalize_source("traffic",{"signals":[self.signal("GraphQL","https://api.example.test/graphql")]})
        self.assertEqual(result["signals"][0]["protocol"],"graphql")
        self.assertEqual(result["signals"][0]["host"],"api.example.test")

    def test_two_sources_promote_agreement(self):
        a={"source":"traffic","signals":[self.signal("graphql","https://api.example.test/graphql")]}
        b={"source":"replay","signals":[self.signal("graphql","https://api.example.test/gql")]}
        result=fuse_sources(a,b)
        self.assertEqual(result["agreement_count"],1)
        self.assertEqual(result["disagreement_count"],0)
        self.assertGreaterEqual(result["agreements"][0]["confidence"],0.88)

    def test_single_source_is_not_promoted(self):
        a={"source":"traffic","signals":[self.signal("graphql","https://api.example.test/graphql")]}
        self.assertEqual(fuse_sources(a)["agreement_count"],0)

    def test_conflicting_protocol_classes_are_retained_as_disagreement(self):
        a={"source":"traffic","signals":[self.signal("graphql","https://api.example.test/graphql")]}
        b={"source":"replay","signals":[self.signal("grpc","https://api.example.test/pkg.Service/Method")]}
        result=fuse_sources(a,b)
        self.assertEqual(result["agreement_count"],0)
        self.assertEqual(result["disagreement_count"],1)
        self.assertEqual(result["disagreements"][0]["protocols"],["graphql","grpc"])

    def test_different_hosts_do_not_cross_correlate(self):
        a={"source":"traffic","signals":[self.signal("graphql","https://one.test/graphql")]}
        b={"source":"replay","signals":[self.signal("graphql","https://two.test/graphql")]}
        result=fuse_sources(a,b)
        self.assertEqual(result["agreement_count"],0)


if __name__=="__main__":
    unittest.main()
