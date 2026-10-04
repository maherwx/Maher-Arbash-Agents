import unittest

from maher_bounty.correlation_engine import correlate_evidence


class CorrelationEngineTests(unittest.TestCase):
    def test_requires_independent_sources(self):
        one={"source":"traffic","signals":[{"protocol":"graphql","key":"Viewer","metadata":{"url":"https://api.example.test/graphql"}}]}
        self.assertEqual(correlate_evidence(one)["correlation_count"],0)

    def test_correlates_same_host_and_protocol(self):
        traffic={"source":"traffic","signals":[{"protocol":"graphql","key":"Viewer","metadata":{"url":"https://api.example.test/graphql"}}]}
        replay={"source":"replay","signals":[{"protocol":"graphql","key":"Viewer2","metadata":{"url":"https://api.example.test/gql"}}]}
        result=correlate_evidence(traffic,replay)
        self.assertEqual(result["correlation_count"],1)
        item=result["correlations"][0]
        self.assertEqual(item["host"],"api.example.test")
        self.assertEqual(item["protocol"],"graphql")
        self.assertEqual(item["source_count"],2)

    def test_does_not_merge_different_protocols_or_hosts(self):
        a={"source":"a","signals":[{"protocol":"graphql","key":"x","metadata":{"url":"https://one.test/graphql"}}]}
        b={"source":"b","signals":[{"protocol":"grpc","key":"x","metadata":{"url":"https://one.test/service"}}]}
        c={"source":"c","signals":[{"protocol":"graphql","key":"x","metadata":{"url":"https://two.test/graphql"}}]}
        self.assertEqual(correlate_evidence(a,b,c)["correlation_count"],0)


if __name__=="__main__":
    unittest.main()
