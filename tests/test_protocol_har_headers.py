import json
import unittest

from maher_bounty.protocol_intelligence import analyze_http_records


class ProtocolHarHeaderTests(unittest.TestCase):
    def test_grpc_detected_from_json_encoded_har_headers(self):
        req=json.dumps({"headers":[{"name":"Content-Type","value":"application/grpc"}]})
        resp=json.dumps({"headers":[{"name":"grpc-status","value":"0"}]})
        result=analyze_http_records([{"url":"https://bench.test/pkg.Service/Method","request_raw":req,"response_raw":resp}])
        self.assertEqual(result["protocol_counts"].get("grpc"),1)
        signal=result["signals"][0]
        self.assertEqual(signal["protocol"],"grpc")
        self.assertEqual(signal["metadata"]["grpc_status"],"0")


if __name__=="__main__":
    unittest.main()
