import tempfile
import unittest

from maher_bounty.workflow_execution import _assertions, _json_value, execute_workflows


class JsonPolicyEvidenceTests(unittest.TestCase):
    def test_booleans_cannot_satisfy_numeric_resource_proof(self):
        for body, wanted in [('true', 1), ('false', 0), ('1', True), ('0', False),
                             ('{"roles":[true]}', {"roles": [1]})]:
            with self.subTest(body=body):
                checks = _assertions({"body": body}, {"json_equals": {"": wanted}})
                self.assertFalse(checks[0]["passed"])

    def test_json_number_types_and_escaped_pointer_remain_supported(self):
        self.assertTrue(_assertions({"body": '{"a/b":{"~key":1.0}}'},
                                   {"json_equals": {"/a~1b/~0key": 1}})[0]["passed"])
        huge = 10 ** 400
        self.assertTrue(_assertions({"body": str(huge)}, {"json_equals": {"": huge}})[0]["passed"])

    def test_ambiguous_or_nonfinite_json_cannot_supply_proof_or_capture(self):
        for body in ['{"id":0,"id":42}', '{"nested":{"id":0,"id":42},"id":42}',
                     '{"id":42,"extra":NaN}', '{"id":42,"extra":Infinity}',
                     '{"id":42,"extra":1e400}']:
            with self.subTest(body=body):
                self.assertFalse(_assertions({"body": body}, {"json_equals": {"/id": 42}})[0]["passed"])
                with self.assertRaises(ValueError):
                    _json_value(body, "/id")

    def test_array_pointer_requires_canonical_nonnegative_index(self):
        for pointer in ["/-1", "/01", "/+1", "/ 1", "/-"]:
            with self.subTest(pointer=pointer), self.assertRaises(ValueError):
                _json_value('[10,20]', pointer)
        self.assertEqual(_json_value('[10,20]', "/1"), 20)

    def test_type_confusion_does_not_confirm_forbidden_access(self):
        origin = "https://app.example.test"
        config = {"identities": {n: {"origin": origin} for n in ["owner", "other"]},
                  "access_cases": [{"id": "private", "allowed": ["owner"], "denied": ["other"],
                                    "request": {"url": origin + "/resource"}, "proof": {"json_equals": {"/id": 1}}}]}
        def sender(name, request):
            return {"status": 200, "body": '{"id":1}' if name == "owner" else '{"id":true}'}
        with tempfile.TemporaryDirectory() as td:
            result = execute_workflows(config, {"assets": [origin]}, td, authorized=True, transport=sender)
        self.assertEqual(result["requests"], 4)
        self.assertFalse(result["findings"])

    def test_nonfinite_expectation_rejected_before_network(self):
        origin = "https://app.example.test"
        config = {"identities": {"owner": {"origin": origin}}, "workflows": [{"id": "state", "identity": "owner",
                  "steps": [{"request": {"url": origin}, "expect": {"json_equals": {"/state": float("nan")}}}]}]}
        with tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
            execute_workflows(config, {"assets": [origin]}, td, authorized=True,
                              transport=lambda *_: self.fail("must not issue traffic"))
