import unittest

from maher_bounty.full_analysis_pipeline import analyze_full
from maher_bounty.performance_guard import measure


class LargeProjectPerformanceTests(unittest.TestCase):
    def test_thousand_function_project_stays_bounded(self):
        functions=[]
        for i in range(1000):
            functions.append({"id":f"fn{i}","language":"python" if i%2==0 else "go","file":f"src/m{i%20}/f{i}.py","name":f"func{i}","line":i+1,"async_function":False,"parameters":[],"calls":[f"func{i+1}"] if i<999 else [],"reads":[f"v{i}"],"writes":[f"v{i+1}"],"complexity":1,"route_bindings":[]})
        measured=measure(lambda:analyze_full({"language":"mixed","functions":functions},min_resolution=.99,min_flow=.99))
        self.assertTrue(measured["result"]["ready"])
        self.assertLess(measured["elapsed_seconds"],15.0)
        self.assertLess(measured["peak_bytes"],256*1024*1024)


if __name__=="__main__":unittest.main()
