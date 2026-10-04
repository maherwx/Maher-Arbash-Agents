import tempfile
import unittest
from pathlib import Path

from maher_bounty.dataflow_intelligence import analyze_source_flows, correlate_runtime_routes
from maher_bounty.database_intelligence import analyze_database_usage


class DataflowDatabaseTests(unittest.TestCase):
    def test_source_to_runtime_correlation(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "api.py").write_text(
                'from fastapi import FastAPI, Request\n'
                'app=FastAPI()\n'
                '@app.get("/users/{id}")\n'
                'def user(request: Request):\n'
                '    q=request.args\n'
                '    return db.execute("select * from users")\n',
                encoding="utf-8",
            )
            analysis = analyze_source_flows(root)
            self.assertGreaterEqual(analysis["signal_count"], 2)
            self.assertGreaterEqual(len(analysis["cross_surface_candidates"]), 1)

            traffic = [{
                "url": "https://example.test/users/123",
                "method": "GET",
                "status": 200,
                "source": "har",
            }]
            corr = correlate_runtime_routes(analysis, traffic)
            self.assertGreaterEqual(corr["correlation_count"], 1)

    def test_database_orm_detection(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "models.py").write_text(
                'from sqlalchemy import select\n'
                'DATABASE_URL="postgresql://user:pass@db/app"\n'
                'session.query(User).filter(User.id == 1)\n'
                'db.execute("select * from users")\n',
                encoding="utf-8",
            )
            result = analyze_database_usage(root)
            self.assertIn("postgresql", result["database_counts"])
            self.assertIn("sqlalchemy", result["orm_counts"])
            self.assertGreaterEqual(result["raw_query_site_count"], 1)


if __name__ == "__main__":
    unittest.main()
