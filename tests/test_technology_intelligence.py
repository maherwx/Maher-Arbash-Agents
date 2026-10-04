import tempfile
import unittest
from pathlib import Path

from maher_bounty.technology_intelligence import analyze_source_tree


class TechnologyIntelligenceTests(unittest.TestCase):
    def test_detects_multiple_ecosystems_and_routes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            samples = {
                "api.py": 'from fastapi import FastAPI\napp=FastAPI()\n@app.get("/users/{id}")\ndef get_user(): pass\n',
                "server.ts": 'import express from "express"; const app=express(); app.get("/v1/items", handler);',
                "UserController.java": '@RestController class C { @GetMapping("/accounts") void x(){} }',
                "UsersController.cs": '[ApiController] class C { [HttpGet("/profiles")] void X(){} }',
                "routes.php": '<?php Route::get("/orders", fn()=>null);',
                "routes.rb": 'get("/reports")',
                "main.go": 'package main // gin-gonic\n',
                "lib.rs": 'use axum::Router;',
                "native.cpp": 'int main(){return 0;}',
                "App.swift": 'import Vapor\n',
            }
            for name, body in samples.items():
                (root / name).write_text(body, encoding="utf-8")
            result = analyze_source_tree(root)
            tech = result["technology_counts"]
            for expected in ("python", "javascript_typescript", "java_kotlin", "dotnet", "php", "ruby", "go", "rust", "native", "swift_objc"):
                self.assertIn(expected, tech)
            self.assertGreaterEqual(result["route_count"], 5)
            self.assertIn("fastapi", result["framework_signals"])
            self.assertIn("express", result["framework_signals"])
            self.assertIn("spring", result["framework_signals"])
            self.assertIn("aspnet", result["framework_signals"])


if __name__ == "__main__":
    unittest.main()
