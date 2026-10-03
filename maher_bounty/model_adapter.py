class LocalModelAdapter:
    """Adapter point for a local/self-hosted model. No cloud API is required."""
    def analyze(self, agent, context):
        return {"agent":agent["id"],"status":"planned","observations":[],"candidate_findings":[],"evidence_notes":[],"next_checks":[agent["mission"]]}
