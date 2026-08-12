import sys
import types
import unittest
from unittest.mock import Mock, patch


if "requests" not in sys.modules:
    requests_stub = types.ModuleType("requests")
    requests_stub.exceptions = types.SimpleNamespace(
        ConnectionError=ConnectionError,
        Timeout=TimeoutError,
    )
    requests_stub.post = Mock()
    sys.modules["requests"] = requests_stub


import ai_analyzer
import ollama_ai


class AiSummaryTests(unittest.TestCase):
    @patch("ai_analyzer.analyze_with_llama", return_value="report")
    def test_evidence_packet_contains_accounts_risk_and_confidence(self, llama):
        result = ai_analyzer.generate_ai_summary({
            "target": "person@example.com",
            "username": None,
            "accounts": [{
                "platform": "Google",
                "source": "GHunt",
                "verification": "Verified",
                "confidence": 90,
            }],
            "holehe": [{"website": "example.com"}],
            "ghunt": {
                "account_found": True,
                "gaia_id": "123",
                "google_services": ["Maps", "Photos"],
            },
            "hibp": {
                "status": "success",
                "breached": True,
                "breaches": ["ExampleBreach"],
            },
            "summary": {
                "holehe": 1,
                "ghunt": 1,
                "ghunt_services": 2,
            },
        })

        self.assertEqual(result, "report")
        evidence = llama.call_args.args[0]
        self.assertIn("Target type: Email", evidence)
        self.assertIn("Platform=Google", evidence)
        self.assertIn("GHunt activated services (2)", evidence)
        self.assertIn("Confirmed breach count: 1", evidence)
        self.assertIn("average=90.0%", evidence)

    def test_ollama_prompt_requests_all_professional_sections(self):
        response = Mock(status_code=200)
        response.json.return_value = {"response": "report"}

        with patch.object(ollama_ai.requests, "post", return_value=response) as post:
            self.assertEqual(ollama_ai.analyze_with_llama("facts"), "report")

        request = post.call_args.kwargs
        prompt = request["json"]["prompt"]
        for heading in (
            "Investigation Overview",
            "Important Findings",
            "Account and Platform Information",
            "Risk Indicators",
            "Confidence Explanation",
            "Threat Assessment",
            "Conclusion",
        ):
            self.assertIn(heading, prompt)
        self.assertEqual(request["timeout"], 300)
        self.assertEqual(request["json"]["options"]["num_predict"], 800)


if __name__ == "__main__":
    unittest.main()
