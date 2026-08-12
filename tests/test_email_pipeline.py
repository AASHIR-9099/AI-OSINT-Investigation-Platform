import io
import subprocess
import sys
import types
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch


# The archived project virtual environment does not contain its executable.
# A tiny Rich stand-in keeps this unit suite independent from the console UI.
if "rich.progress" not in sys.modules:
    rich_module = types.ModuleType("rich")
    rich_progress = types.ModuleType("rich.progress")

    class DummyProgress:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def add_task(self, *args, **kwargs):
            return 1

        def update(self, *args, **kwargs):
            return None

    rich_progress.Progress = DummyProgress
    rich_progress.SpinnerColumn = lambda *args, **kwargs: object()
    rich_progress.BarColumn = lambda *args, **kwargs: object()
    rich_progress.TextColumn = lambda *args, **kwargs: object()
    rich_module.progress = rich_progress
    sys.modules["rich"] = rich_module
    sys.modules["rich.progress"] = rich_progress


import ghunt_tool
import hibp_tool
import holehe_tool
import investigator
from email_parser import merge_email_results
from report_generator import generate_report


class EmailPipelineTests(unittest.TestCase):
    def test_holehe_parser_accepts_only_positive_service_domains(self):
        output = """
[+] twitter.com
[+] duolingo.com
[+] Email used, [-] Email not used, [x] Rate limit, [!] Error
[x] github.com
[-] adobe.com
[!] gravatar.com
123 websites checked in 12.58 seconds
"""

        findings, diagnostics = holehe_tool.parse_holehe_output(
            output,
            "person@example.com"
        )

        self.assertEqual(
            [item["website"] for item in findings],
            ["twitter.com", "duolingo.com"]
        )
        self.assertTrue(diagnostics["completed"])
        self.assertEqual(diagnostics["rate_limited_checks"], 1)
        self.assertEqual(diagnostics["error_checks"], 1)

    @patch("holehe_tool.os.path.isfile", return_value=False)
    def test_holehe_missing_executable_is_not_a_negative(self, _isfile):
        result = holehe_tool.run_holehe("person@example.com")
        self.assertEqual(result["status"], "missing_executable")
        self.assertEqual(result["findings"], [])
        self.assertIn("not found", result["error"].lower())

    @patch("holehe_tool.save_email_tool_debug_output", return_value="debug.txt")
    @patch("holehe_tool.os.path.isfile", return_value=True)
    @patch("holehe_tool.subprocess.run")
    def test_holehe_successful_negative_is_explicit(
        self,
        run,
        _isfile,
        _debug
    ):
        run.return_value = types.SimpleNamespace(
            returncode=0,
            stdout="[-] adobe.com\n1 website checked in 1.0 seconds\n",
            stderr=""
        )

        result = holehe_tool.run_holehe("person@example.com")
        self.assertEqual(result["status"], "no_results")
        self.assertEqual(result["findings"], [])

    @patch("holehe_tool.save_email_tool_debug_output", return_value="debug.txt")
    @patch("holehe_tool.os.path.isfile", return_value=True)
    @patch("holehe_tool.subprocess.run")
    def test_holehe_timeout_is_explicit(self, run, _isfile, _debug):
        run.side_effect = subprocess.TimeoutExpired("holehe", 5)
        result = holehe_tool.run_holehe("person@example.com", timeout=5)
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["findings"], [])

    @patch("holehe_tool.save_email_tool_debug_output", return_value="debug.txt")
    @patch("holehe_tool.os.path.isfile", return_value=True)
    @patch("holehe_tool.subprocess.run")
    def test_holehe_nonzero_exit_is_a_failure(self, run, _isfile, _debug):
        run.return_value = types.SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="tool failed"
        )

        result = holehe_tool.run_holehe("person@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["raw_output_path"], "debug.txt")

    @patch("ghunt_tool.os.path.isfile", return_value=False)
    def test_ghunt_missing_executable_is_not_a_google_finding(self, _isfile):
        result = ghunt_tool.ghunt_email("person@example.com")
        self.assertEqual(result["status"], "missing_executable")
        self.assertEqual(result["data"], {})

    @patch("ghunt_tool.save_email_tool_debug_output", return_value="debug.txt")
    @patch("ghunt_tool.os.path.isfile", return_value=True)
    @patch("ghunt_tool.subprocess.run")
    def test_ghunt_nonzero_exit_is_a_failure(self, run, _isfile, _debug):
        run.return_value = types.SimpleNamespace(
            returncode=2,
            stdout="",
            stderr="authentication failed"
        )

        result = ghunt_tool.ghunt_email("person@example.com")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["return_code"], 2)
        self.assertEqual(result["data"], {})

    @patch("ghunt_tool.save_email_tool_debug_output", return_value="debug.txt")
    @patch("ghunt_tool.os.path.isfile", return_value=True)
    @patch("ghunt_tool.subprocess.run")
    def test_ghunt_preserves_core_evidence_after_later_failure(
        self,
        run,
        _isfile,
        _debug
    ):
        run.return_value = types.SimpleNamespace(
            returncode=1,
            stdout=(
                "Google Account data\n"
                "Email : person@example.com\n"
                "Gaia ID : 123456789\n"
                "Maps data\n"
            ),
            stderr="Traceback: Maps enrichment failed"
        )

        result = ghunt_tool.ghunt_email("person@example.com")
        self.assertEqual(result["status"], "partial")
        self.assertTrue(result["data"]["account_found"])
        self.assertEqual(result["return_code"], 1)
        self.assertEqual(result["raw_output_path"], "debug.txt")

    @patch("ghunt_tool.save_email_tool_debug_output", return_value="debug.txt")
    @patch("ghunt_tool.os.path.isfile", return_value=True)
    @patch("ghunt_tool.subprocess.run")
    def test_ghunt_empty_output_is_a_parser_failure(self, run, _isfile, _debug):
        run.return_value = types.SimpleNamespace(
            returncode=0,
            stdout="",
            stderr=""
        )

        result = ghunt_tool.ghunt_email("person@example.com")
        self.assertEqual(result["status"], "parser_failure")
        self.assertEqual(result["raw_output_path"], "debug.txt")

    @patch("ghunt_tool.save_email_tool_debug_output", return_value="debug.txt")
    @patch("ghunt_tool.os.path.isfile", return_value=True)
    @patch("ghunt_tool.subprocess.run")
    def test_ghunt_timeout_is_explicit(self, run, _isfile, _debug):
        run.side_effect = subprocess.TimeoutExpired("ghunt", 5)
        result = ghunt_tool.ghunt_email("person@example.com", timeout=5)
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["data"], {})

    @patch("ghunt_tool.save_email_tool_debug_output", return_value="debug.txt")
    @patch("ghunt_tool.os.path.isfile", return_value=True)
    @patch("ghunt_tool.subprocess.run")
    def test_ghunt_unrecognized_output_is_a_parser_failure(
        self,
        run,
        _isfile,
        _debug
    ):
        run.return_value = types.SimpleNamespace(
            returncode=0,
            stdout="GHunt started but produced an unknown format\n",
            stderr=""
        )

        result = ghunt_tool.ghunt_email("person@example.com")
        self.assertEqual(result["status"], "parser_failure")
        self.assertEqual(result["data"], {})

    @patch("ghunt_tool.os.path.isfile", return_value=True)
    @patch("ghunt_tool.subprocess.run")
    def test_ghunt_explicit_negative_is_not_a_failure(self, run, _isfile):
        run.return_value = types.SimpleNamespace(
            returncode=0,
            stdout="[-] No Google account found\n",
            stderr=""
        )

        result = ghunt_tool.ghunt_email("person@example.com")
        self.assertEqual(result["status"], "no_results")
        self.assertEqual(result["data"], {})

    @patch("ghunt_tool.os.path.isfile", return_value=True)
    @patch("ghunt_tool.subprocess.run")
    def test_ghunt_requires_and_preserves_gaia_evidence(self, run, _isfile):
        run.return_value = types.SimpleNamespace(
            returncode=0,
            stdout=(
                "Google Account data\n"
                "Email : person@example.com\n"
                "Gaia ID : 123456789\n"
            ),
            stderr=""
        )

        result = ghunt_tool.ghunt_email("person@example.com")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["data"]["account_found"])
        self.assertEqual(result["data"]["gaia_id"], "123456789")

    @patch("ghunt_tool.save_email_tool_debug_output", return_value="debug.txt")
    @patch("ghunt_tool.os.path.isfile", return_value=True)
    @patch("ghunt_tool.subprocess.run")
    def test_ghunt_rejects_evidence_for_a_different_email(
        self,
        run,
        _isfile,
        _debug
    ):
        run.return_value = types.SimpleNamespace(
            returncode=0,
            stdout=(
                "Google Account data\n"
                "Email : different@example.com\n"
                "Gaia ID : 123456789\n"
            ),
            stderr=""
        )

        result = ghunt_tool.ghunt_email("person@example.com")
        self.assertEqual(result["status"], "parser_failure")
        self.assertEqual(result["data"], {})

    def test_failed_ghunt_dictionary_is_not_merged(self):
        accounts = merge_email_results(
            ghunt={
                "email": "person@example.com",
                "status": "failed",
                "error": "missing executable"
            },
            holehe=[]
        )
        self.assertEqual(accounts, [])

    @patch("hibp_tool.requests.get")
    def test_hibp_successful_negative_is_explicit(self, get):
        get.return_value = Mock(status_code=404)
        result = hibp_tool.check_email_breaches(
            "person@example.com",
            api_key="test-key"
        )
        self.assertEqual(result["status"], "no_results")
        self.assertFalse(result["breached"])

    def test_hibp_missing_key_is_not_a_negative(self):
        with patch.dict("os.environ", {}, clear=True):
            result = hibp_tool.check_email_breaches("person@example.com")

        self.assertEqual(result["status"], "not_configured")
        self.assertTrue(result["skipped"])

    @patch("hibp_tool.requests.get")
    def test_hibp_invalid_json_is_a_parser_failure(self, get):
        response = Mock(status_code=200)
        response.json.side_effect = ValueError("bad json")
        get.return_value = response

        result = hibp_tool.check_email_breaches(
            "person@example.com",
            api_key="test-key"
        )
        self.assertEqual(result["status"], "parser_failure")
        self.assertIn("invalid json", result["error"].lower())

    def test_email_report_uses_email_breach_fields(self):
        result = {
            "target": "person@example.com",
            "username": None,
            "accounts": [],
            "gitfive": {},
            "ghunt": {},
            "hibp": {
                "configured": True,
                "status": "success",
                "breached": True,
                "breaches": ["ExampleBreach"]
            },
            "summary": {},
            "ai_summary": ""
        }

        output = io.StringIO()
        with redirect_stdout(output):
            generate_report(result)

        text = output.getvalue()
        self.assertIn("EMAIL BREACH CHECK", text)
        self.assertIn("Email Status : BREACHED", text)
        self.assertNotIn("Status      : SAFE", text)

    @patch("investigator.generate_ai_summary", return_value="summary")
    @patch("investigator.check_email_breaches")
    @patch("investigator.ghunt_email")
    @patch("investigator.run_holehe")
    def test_complete_email_scan_does_not_derive_or_run_a_username(
        self,
        run_holehe,
        run_ghunt,
        run_hibp,
        _ai
    ):
        run_holehe.return_value = {
            "tool": "Holehe",
            "status": "success",
            "findings": [{
                "website": "twitter.com",
                "email": "localpart@example.com",
                "url": "",
                "source": "Holehe"
            }],
            "error": None,
            "return_code": 0,
            "diagnostics": {"completed": True},
            "raw_output_path": None,
        }
        run_ghunt.return_value = {
            "tool": "GHunt",
            "status": "failed",
            "data": {},
            "error": "authentication failed",
            "return_code": 2,
            "raw_output_path": "debug.txt",
        }
        run_hibp.return_value = {
            "configured": True,
            "status": "no_results",
            "breached": False,
            "breaches": []
        }

        username_tools = (
            "run_sherlock",
            "run_blackbird",
            "run_maigret",
            "run_gitfive",
            "run_whatsmyname",
            "run_social_analyzer",
        )

        patchers = [
            patch.object(investigator, name)
            for name in username_tools
        ]

        mocks = [patcher.start() for patcher in patchers]
        self.addCleanup(lambda: [patcher.stop() for patcher in patchers])

        result = investigator.verify_profiles("localpart@example.com")

        self.assertIsNone(result["username"])
        self.assertEqual(result["ghunt"], {})
        self.assertEqual(result["summary"]["ghunt"], 0)
        self.assertEqual(result["summary"]["holehe"], 1)
        self.assertEqual(
            result["email_tool_status"]["ghunt"]["status"],
            "failed"
        )

        for tool_mock in mocks:
            tool_mock.assert_not_called()

    @patch("investigator.generate_ai_summary", return_value="summary")
    @patch("investigator.run_social_analyzer", return_value=[])
    @patch("investigator.run_whatsmyname", return_value=[])
    @patch(
        "investigator.run_gitfive",
        return_value={"github_found": False, "accounts": []}
    )
    @patch("investigator.run_maigret", return_value=[])
    @patch("investigator.run_blackbird", return_value=[])
    @patch("investigator.run_sherlock", return_value=[])
    def test_username_result_shape_is_not_extended_by_email_status(
        self,
        _sherlock,
        _blackbird,
        _maigret,
        _gitfive,
        _whatsmyname,
        _social,
        _ai
    ):
        result = investigator.verify_profiles("ordinary_username")
        self.assertEqual(result["username"], "ordinary_username")
        self.assertNotIn("email_tool_status", result)


if __name__ == "__main__":
    unittest.main()
