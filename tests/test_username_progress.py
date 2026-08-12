import json
import sys
import types
import unittest
from unittest.mock import Mock, patch


if "rich.progress" not in sys.modules:
    rich_module = types.ModuleType("rich")
    rich_progress = types.ModuleType("rich.progress")

    class DummyConsole:
        def print(self, *args, **kwargs):
            return None

    class DummyProgress:
        def __init__(self, *args, **kwargs):
            self.console = DummyConsole()

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


try:
    import fastapi  # noqa: F401
except ModuleNotFoundError:
    fastapi_module = types.ModuleType("fastapi")
    fastapi_middleware = types.ModuleType("fastapi.middleware")
    fastapi_cors = types.ModuleType("fastapi.middleware.cors")
    pydantic_module = types.ModuleType("pydantic")

    class DummyFastAPI:
        def __init__(self, *args, **kwargs):
            pass

        def add_middleware(self, *args, **kwargs):
            return None

        def get(self, *args, **kwargs):
            return lambda function: function

        def post(self, *args, **kwargs):
            return lambda function: function

    class DummyBaseModel:
        pass

    fastapi_module.FastAPI = DummyFastAPI
    fastapi_cors.CORSMiddleware = object
    pydantic_module.BaseModel = DummyBaseModel
    sys.modules["fastapi"] = fastapi_module
    sys.modules["fastapi.middleware"] = fastapi_middleware
    sys.modules["fastapi.middleware.cors"] = fastapi_cors
    sys.modules["pydantic"] = pydantic_module


import api
import blackbird_tool
import gitfive_tool
import investigator
import maigret_tool
import sherlock_tool
import social_analyzer_tool
import whatsmyname_tool
from parser import merge_results
from verification.confidence import score_account
from verification.generic import verify_generic
from verification.github import verify_github
from username_validation import url_references_username


class UsernameParserTests(unittest.TestCase):
    def test_url_username_match_requires_token_boundaries(self):
        self.assertTrue(
            url_references_username("https://example.com/user/alice", "alice")
        )
        self.assertFalse(
            url_references_username("https://example.com/user/malice", "alice")
        )

    def test_sherlock_requires_target_specific_profile_url(self):
        output = """
[+] Discord: https://discord.com
[+] Instagram: https://instagram.com/alice
[*] Search completed
"""
        accounts = sherlock_tool.parse_sherlock_output(output, "alice")
        self.assertEqual([item["website"] for item in accounts], ["Instagram"])

    def test_blackbird_rejects_log_and_generic_urls(self):
        output = """
[DEBUG] https://example.com/alice
[Discord] https://discord.com
[Reddit] https://reddit.com/user/alice
"""
        accounts = blackbird_tool.parse_blackbird_output(output, "alice")
        self.assertEqual([item["website"] for item in accounts], ["Reddit"])

    def test_maigret_requires_target_specific_profile_url(self):
        output = """
[+] Using sites database: https://example.com/database
[+] GitLab: https://gitlab.com/alice
"""
        accounts = maigret_tool.parse_maigret_output(output, "alice")
        self.assertEqual([item["website"] for item in accounts], ["GitLab"])

    def test_gitfive_requires_exact_username_and_numeric_id(self):
        generic = "Username : someone_else\nID : unknown\nProfile : none"
        self.assertIsNone(gitfive_tool.parse_gitfive_output(generic, "alice"))

        exact = "Username : Alice\nID : 123456\n"
        account = gitfive_tool.parse_gitfive_output(exact, "alice")
        self.assertEqual(account["url"], "https://github.com/Alice")
        self.assertEqual(account["tool"], "GitFive")

    def test_social_analyzer_accepts_only_target_specific_links(self):
        output = "init\n" + json.dumps({
            "detected": [
                {"link": "https://instagram.com/alice"},
                {"link": "https://facebook.com/home"},
            ]
        })
        accounts = social_analyzer_tool.parse_social_analyzer_output(
            output,
            "alice"
        )
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0]["website"], "Instagram")

    @patch("whatsmyname_tool.requests.get")
    def test_whatsmyname_requires_positive_signature(self, get):
        site = {
            "name": "Example",
            "uri_check": "https://example.com/{account}",
            "e_code": 200,
            "e_string": "profile-marker",
            "m_code": 200,
            "m_string": "user-not-found",
        }

        get.return_value = Mock(
            status_code=200,
            text="generic homepage"
        )
        self.assertIsNone(whatsmyname_tool.check_site(site, "alice"))

        get.return_value = Mock(
            status_code=200,
            text="profile-marker for account"
        )
        finding = whatsmyname_tool.check_site(site, "alice")
        self.assertEqual(finding["website"], "Example")

    def test_merge_preserves_username_and_tool_provenance(self):
        accounts = merge_results(
            [{
                "website": "GitHub",
                "url": "https://github.com/alice",
                "tool": "Sherlock",
                "username": "alice",
            }],
            [],
            [],
            [{
                "website": "GitHub",
                "url": "https://github.com/alice/",
                "tool": "WhatsMyName",
                "username": "alice",
            }],
            [],
            [],
        )
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0]["username"], "alice")
        self.assertEqual(accounts[0]["tools"], ["Sherlock", "WhatsMyName"])


class VerificationAndConfidenceTests(unittest.TestCase):
    @patch("verification.generic.requests.get")
    def test_generic_username_echo_is_not_verified(self, get):
        get.return_value = Mock(
            status_code=200,
            url="https://example.com/alice",
            text="<html><title>Profile</title>alice</html>",
        )
        account = verify_generic({
            "website": "Example",
            "url": "https://example.com/alice",
            "username": "alice",
        })
        self.assertEqual(account["verification"], "Needs Review")

    @patch("verification.generic.requests.get")
    def test_redirect_to_generic_homepage_is_rejected(self, get):
        get.return_value = Mock(
            status_code=200,
            url="https://example.com/",
            text="<html><title>Example</title></html>",
        )
        account = verify_generic({
            "website": "Example",
            "url": "https://example.com/alice",
            "username": "alice",
        })
        self.assertEqual(account["verification"], "False Positive")

    @patch("verification.github.requests.get")
    def test_github_api_can_platform_verify_exact_username(self, get):
        response = Mock(status_code=200)
        response.json.return_value = {"login": "Alice", "id": 123}
        get.return_value = response

        account = verify_github({
            "website": "GitHub",
            "url": "https://github.com/alice",
            "username": "alice",
        })
        self.assertEqual(account["verification"], "Verified")
        self.assertEqual(account["verification_evidence"]["id"], 123)

    def test_correlated_tool_agreement_cannot_create_high_confidence(self):
        account = score_account({
            "website": "Instagram",
            "tools": [
                "Sherlock",
                "Blackbird",
                "Maigret",
                "WhatsMyName",
                "Social Analyzer",
            ],
            "verification": "Needs Review",
        })
        self.assertLess(account["confidence"], 70)
        self.assertNotEqual(account["status"], "High Confidence")

    def test_platform_verification_can_create_high_confidence(self):
        account = score_account({
            "website": "GitHub",
            "tools": ["GitFive"],
            "verification": "Verified",
        })
        self.assertGreaterEqual(account["confidence"], 70)
        self.assertEqual(account["status"], "High Confidence")

    def test_investigator_excludes_explicitly_rejected_username_candidate(self):
        candidate = {
            "website": "Example",
            "url": "https://example.com/alice",
            "tool": "Sherlock",
            "username": "alice",
        }

        def reject(accounts):
            for account in accounts:
                account["verification"] = "False Positive"
            return accounts

        with patch.multiple(
            investigator,
            run_sherlock=Mock(return_value=[candidate]),
            run_blackbird=Mock(return_value=[]),
            run_maigret=Mock(return_value=[]),
            run_gitfive=Mock(return_value={
                "github_found": False,
                "accounts": [],
                "success": True,
            }),
            run_whatsmyname=Mock(return_value=[]),
            run_social_analyzer=Mock(return_value=[]),
            verify_accounts=Mock(side_effect=reject),
            generate_ai_summary=Mock(return_value="summary"),
        ):
            result = investigator.verify_profiles("alice")

        self.assertEqual(result["accounts"], [])
        self.assertEqual(result["summary"]["sherlock"], 0)


class ProgressTests(unittest.TestCase):
    def test_progress_description_marks_raised_tool_failure(self):
        self.assertEqual(
            investigator._tool_progress_description(
                "Sherlock",
                [],
                raised_exception=True,
            ),
            "Failed: Sherlock",
        )

    def test_progress_description_distinguishes_email_unavailability(self):
        self.assertEqual(
            investigator._tool_progress_description(
                "HIBP Email Breach Check",
                {"status": "not_configured", "skipped": True},
            ),
            "Skipped: HIBP Email Breach Check (not configured)",
        )

    @patch("investigator.generate_ai_summary", return_value="summary")
    @patch("investigator.run_social_analyzer", return_value=[])
    @patch("investigator.run_whatsmyname", return_value=[])
    @patch(
        "investigator.run_gitfive",
        return_value={
            "github_found": False,
            "accounts": [],
            "success": True,
        },
    )
    @patch("investigator.run_maigret", return_value=[])
    @patch("investigator.run_blackbird", return_value=[])
    @patch("investigator.run_sherlock", return_value=[])
    def test_every_username_tool_emits_running_and_completion_events(
        self,
        _sherlock,
        _blackbird,
        _maigret,
        _gitfive,
        _whatsmyname,
        _social_analyzer,
        _ai,
    ):
        events = []
        investigator.verify_profiles(
            "alice",
            progress_callback=lambda percent, description: events.append(
                (percent, description)
            ),
        )
        descriptions = [description for _percent, description in events]

        for label in (
            "Sherlock",
            "Blackbird",
            "Maigret",
            "GitFive",
            "WhatsMyName",
            "Social Analyzer",
        ):
            self.assertIn(f"Running: {label}", descriptions)
            self.assertIn(f"Completed: {label}", descriptions)

    @patch("investigator.generate_ai_summary", return_value="summary")
    @patch("investigator.check_email_breaches")
    @patch("investigator.ghunt_email")
    @patch("investigator.run_holehe")
    def test_every_email_tool_emits_running_and_completion_events(
        self,
        run_holehe,
        run_ghunt,
        run_hibp,
        _ai,
    ):
        run_holehe.return_value = {
            "tool": "Holehe",
            "status": "no_results",
            "findings": [],
            "error": None,
            "return_code": 0,
            "diagnostics": {"completed": True},
            "raw_output_path": None,
        }
        run_ghunt.return_value = {
            "tool": "GHunt",
            "status": "no_results",
            "data": {},
            "error": None,
            "return_code": 0,
            "raw_output_path": None,
        }
        run_hibp.return_value = {
            "configured": True,
            "status": "no_results",
            "breached": False,
            "breaches": [],
        }

        events = []
        investigator.verify_profiles(
            "person@example.com",
            progress_callback=lambda percent, description: events.append(
                (percent, description)
            ),
        )
        descriptions = [description for _percent, description in events]

        for label in ("Holehe", "GHunt", "HIBP Email Breach Check"):
            self.assertIn(f"Running: {label}", descriptions)
            self.assertIn(f"Completed: {label}", descriptions)
            self.assertLess(
                descriptions.index(f"Running: {label}"),
                descriptions.index(f"Completed: {label}"),
            )

        completion_percents = [
            percent
            for percent, description in events
            if description.startswith("Completed:")
        ]
        completion_deltas = [
            percent - (completion_percents[index - 1] if index else 0)
            for index, percent in enumerate(completion_percents)
        ]

        self.assertEqual(completion_percents[-1], 85)
        self.assertEqual(sorted(completion_deltas), [17, 34, 34])

    def test_api_keeps_all_progress_events(self):
        api.JOBS["test-job"] = {
            "target": "alice",
            "percent": 0,
            "description": "Starting OSINT Scan...",
            "done": False,
            "results": None,
            "error": None,
            "events": [],
        }

        def fake_scan(target, progress_callback):
            progress_callback(0, "Running: Sherlock")
            progress_callback(20, "Completed: Sherlock")
            progress_callback(20, "Running: WhatsMyName")
            progress_callback(100, "Completed: WhatsMyName")
            return {"target": target}

        with patch("api.verify_profiles", side_effect=fake_scan):
            api._run_scan_job("test-job", "alice")

        descriptions = [
            event["description"]
            for event in api.JOBS["test-job"]["events"]
        ]
        self.assertEqual(
            descriptions[:4],
            [
                "Running: Sherlock",
                "Completed: Sherlock",
                "Running: WhatsMyName",
                "Completed: WhatsMyName",
            ],
        )
        self.assertEqual(descriptions[-1], "Investigation completed")

    def test_api_status_returns_stable_event_snapshot(self):
        api.JOBS["snapshot-job"] = {
            "target": "person@example.com",
            "percent": 0,
            "description": "Starting OSINT Scan...",
            "done": False,
            "results": None,
            "error": None,
            "events": [],
        }

        api._record_progress("snapshot-job", 0, "Running: Holehe")
        snapshot = api.status("snapshot-job")
        api._record_progress("snapshot-job", 34, "Completed: Holehe")

        self.assertEqual(len(snapshot["events"]), 1)
        self.assertEqual(len(api.status("snapshot-job")["events"]), 2)


if __name__ == "__main__":
    unittest.main()
