import os
from threading import Lock

from ghunt_tool import ghunt_email
from whatsmyname_tool import run_whatsmyname
from parser import merge_results
from verification.confidence import (
    calculate_investigation_confidence,
    score_accounts,
)
from verification.engine import verify_accounts

from holehe_tool import run_holehe
from sherlock_tool import run_sherlock
from blackbird_tool import run_blackbird
from maigret_tool import run_maigret
from gitfive_tool import run_gitfive
from hibp_tool import check_email_breaches
from email_parser import merge_email_results

# Ollama AI integration
from ai_analyzer import generate_ai_summary

from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn
)


_DEFAULTS = {
    "holehe": [],
    "ghunt": {},
    "sherlock": [],
    "blackbird": [],
    "maigret": [],
    "gitfive": {
        "github_found": False,
        "accounts": []
    },
    "whatsmyname": [],
    "hibp": {
        "configured": False,
        "skipped": True
    },
}


def _email_tool_failure_result(name, error):
    """Create an email-only fallback without changing other pipelines."""

    if name == "holehe":
        return {
            "tool": "Holehe",
            "status": "failed",
            "findings": [],
            "error": str(error),
            "return_code": None,
            "diagnostics": {},
            "raw_output_path": None,
        }

    if name == "ghunt":
        return {
            "tool": "GHunt",
            "status": "failed",
            "data": {},
            "error": str(error),
            "return_code": None,
            "raw_output_path": None,
        }

    if name == "hibp":
        return {
            "configured": None,
            "status": "failed",
            "error": str(error),
        }

    return _DEFAULTS.get(name)


def _email_status_snapshot(tool_result):
    """Expose execution state without duplicating full findings or raw data."""

    if not isinstance(tool_result, dict):
        return {
            "status": "unknown",
            "error": "Unexpected tool result format"
        }

    fields = (
        "tool",
        "status",
        "error",
        "return_code",
        "raw_output_path",
        "configured",
        "skipped",
        "reason",
        "diagnostics",
    )

    return {
        field: tool_result[field]
        for field in fields
        if field in tool_result
    }


def _tool_progress_description(label, tool_result, raised_exception=False):
    """Describe completion consistently without changing tool contracts."""

    if raised_exception:
        return f"Failed: {label}"

    if isinstance(tool_result, dict):
        status = tool_result.get("status")

        if status == "timeout":
            return f"Timed out: {label}"
        if status == "missing_executable":
            return f"Unavailable: {label}"
        if status == "not_configured" or tool_result.get("skipped") is True:
            return f"Skipped: {label} (not configured)"
        if status == "rate_limited":
            return f"Rate limited: {label}"
        if status == "parser_failure":
            return f"Parser failure: {label}"
        if status == "failed" or tool_result.get("success") is False:
            return f"Failed: {label}"
        if status == "partial":
            return f"Completed with limitations: {label}"

    return f"Completed: {label}"


def verify_profiles(target, progress_callback=None):

    is_email = "@" in target
    is_domain = "." in target and not is_email

    # An email local part is not a verified username.  Keep this field for
    # backward-compatible result shape, but explicitly mark it not applicable.
    username = None if is_email else target

    # -----------------------------
    # Create jobs
    # -----------------------------

    jobs = []


    def add_job(name, func, weight, label):
        jobs.append(
            (name, func, weight, label)
        )


    # Email based tools
    if is_email:
        add_job(
            "holehe",
            lambda: run_holehe(target),
            10,
            "Holehe"
        )

        add_job(
            "ghunt",
            lambda: ghunt_email(target),
            10,
            "GHunt"
        )

        add_job(
            "hibp",
            lambda: check_email_breaches(target),
            5,
            "HIBP Email Breach Check"
        )


# -----------------------------
# Username Investigation
# -----------------------------

    if not is_email:

        add_job(
        "sherlock",
        lambda: run_sherlock(username),
        15,
        "Sherlock"
    )

        add_job(
        "blackbird",
        lambda: run_blackbird(username),
        10,
        "Blackbird"
    )

        add_job(
        "maigret",
        lambda: run_maigret(username),
        10,
        "Maigret"
    )

        add_job(
        "gitfive",
        lambda: run_gitfive(username),
        10,
        "GitFive"
    )

        add_job(
        "whatsmyname",
        lambda: run_whatsmyname(username),
        5,
        "WhatsMyName"
    )



    # -----------------------------
    # Run tools concurrently
    # -----------------------------

    total_weight = sum(job[2] for job in jobs) or 1

    results = {}

    completed_weight = {
        "value": 0
    }

    # Tool-start callbacks can be emitted by concurrent workers. Keep console
    # output, percentage state, and the external callback in one ordered stream
    # so the API cannot lose a fast tool event between simultaneous starts.
    progress_event_lock = Lock()


    def on_tool_done(
        name,
        weight,
        label,
        tool_result,
        raised_exception=False,
        rich_task=None,
        rich_progress=None
    ):

        with progress_event_lock:
            completed_weight["value"] += weight

            percent = min(
                int(
                    completed_weight["value"]
                    /
                    total_weight
                    *
                    85
                ),
                85
            )

            description = _tool_progress_description(
                label,
                tool_result,
                raised_exception
            )


            if rich_progress:
                console = getattr(rich_progress, "console", None)
                console_print = getattr(console, "print", None)
                if console_print:
                    console_print(f"✓ {description}")

                rich_progress.update(
                    rich_task,
                    completed=percent,
                    description=description
                )


            if progress_callback:
                progress_callback(
                    percent,
                    description
                )



    with Progress(
        SpinnerColumn(),
        TextColumn(
            "[progress.description]{task.description}"
        ),
        BarColumn(),
        TextColumn(
            "{task.percentage:>3.0f}%"
        )
    ) as progress:


        task = progress.add_task(
            "Starting OSINT Scan...",
            total=100
        )


        if progress_callback:
            progress_callback(
                0,
                "Starting OSINT Scan..."
            )

        def run_with_progress(func, label):
            """Emit a start event when the worker actually begins the tool."""

            with progress_event_lock:
                percent = min(
                    int(
                        completed_weight["value"]
                        /
                        total_weight
                        *
                        85
                    ),
                    85
                )
                description = f"Running: {label}"

                console = getattr(progress, "console", None)
                console_print = getattr(console, "print", None)
                if console_print:
                    console_print(f"→ {description}")

                if progress_callback:
                    progress_callback(percent, description)

            return func()


        with ThreadPoolExecutor(
            max_workers=max(len(jobs), 1)
        ) as executor:


            future_map = {

                executor.submit(run_with_progress, func, label):
                (
                    name,
                    weight,
                    label
                )

                for name, func, weight, label in jobs

            }


            for future in as_completed(future_map):

                name, weight, label = future_map[future]

                print(f"[DEBUG] Future finished: {label}")


                raised_exception = False

                try:
                    results[name] = future.result()

                    print(f"[DEBUG] {label} returned successfully")

                except Exception as exc:

                    raised_exception = True

                    if is_email and name in {"holehe", "ghunt", "hibp"}:
                        results[name] = _email_tool_failure_result(name, exc)
                    else:
                        results[name] = _DEFAULTS.get(name)

                        print(f"[DEBUG] Calling on_tool_done for {label}")


                on_tool_done(
                    name,
                    weight,
                    label,
                    results[name],
                    raised_exception,
                    task,
                    progress
                )



        progress.update(
            task,
            completed=100,
            description="All OSINT tools completed"
        )



    if progress_callback:
        progress_callback(
            85,
            "All OSINT tools completed"
        )



    # -----------------------------
    # Collect results
    # -----------------------------

    holehe_result = results.get(
        "holehe",
        _DEFAULTS["holehe"]
    )

    if isinstance(holehe_result, dict) and "findings" in holehe_result:
        holehe = holehe_result.get("findings", [])
    else:
        # Compatibility with an older/custom wrapper that still returns a list.
        holehe = holehe_result if isinstance(holehe_result, list) else []

    ghunt_result = results.get(
        "ghunt",
        _DEFAULTS["ghunt"]
    )

    if isinstance(ghunt_result, dict) and "data" in ghunt_result:
        if ghunt_result.get("status") in {"success", "partial"}:
            ghunt = ghunt_result.get("data", {})
        else:
            ghunt = {}
    else:
        # Accept only legacy output that contains actual Gaia evidence.
        ghunt = (
            ghunt_result
            if isinstance(ghunt_result, dict)
            and ghunt_result.get("account_found") is True
            and ghunt_result.get("gaia_id")
            else {}
        )

    sherlock = results.get(
        "sherlock",
        _DEFAULTS["sherlock"]
    )

    blackbird = results.get(
        "blackbird",
        _DEFAULTS["blackbird"]
    )

    maigret = results.get(
        "maigret",
        _DEFAULTS["maigret"]
    )

    gitfive = results.get(
        "gitfive",
        _DEFAULTS["gitfive"]
    )
    whatsmyname = results.get(
        "whatsmyname",
        _DEFAULTS["whatsmyname"]
    )


    if is_email:

        hibp = results.get(
            "hibp",
            _DEFAULTS["hibp"]
        )

        email_tool_status = {
            "holehe": _email_status_snapshot(holehe_result),
            "ghunt": _email_status_snapshot(ghunt_result),
            "hibp": _email_status_snapshot(hibp),
        }

    else:

        hibp = {
            "configured": None,
            "skipped": True,
            "reason":
            "HIBP breach lookup only applies to email targets."
        }

# -----------------------------
# Merge Results
# -----------------------------
    
    detected_account_count = None

    if is_email:

        accounts = merge_email_results(
            ghunt=ghunt,
            holehe=holehe,
        )

    else:

        accounts = merge_results(
            sherlock,
            blackbird,
            maigret,
            whatsmyname,
            gitfive.get(
                "accounts",
                []
            ),
        )
    detected_account_count = len(accounts)

    if is_domain:
        # Preserve the existing domain path during the username-only
        # accuracy pass.
        accounts = score_accounts(accounts, evidence_aware=False)
        accounts = verify_accounts(accounts)

    elif not is_email:
        # Verification must precede confidence.
        print("[+] Verifying username candidates...")

        if progress_callback:
            progress_callback(85, "Verifying username candidates")

        accounts = verify_accounts(accounts)

        accounts = [
            account
            for account in accounts
            if account.get("verification") != "False Positive"
        ]

        accounts = score_accounts(accounts)

        if progress_callback:
            progress_callback(
                95,
                "Username candidate verification completed",
            )

        # Do not leave the legacy GitHub flag positive after the GitHub
        # platform check explicitly rejected its only candidate.
        accepted_gitfive = any(
            "GitFive" in account.get("tools", [])
            for account in accounts
        )

        if gitfive.get("github_found") and not accepted_gitfive:
            gitfive = dict(gitfive)
            gitfive["github_found"] = False
            gitfive["accounts"] = []



    if hibp.get("error"):

        hibp_summary = "Error"

    elif hibp.get("skipped"):

        hibp_summary = "Not Configured"

    elif hibp.get("breached"):

        hibp_summary = (
            f"{len(hibp.get('breaches', []))} Breach(es)"
        )

    else:

        hibp_summary = "No Breaches Found"


    def accepted_tool_count(tool_name, fallback):
        if is_email or is_domain:
            return fallback

        return sum(
            1
            for account in accounts
            if tool_name in account.get("tools", [])
        )


    confidence_result = calculate_investigation_confidence(
        target=target,
        accounts=accounts,
        ghunt=ghunt,
        holehe=holehe,
        hibp=hibp,
        detected_account_count=detected_account_count,
    )
    harvester_summary = 0


    final_result = {

        "target": target,

        "username": username,

        "accounts": accounts,

        "confidence": confidence_result["score"],

        "confidence_level": confidence_result["level"],

        "confidence_reasons": confidence_result["reasons"],

        "confidence_breakdown": confidence_result["breakdown"],

        "holehe": holehe,

        "ghunt": ghunt,

        "gitfive": gitfive,

        "hibp": hibp,

        "whatsmyname": whatsmyname,


        "summary": {

            "sherlock": accepted_tool_count("Sherlock", len(sherlock)),

            "blackbird": accepted_tool_count("Blackbird", len(blackbird)),

            "maigret": accepted_tool_count("Maigret", len(maigret)),

            "gitfive":
                accepted_tool_count(
                    "GitFive",
                    1 if gitfive.get("github_found") else 0
                ),

            "holehe":
                len(holehe)
                if isinstance(holehe, list)
                else 0,

            "ghunt":
                1 if (
                    isinstance(ghunt, dict)
                    and ghunt.get("account_found") is True
                    and ghunt.get("gaia_id")
                )
                else 0,

            "ghunt_services":
                len(ghunt.get("google_services", []))
                if (
                    isinstance(ghunt, dict)
                    and isinstance(ghunt.get("google_services"), list)
                )
                else 0,

            "whatsmyname":
                accepted_tool_count("WhatsMyName", len(whatsmyname)),

            "hibp":
                hibp_summary,

            "unique":
                len(accounts)

        }

    }

    # Additive email-only compatibility field: existing frontend keys remain
    # unchanged, and non-email result shapes are not modified.
    if is_email:
        final_result["email_tool_status"] = email_tool_status



    # -----------------------------
    # Ollama AI Summary
    # -----------------------------

    if progress_callback:
        progress_callback(
            95,
            "Generating AI Risk Summary..."
        )


    try:

        ai_summary = generate_ai_summary(
            final_result
        )


    except Exception as e:

        ai_summary = {
            "error": str(e)
        }



    final_result["ai_summary"] = ai_summary


    return final_result