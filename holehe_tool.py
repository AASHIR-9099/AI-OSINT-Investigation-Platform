import subprocess
import os
import re

from email_debug import save_email_tool_debug_output

HOLEHE_EXECUTABLE = os.path.expanduser(
    "~/holehe/venv/bin/holehe"
)


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SERVICE_NAME = re.compile(
    r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?(?:\.[a-z0-9_-]+)+$",
    re.IGNORECASE
)


def parse_holehe_output(output, email):
    """Parse only genuine Holehe positive service lines."""

    findings = []
    seen = set()
    diagnostics = {
        "completed": False,
        "negative_checks": 0,
        "rate_limited_checks": 0,
        "error_checks": 0,
    }

    for raw_line in output.splitlines():
        line = ANSI_ESCAPE.sub("", raw_line).strip()

        if re.search(r"\b\d+\s+websites?\s+checked\b", line, re.IGNORECASE):
            diagnostics["completed"] = True

        if line.startswith("[-]"):
            diagnostics["negative_checks"] += 1
            continue

        if line.startswith("[x]"):
            diagnostics["rate_limited_checks"] += 1
            continue

        if line.startswith("[!]"):
            diagnostics["error_checks"] += 1
            continue

        if not line.startswith("[+]"):
            continue

        service = line[3:].strip().lower()

        # Holehe positives are service domains such as "twitter.com".
        # Requiring that shape excludes banners and the final legend line.
        if not SERVICE_NAME.fullmatch(service):
            continue

        if service in seen:
            continue

        seen.add(service)
        findings.append({
            "website": service,
            "email": email,
            "url": "",
            "source": "Holehe"
        })

    return findings, diagnostics


def _holehe_result(
    status,
    *,
    findings=None,
    error=None,
    return_code=None,
    diagnostics=None,
    raw_output_path=None
):
    return {
        "tool": "Holehe",
        "status": status,
        "findings": findings or [],
        "error": error,
        "return_code": return_code,
        "diagnostics": diagnostics or {},
        "raw_output_path": raw_output_path,
    }


def run_holehe(email, timeout=120):

    if not os.path.isfile(HOLEHE_EXECUTABLE):
        return _holehe_result(
            "missing_executable",
            error=f"Holehe executable not found: {HOLEHE_EXECUTABLE}"
        )

    try:

        result = subprocess.run(
            [
                HOLEHE_EXECUTABLE,
                email
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")

        raw_output_path = save_email_tool_debug_output(
            "Holehe",
            email,
            stdout,
            stderr
        )

        return _holehe_result(
            "timeout",
            error=f"Holehe timed out after {timeout} seconds",
            raw_output_path=raw_output_path
        )

    except (FileNotFoundError, PermissionError) as exc:
        return _holehe_result(
            "missing_executable",
            error=str(exc)
        )

    except OSError as exc:
        return _holehe_result(
            "failed",
            error=str(exc)
        )

    stdout = result.stdout or ""
    stderr = result.stderr or ""

    if result.returncode != 0:
        raw_output_path = save_email_tool_debug_output(
            "Holehe",
            email,
            stdout,
            stderr
        )

        error_detail = stderr.strip() or stdout.strip()
        error = f"Holehe exited with code {result.returncode}"
        if error_detail:
            error += f": {error_detail[-300:]}"

        return _holehe_result(
            "failed",
            error=error,
            return_code=result.returncode,
            raw_output_path=raw_output_path
        )

    if not stdout.strip():
        raw_output_path = save_email_tool_debug_output(
            "Holehe",
            email,
            stdout,
            stderr
        )

        return _holehe_result(
            "parser_failure",
            error="Holehe completed without parseable stdout",
            return_code=result.returncode,
            raw_output_path=raw_output_path
        )

    findings, diagnostics = parse_holehe_output(stdout, email)

    has_incomplete_checks = (
        diagnostics["rate_limited_checks"] > 0
        or diagnostics["error_checks"] > 0
    )

    if findings:
        status = "partial" if has_incomplete_checks else "success"

    elif diagnostics["completed"] and not has_incomplete_checks:
        status = "no_results"

    elif diagnostics["completed"]:
        # No positives were found, but some services could not be checked.
        status = "partial"

    else:
        raw_output_path = save_email_tool_debug_output(
            "Holehe",
            email,
            stdout,
            stderr
        )

        return _holehe_result(
            "parser_failure",
            error="Holehe output did not contain a completion marker",
            return_code=result.returncode,
            diagnostics=diagnostics,
            raw_output_path=raw_output_path
        )

    return _holehe_result(
        status,
        findings=findings,
        return_code=result.returncode,
        diagnostics=diagnostics
    )
