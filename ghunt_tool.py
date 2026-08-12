import subprocess
import os

from email_debug import save_email_tool_debug_output
from ghunt_parser import parse_ghunt_output


GHUNT_EXECUTABLE = os.path.expanduser(
    "~/GHunt/venv/bin/ghunt"
)


def _ghunt_result(
    status,
    *,
    data=None,
    error=None,
    return_code=None,
    raw_output_path=None
):
    """Return a predictable email-tool result without changing API output."""

    return {
        "tool": "GHunt",
        "status": status,
        "data": data or {},
        "error": error,
        "return_code": return_code,
        "raw_output_path": raw_output_path,
    }


def _is_explicit_not_found(output):
    """Recognize only clear whole-message GHunt negative statements."""

    normalized_lines = [
        line.strip().lower()
        for line in output.splitlines()
        if line.strip()
    ]

    phrases = (
        "no google account found",
        "google account not found",
        "could not find google account",
        "couldn't find google account",
        "unable to find google account",
    )

    return any(
        any(phrase in line for phrase in phrases)
        for line in normalized_lines
    )


def _parse_account_evidence(output, requested_email):
    """Return verified core GHunt evidence or a conservative parse error."""

    try:
        data = parse_ghunt_output(output)

    except Exception as exc:
        return {}, f"GHunt output parser failed: {exc}"

    parsed_email = data.get("email")
    parsed_target_matches = (
        isinstance(parsed_email, str)
        and parsed_email.casefold() == requested_email.casefold()
    )

    if not data.get("gaia_id") or not parsed_target_matches:
        return {}, "GHunt output did not contain a matching email and Gaia ID"

    data["account_found"] = True
    return data, None


def ghunt_email(email, timeout=180):

    if not os.path.isfile(GHUNT_EXECUTABLE):
        return _ghunt_result(
            "missing_executable",
            error=f"GHunt executable not found: {GHUNT_EXECUTABLE}"
        )

    try:

        process = subprocess.run(
            [
                GHUNT_EXECUTABLE,
                "email",
                email
            ],
            capture_output=True,
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
            "GHunt",
            email,
            stdout,
            stderr
        )

        return _ghunt_result(
            "timeout",
            error=f"GHunt timed out after {timeout} seconds",
            raw_output_path=raw_output_path
        )

    except (FileNotFoundError, PermissionError) as exc:
        return _ghunt_result(
            "missing_executable",
            error=str(exc)
        )

    except OSError as exc:
        return _ghunt_result(
            "failed",
            error=str(exc)
        )

    stdout = process.stdout or ""
    stderr = process.stderr or ""

    if process.returncode != 0:
        raw_output_path = save_email_tool_debug_output(
            "GHunt",
            email,
            stdout,
            stderr
        )

        error_detail = stderr.strip() or stdout.strip()
        error = f"GHunt exited with code {process.returncode}"
        if error_detail:
            error += f": {error_detail[-300:]}"

        # GHunt may resolve the account and fail later in optional enrichment
        # stages. Preserve matching email/Gaia evidence, but clearly mark the
        # execution partial rather than successful.
        data, _parse_error = _parse_account_evidence(stdout, email)

        if data:
            data["status"] = "partial"
            return _ghunt_result(
                "partial",
                data=data,
                error=error,
                return_code=process.returncode,
                raw_output_path=raw_output_path
            )

        return _ghunt_result(
            "failed",
            error=error,
            return_code=process.returncode,
            raw_output_path=raw_output_path
        )

    if not stdout.strip():
        raw_output_path = save_email_tool_debug_output(
            "GHunt",
            email,
            stdout,
            stderr
        )

        return _ghunt_result(
            "parser_failure",
            error="GHunt completed without parseable stdout",
            return_code=process.returncode,
            raw_output_path=raw_output_path
        )

    if _is_explicit_not_found(stdout):
        return _ghunt_result(
            "no_results",
            return_code=process.returncode
        )

    # A matching email and Gaia ID are stable evidence that GHunt actually
    # resolved the requested Google account.  The input email alone is not
    # evidence and is never injected into parsed output.
    data, parse_error = _parse_account_evidence(stdout, email)

    if parse_error:
        raw_output_path = save_email_tool_debug_output(
            "GHunt",
            email,
            stdout,
            stderr
        )

        return _ghunt_result(
            "parser_failure",
            error=parse_error,
            return_code=process.returncode,
            raw_output_path=raw_output_path
        )

    data["status"] = "completed"

    return _ghunt_result(
        "success",
        data=data,
        return_code=process.returncode
    )
