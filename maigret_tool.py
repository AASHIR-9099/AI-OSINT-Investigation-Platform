import os
import re
import subprocess

from username_validation import url_references_username


# Use the exact Maigret environment that was confirmed to work manually.
MAIGRET_PYTHON = "/home/kali/maigret/venv/bin/python"

ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

MAIGRET_RESULT = re.compile(
    r"^[+]\s*([^:]+):\s*(https?://\S+)\s*$",
    re.IGNORECASE
)


def parse_maigret_output(output, username):
    """Parse only target-specific Maigret claimed-profile lines."""

    accounts = []
    seen = set()

    for raw_line in output.splitlines():
        line = ANSI_ESCAPE.sub("", raw_line).strip()
        match = MAIGRET_RESULT.match(line)

        if not match:
            continue

        website = match.group(1).strip()
        url = match.group(2).rstrip(".,;)")

        # Keep only URLs that actually reference the requested username.
        if not url_references_username(url, username):
            continue

        key = url.casefold().rstrip("/")

        if key in seen:
            continue

        seen.add(key)

        accounts.append({
            "website": website,
            "url": url,
            "tool": "Maigret",
            "username": username,
        })

    return accounts


def run_maigret(username):
    """
    Run Maigret using the dedicated Python virtual environment.

    Maigret can encounter individual site/DNS/bot-protection errors
    while still completing successfully, so only a non-zero process
    return code or a timeout is treated as an execution failure.
    """

    if not os.path.isfile(MAIGRET_PYTHON):
        raise FileNotFoundError(
            f"Maigret Python interpreter not found: {MAIGRET_PYTHON}"
        )

    try:
        result = subprocess.run(
            [
                MAIGRET_PYTHON,
                "-m",
                "maigret",
                username,
                "--no-progressbar",
                "--no-color",
                "--dns-resolver",
                "threaded",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180,
        )

        # A non-zero return code means Maigret itself failed to execute
        # successfully. Site-level DNS/bot-protection warnings are not
        # treated as fatal if Maigret exits successfully.
        if result.returncode != 0:
            detail = (
                result.stderr
                or result.stdout
                or ""
            ).strip()[-500:]

            raise RuntimeError(
                f"Maigret exited with code {result.returncode}: {detail}"
            )

        # Maigret completed successfully but produced no stdout.
        if not (result.stdout or "").strip():
            raise RuntimeError(
                "Maigret completed without output"
            )

        return parse_maigret_output(
            result.stdout or "",
            username
        )

    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            "Maigret timed out after 180 seconds"
        ) from exc

    except OSError as exc:
        raise RuntimeError(
            f"Maigret could not start: {exc}"
        ) from exc