import subprocess
import re
import os

from username_validation import url_references_username

BLACKBIRD_DIR = "/home/kali/blackbird"
BLACKBIRD_SCRIPT = os.path.join(BLACKBIRD_DIR, "blackbird.py")
BLACKBIRD_PYTHON = os.path.join(BLACKBIRD_DIR, "venv", "bin", "python")

ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
BLACKBIRD_RESULT = re.compile(r"\[([^\]]+)\]\s+(https?://\S+)")
NON_RESULT_LABELS = {
    "debug",
    "info",
    "warning",
    "error",
    "!",
    "+",
    "-",
    "x",
}


def parse_blackbird_output(output, username):
    """Parse target-specific Blackbird findings, excluding log messages."""

    accounts = []
    seen = set()

    for raw_line in output.splitlines():
        line = ANSI_ESCAPE.sub("", raw_line).strip()
        match = BLACKBIRD_RESULT.search(line)

        if not match:
            continue

        website = match.group(1).strip()
        url = match.group(2).rstrip(".,;)")

        if website.casefold() in NON_RESULT_LABELS:
            continue

        if not url_references_username(url, username):
            continue

        key = url.casefold().rstrip("/")
        if key in seen:
            continue

        seen.add(key)
        accounts.append({
            "website": website,
            "url": url,
            "tool": "Blackbird",
            "username": username,
        })

    return accounts


def run_blackbird(username):

    if not os.path.exists(BLACKBIRD_DIR):
        raise FileNotFoundError(
            f"Blackbird directory not found: {BLACKBIRD_DIR}"
        )

    if not os.path.exists(BLACKBIRD_SCRIPT):
        raise FileNotFoundError(
            f"Blackbird script not found: {BLACKBIRD_SCRIPT}"
        )

    if not os.path.exists(BLACKBIRD_PYTHON):
        raise FileNotFoundError(
            f"Blackbird Python not found: {BLACKBIRD_PYTHON}"
        )

    try:

        result = subprocess.run(
            [
                BLACKBIRD_PYTHON,
                BLACKBIRD_SCRIPT,
                "--username",
                username,
                "--no-update",
            ],
            cwd=BLACKBIRD_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=180
        )

        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()[-300:]
            raise RuntimeError(
                f"Blackbird exited with code {result.returncode}: {detail}"
            )

        if not (result.stdout or "").strip():
            raise RuntimeError("Blackbird completed without output")

        return parse_blackbird_output(result.stdout or "", username)

    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Blackbird timed out after 180 seconds") from exc

    except OSError as exc:
        raise RuntimeError(f"Blackbird could not start: {exc}") from exc
