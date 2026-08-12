import re
import shutil
import subprocess

from username_validation import url_references_username


ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
SHERLOCK_RESULT = re.compile(
    r"^\[\+\]\s*([^:]+):\s*(https?://\S+)\s*$",
    re.IGNORECASE
)


def parse_sherlock_output(output, username):
    """Parse only target-specific Sherlock claimed-profile lines."""

    accounts = []
    seen = set()

    for raw_line in output.splitlines():
        line = ANSI_ESCAPE.sub("", raw_line).strip()
        match = SHERLOCK_RESULT.match(line)

        if not match:
            continue

        website = match.group(1).strip()
        url = match.group(2).rstrip(".,;)")

        if not url_references_username(url, username):
            continue

        key = url.casefold().rstrip("/")
        if key in seen:
            continue

        seen.add(key)
        accounts.append({
            "website": website,
            "url": url,
            "tool": "Sherlock",
            "username": username,
        })

    return accounts


def run_sherlock(username, timeout=180):

    executable = shutil.which("sherlock")
    if not executable:
        raise FileNotFoundError("Sherlock executable was not found")

    try:
        result = subprocess.run(
            [
                executable,
                username,
                "--print-found",
                "--no-color",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )

    except subprocess.TimeoutExpired as exc:
        raise TimeoutError(
            f"Sherlock timed out after {timeout} seconds"
        ) from exc

    except OSError as exc:
        raise RuntimeError(
            f"Sherlock could not start: {exc}"
        ) from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()[-300:]
        raise RuntimeError(
            f"Sherlock exited with code {result.returncode}: {detail}"
        )

    if not (result.stdout or "").strip():
        raise RuntimeError("Sherlock completed without output")

    accounts = parse_sherlock_output(result.stdout or "", username)

    print(f"[DEBUG] Sherlock returned {len(accounts)} accounts")

    return accounts