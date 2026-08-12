import subprocess
import os
import re

from username_validation import url_references_username


GITFIVE_PYTHON = "/home/kali/GitFive/venv/bin/python"
GITFIVE_MAIN = "/home/kali/GitFive/main.py"

ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def parse_gitfive_output(output, target):
    """Require exact GitFive identity evidence for the requested username."""

    clean_output = ANSI_ESCAPE.sub("", output or "")
    normalized_target = target.strip().lstrip("@").casefold()

    github_url = None
    for url in re.findall(r"https?://github\.com/[^\s\])}>,]+", clean_output):
        url = url.rstrip(".,;)")
        if url_references_username(url, normalized_target):
            github_url = f"https://github.com/{target.strip().lstrip('@')}"
            break

    parsed_username = None
    parsed_id = None

    for line in clean_output.splitlines():
        username_match = re.match(r"^\s*Username\s*:\s*([^\s]+)\s*$", line)
        id_match = re.match(r"^\s*ID\s*:\s*(\d+)\s*$", line)

        if username_match:
            parsed_username = username_match.group(1).strip().lstrip("@")
        if id_match:
            parsed_id = id_match.group(1)

    exact_identity = (
        parsed_username is not None
        and parsed_username.casefold() == normalized_target
        and parsed_id is not None
    )

    if github_url or exact_identity:
        return {
            "website": "GitHub",
            "url": github_url or f"https://github.com/{parsed_username}",
            "tool": "GitFive",
            "username": parsed_username or target.strip().lstrip("@"),
            "github_id": parsed_id,
        }

    return None


def run_gitfive(target):

    print("\n[+] Searching GitHub intelligence with GitFive...\n")

    try:

        # Check GitFive Python
        if not os.path.exists(GITFIVE_PYTHON):

            return {
                "tool": "GitFive",
                "username": target,
                "github_found": False,
                "accounts": [],
                "output": "",
                "success": False,
                "error": f"GitFive Python not found: {GITFIVE_PYTHON}"
            }


        # Check GitFive main.py
        if not os.path.exists(GITFIVE_MAIN):

            return {
                "tool": "GitFive",
                "username": target,
                "github_found": False,
                "accounts": [],
                "output": "",
                "success": False,
                "error": f"GitFive main.py not found: {GITFIVE_MAIN}"
            }



        # Decide GitFive search mode
        if "@" in target:

            command = [
                GITFIVE_PYTHON,
                GITFIVE_MAIN,
                "email",
                target
            ]

        else:

            command = [
                GITFIVE_PYTHON,
                GITFIVE_MAIN,
                "user",
                target
            ]



        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180
        )

        output = (
            (result.stdout or "")
            +
            "\n"
            +
            (result.stderr or "")
        )

        # GitFive returns exit code 1 when the username does not exist.
        # That is a valid search result, not a tool failure.

        not_found = (
            result.returncode == 1
            and f'User "{target}" not found' in output
        )

        account = None
        if result.returncode == 0 and "@" not in target:
            account = parse_gitfive_output(result.stdout or "", target)

        github_found = account is not None
        accounts = [account] if account else []

        execution_success = (
            result.returncode == 0
            or not_found
        )

        return {

            "tool": "GitFive",

            "username": target,

            "github_found": github_found,

            "accounts": accounts,

            "output": output,

            "success": execution_success,

            "return_code": result.returncode

        }


    except subprocess.TimeoutExpired:


        return {

            "tool": "GitFive",

            "username": target,

            "github_found": False,

            "accounts": [],

            "output": "",

            "success": False,

            "error": "GitFive timeout"

        }



    except Exception as e:


        return {

            "tool": "GitFive",

            "username": target,

            "github_found": False,

            "accounts": [],

            "output": "",

            "success": False,

            "error": str(e)

        }
