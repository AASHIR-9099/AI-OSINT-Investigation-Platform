from urllib.parse import unquote, urlparse

import requests


def verify_github(account):
    """Verify a GitHub candidate through GitHub's user API."""

    account["verification"] = "Needs Review"
    account["verification_reason"] = []

    try:
        parsed = urlparse(account.get("url", ""))
        username = unquote(parsed.path).strip("/").split("/", 1)[0]
    except (ValueError, IndexError):
        username = ""

    expected_username = account.get("username") or username

    if not username or username.casefold() != str(expected_username).casefold():
        account["verification_reason"].append(
            "GitHub profile URL does not match the requested username."
        )
        return account

    try:
        response = requests.get(
            f"https://api.github.com/users/{username}",
            timeout=10,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "AI-OSINT-System",
            },
        )
    except requests.RequestException as exc:
        account["verification"] = "Error"
        account["verification_reason"].append(str(exc))
        return account

    if response.status_code == 404:
        account["verification"] = "False Positive"
        account["verification_reason"].append("GitHub API returned HTTP 404.")
        return account

    if response.status_code != 200:
        account["verification_reason"].append(
            f"GitHub API returned HTTP {response.status_code}."
        )
        return account

    try:
        data = response.json()
    except ValueError:
        account["verification_reason"].append(
            "GitHub API returned invalid JSON."
        )
        return account

    login = data.get("login") if isinstance(data, dict) else None
    github_id = data.get("id") if isinstance(data, dict) else None

    if not login or login.casefold() != username.casefold() or github_id is None:
        account["verification_reason"].append(
            "GitHub API response did not match the requested username."
        )
        return account

    account["verification"] = "Verified"
    account["verification_reason"].append(
        "GitHub API confirmed the exact username and account ID."
    )
    verification_evidence = {
        "source": "GitHub API",
        "login": login,
        "id": github_id,
    }

    optional_metadata = {
        "display_name": data.get("name"),
        "avatar_url": data.get("avatar_url"),
        "bio": data.get("bio"),
        "followers": data.get("followers"),
    }
    verification_evidence.update({
        key: value
        for key, value in optional_metadata.items()
        if value not in (None, "", [], {})
    })

    account["verification_evidence"] = verification_evidence
    return account