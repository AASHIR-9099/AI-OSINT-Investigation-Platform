import json
import os
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from username_validation import url_references_username


WMN_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "data",
    "wmn-data.json"
)

# Only search popular/important websites
IMPORTANT_SITES = {
    "GitHub",
    "GitLab",
    "Instagram",
    "Facebook",
    "X",
    "Threads",
    "Snapchat",
    "Pinterest",
    "Reddit",
    "LinkedIn",
    "TikTok",
    "Steam",
    "TryHackMe",
    "Hacker News",
    "StackOverflow",
    "PyPI",
    "CodeChef",
    "Replit",
    "Medium",
    "Kaggle",
    "Duolingo",
    "Discord",
    "Telegram",
    "Keybase",
    "Mastodon API",
    "Bluesky Domain as User",
    "Hashnode",
    "WordPress.org (Profiles)",
    "Codecademy",
    "GitHub Pages"
}



def check_roblox(username):
    try:
        response = requests.post(
            "https://users.roblox.com/v1/usernames/users",
            json={
                "usernames": [username],
                "excludeBannedUsers": False
            },
            headers={
                "User-Agent": "Mozilla/5.0",
                "Content-Type": "application/json",
            },
            timeout=5,
        )

        if response.status_code != 200:
            return None

        data = response.json().get("data", [])

        if not data:
            return None

        user = data[0]

        if user.get("name", "").lower() != username.lower():
            return None

        return {
            "website": "Roblox",
            "url": f"https://www.roblox.com/users/{user['id']}/profile",
            "tool": "WhatsMyName",
            "username": username,
        }

    except (requests.RequestException, ValueError, KeyError, TypeError):
        return None

def check_site(site, username):
    try:
        url = site["uri_check"].replace("{account}", username)

        headers = {
            "User-Agent": "Mozilla/5.0",
            **site.get("headers", {}),
        }

        if site.get("post_body"):
            body = site["post_body"].replace("{account}", username)
            response = requests.post(
                url,
                data=body,
                timeout=5,
                allow_redirects=False,
                headers=headers,
            )
        else:
            response = requests.get(
                url,
                timeout=5,
                allow_redirects=False,
                headers=headers,
            )

        response_text = response.text or ""
        expected_code = site.get("e_code")
        expected_string = site.get("e_string")
        missing_string = site.get("m_string")

        # WhatsMyName provides platform-specific positive and negative
        # signatures.  A generic HTTP 200/redirect is not account evidence.
        if expected_code is not None and response.status_code != expected_code:
            return None

        if missing_string and missing_string in response_text:
            return None

        if not expected_string or expected_string not in response_text:
            return None

        profile_url = (
            site.get("uri_pretty")
            or site["uri_check"]
        ).replace("{account}", username)

        if not url_references_username(profile_url, username):
            return None

        return {
            "website": site["name"],
            "url": profile_url,
            "tool": "WhatsMyName",
            "username": username,
        }

    except (KeyError, TypeError, requests.RequestException):
        pass

    return None


def run_whatsmyname(username):

    if not os.path.exists(WMN_FILE):
        raise FileNotFoundError(f"WhatsMyName data file not found: {WMN_FILE}")

    with open(WMN_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Keep only important websites
    sites = [
        site for site in data["sites"]
        if site.get("name") in IMPORTANT_SITES
    ]

    results = []

    roblox_result = check_roblox(username)
    if roblox_result:
        results.append(roblox_result)

    with ThreadPoolExecutor(max_workers=20) as executor:

        futures = [
            executor.submit(check_site, site, username)
            for site in sites
        ]

        for future in as_completed(futures):
            result = future.result()

            if result:
                results.append(result)

    return results
