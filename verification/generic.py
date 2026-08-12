import html
import re

import requests

from username_validation import url_references_username

TITLE_NOT_FOUND_PHRASES = [
    "not found",
    "page not found",
    "user not found",
    "profile not found",
]

BODY_NOT_FOUND_PHRASES = [
    "user not found",
    "profile not found",
    "this account doesn't exist",
    "this account does not exist",
    "this user doesn't exist",
    "this user does not exist",
]


def _page_title(response_text):
    match = re.search(
        r"<title[^>]*>(.*?)</title>",
        response_text,
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return ""

    title = re.sub(r"\s+", " ", match.group(1))
    return html.unescape(title).strip().casefold()


def verify_generic(account):
    """
    Generic verification for any website.
    """

    url = account.get("url", "")
    username = account.get("username")

    if not username:
        username = url.rstrip("/").split("/")[-1].replace("@", "")

    account["verification"] = "Unknown"
    account["verification_reason"] = []

    try:
        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": (
                    "Mozilla/5.0"
                )
            },
            allow_redirects=True
        )

    except Exception as e:

        account["verification"] = "Error"
        account["verification_reason"].append(str(e))
        return account

    # HTTP status
    if response.status_code == 404:
        account["verification"] = "False Positive"
        account["verification_reason"].append("HTTP 404")
        return account

    if response.status_code != 200:
        account["verification"] = "Needs Review"
        account["verification_reason"].append(
            f"HTTP {response.status_code}"
        )
        return account

    final_url = getattr(response, "url", None)
    if final_url and not url_references_username(final_url, username):
        account["verification"] = "False Positive"
        account["verification_reason"].append(
            "Profile request redirected to a non-target URL."
        )
        return account

    html = response.text.lower()

    title = _page_title(response.text)

    for phrase in TITLE_NOT_FOUND_PHRASES:
        if phrase in title:
            account["verification"] = "False Positive"
            account["verification_reason"].append(
                f"Page title indicates absence: {phrase}"
            )
            return account

    for phrase in BODY_NOT_FOUND_PHRASES:
        if phrase in html:
            account["verification"] = "False Positive"
            account["verification_reason"].append(
                f"Page content indicates absence: {phrase}"
            )
            return account

    if "account suspended" in html:
        account["verification"] = "Needs Review"
        account["verification_reason"].append(
            "The platform reports a suspended account."
        )
        return account

    # Generic page content can echo the requested URL or username.  It is
    # supporting evidence, but not platform-specific proof of account control.
    if username.lower() in html:
        account["verification"] = "Needs Review"
        account["verification_reason"].append(
            "Username appears in page content; platform verification required."
        )
    else:
        account["verification"] = "Needs Review"
        account["verification_reason"].append(
            "Username not found in page."
        )

    return account
