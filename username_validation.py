"""Small validation helpers shared by username-tool adapters."""

import re
from urllib.parse import unquote, urlparse


def is_http_url(url):
    """Return True only for absolute HTTP(S) URLs with a hostname."""

    if not isinstance(url, str) or not url.strip():
        return False

    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return False

    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.hostname)


def url_references_username(url, username):
    """Check that a candidate profile URL actually references the target."""

    if not is_http_url(url) or not isinstance(username, str):
        return False

    normalized_username = unquote(username).strip().lstrip("@").casefold()
    if not normalized_username:
        return False

    parsed = urlparse(url.strip())
    resource = unquote(
        f"{parsed.path}?{parsed.query}#{parsed.fragment}"
    ).casefold()

    username_pattern = re.compile(
        rf"(?<![a-z0-9_.-]){re.escape(normalized_username)}"
        rf"(?![a-z0-9_.-])"
    )

    if username_pattern.search(resource):
        return True

    hostname_labels = (parsed.hostname or "").casefold().split(".")
    return bool(hostname_labels) and hostname_labels[0] == normalized_username
