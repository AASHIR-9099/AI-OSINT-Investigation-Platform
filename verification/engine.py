from urllib.parse import urlparse

from verification.generic import verify_generic
from verification.github import verify_github


def verify_account(account):
    """
    Verify a single account.
    """

    website = account.get("website", "").casefold()

    try:
        hostname = (urlparse(account.get("url", "")).hostname or "").casefold()
    except ValueError:
        hostname = ""

    if website == "github" or hostname in {"github.com", "www.github.com"}:
        return verify_github(account)

    return verify_generic(account)


def verify_accounts(accounts):
    """
    Verify all accounts.
    """

    verified_accounts = []

    for account in accounts:
        verified_accounts.append(
            verify_account(account)
        )

    return verified_accounts
