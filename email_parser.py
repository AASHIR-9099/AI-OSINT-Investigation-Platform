def merge_email_results(
    ghunt=None,
    holehe=None
):
    """
    Merge email intelligence into a unified account list.
    """

    accounts = []

    # -----------------------------
    # Holehe
    # -----------------------------

    if isinstance(holehe, list):

        for item in holehe:

            if isinstance(item, dict):

                platform = (
                    item.get("website")
                    or item.get("platform")
                )

                if not platform:
                    continue

                accounts.append({

                    "platform": platform,

                    "email": item.get(
                        "email"
                    ),

                    "url": item.get(
                        "url",
                        ""
                    ),

                    "source": item.get("source") or "Holehe"
                })

    # -----------------------------
    # GHunt
    # -----------------------------

    # Only a resolved Gaia ID is strong enough to create a Google finding.
    # A truthy failure/status dictionary or the input email by itself must not
    # be interpreted as evidence that a Google account exists.
    ghunt_account_found = (
        isinstance(ghunt, dict)
        and ghunt.get("account_found") is True
        and bool(ghunt.get("gaia_id"))
    )

    if ghunt_account_found:

        accounts.append({

            "platform": "Google",

            "email": ghunt.get("email"),

            "url": "",

            "source": "GHunt",

            "details": ghunt

        })

    # -----------------------------
    # Remove duplicates
    # -----------------------------

    unique = {}

    for account in accounts:

        key = (

            account.get(
                "platform",
                ""
            ).lower(),

            account.get(
                "url",
                ""
            ).lower()

        )

        if key not in unique:

            unique[key] = account

    return list(unique.values())
