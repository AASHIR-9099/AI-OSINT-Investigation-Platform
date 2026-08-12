def merge_results(
    sherlock,
    blackbird,
    maigret,
    whatsmyname,
    gitfive_accounts,
):
    """
    Merge results from all OSINT tools, remove duplicates,
    and preserve which tools detected each account.
    """

    all_accounts = []

    # Collect all tool outputs
    for tool_results in [
        sherlock,
        blackbird,
        maigret,
        whatsmyname,
        gitfive_accounts,
    ]:

        if isinstance(tool_results, list):
            all_accounts.extend(tool_results)

    merged = {}

    for account in all_accounts:

        if not isinstance(account, dict):
            continue

        website = (
            account.get("website")
            or account.get("site")
            or ""
        ).strip()

        url = account.get("url", "").strip()

        tool = account.get("tool", "").strip()
        username = account.get("username")

        if not website or not url:
            continue

        # Normalize URL
        key = url.lower().rstrip("/")

        if key not in merged:

            merged[key] = {
                "website": website,
                "url": url,
                "username": username,

                # Keep every tool that detected it
                "tools": set(),

                # Verification fields
                "confidence": 0,
                "status": "Unknown",
                "reasons": []
            }

        if tool:
            merged[key]["tools"].add(tool)

        if not merged[key].get("username") and username:
            merged[key]["username"] = username

        # Preserve optional evidence that can improve confidence explanations.
        # Missing values never create points, and later tools only fill fields
        # that were not already supplied by an earlier source.
        for metadata_key in (
            "display_name",
            "full_name",
            "name",
            "profile_picture",
            "profile_picture_url",
            "avatar",
            "avatar_url",
            "bio",
            "biography",
            "description",
            "followers",
            "follower_count",
            "followers_count",
            "verified",
            "is_verified",
            "verified_status",
            "details",
            "metadata",
        ):
            metadata_value = account.get(metadata_key)
            if (
                metadata_value not in (None, "", [], {})
                and merged[key].get(metadata_key) in (None, "", [], {})
            ):
                merged[key][metadata_key] = metadata_value

    cleaned = []

    for account in merged.values():

        account["tools"] = sorted(list(account["tools"]))

        cleaned.append(account)

    cleaned.sort(
        key=lambda x: x["website"].lower()
    )

    return cleaned