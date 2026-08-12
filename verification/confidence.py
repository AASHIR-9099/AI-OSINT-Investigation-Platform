"""Deterministic confidence scoring for username and email investigations.

Confidence means:
    How confident are we that the collected intelligence belongs to the target?

It does not measure threat, exposure, or the raw number of findings.
Username and email investigations use separate scoring models.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Shared configuration
# ---------------------------------------------------------------------------

HIGH_VALUE_SITES = {
    "github",
    "gitlab",
    "linkedin",
    "reddit",
    "instagram",
    "x",
    "twitter",
    "tiktok",
    "youtube",
    "facebook",
}

_PLATFORM_ALIASES = {
    "github": "github",
    "github.com": "github",
    "gitlab": "gitlab",
    "gitlab.com": "gitlab",
    "linkedin": "linkedin",
    "linkedin.com": "linkedin",
    "reddit": "reddit",
    "reddit.com": "reddit",
    "instagram": "instagram",
    "instagram.com": "instagram",
    "x": "x",
    "x.com": "x",
    "twitter": "twitter",
    "twitter.com": "twitter",
    "tiktok": "tiktok",
    "tiktok.com": "tiktok",
    "youtube": "youtube",
    "youtube.com": "youtube",
    "youtu.be": "youtube",
    "facebook": "facebook",
    "facebook.com": "facebook",
}

_TOOL_DISPLAY_NAMES = {
    "sherlock": "Sherlock",
    "maigret": "Maigret",
    "blackbird": "Blackbird",
    "whatsmyname": "WhatsMyName",
    "whats my name": "WhatsMyName",
    "gitfive": "GitFive",
    "social analyzer": "Social Analyzer",
    "social_analyzer": "Social Analyzer",
    "ghunt": "GHunt",
    "holehe": "Holehe",
    "hibp": "HIBP",
}


# ---------------------------------------------------------------------------
# Username scoring configuration
# ---------------------------------------------------------------------------

# Cross-tool agreement remains the strongest repeatable signal.
USERNAME_AGREEMENT_POINTS = {
    0: 0,
    1: 10,
    2: 28,
    3: 44,
    4: 56,
}
USERNAME_FIVE_PLUS_POINTS = 64

PLATFORM_API_VERIFICATION_BONUS = 34
DIRECT_PAGE_EVIDENCE_BONUS = 28
VERIFICATION_ERROR_PENALTY = 8
HIGH_VALUE_PLATFORM_BONUS = 8
MAX_METADATA_BONUS = 8

# Only the five strongest merged accounts affect the weighted account score.
TOP_ACCOUNT_WEIGHTS = (0.42, 0.24, 0.15, 0.11, 0.08)

VERIFIED_ACCOUNT_BONUS = {0: 0, 1: 0, 2: 8, 3: 13, 4: 17}
VERIFIED_FIVE_PLUS_BONUS = 20

CORROBORATED_ACCOUNT_BONUS = {0: 0, 1: 4, 2: 7, 3: 10}
CORROBORATED_FOUR_PLUS_BONUS = 12

HIGH_VALUE_BREADTH_BONUS = {0: 0, 1: 0, 2: 5, 3: 8, 4: 11}
HIGH_VALUE_FIVE_PLUS_BONUS = 13


# ---------------------------------------------------------------------------
# Email scoring configuration
# ---------------------------------------------------------------------------

GHUNT_BASE_POINTS = 44
GHUNT_METADATA_BONUS_CAP = 16
HIBP_POSITIVE_POINTS = 10
EMAIL_AGREEMENT_BONUS = {0: 0, 1: 0, 2: 14, 3: 20}


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _clamp(value, minimum=0, maximum=100):
    return max(minimum, min(maximum, value))


def _confidence_level(score):
    """Map a numeric score to the five user-facing confidence levels."""

    if score < 20:
        return "Very Low"
    if score < 35:
        return "Low"
    if score < 60:
        return "Moderate"
    if score < 80:
        return "High"
    return "Very High"


def _join_names(values):
    items = [str(value) for value in values if str(value).strip()]
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f", and {items[-1]}"


def _as_items(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def _normalise_tool_name(value):
    text = str(value or "").strip()
    if not text:
        return ""
    key = re.sub(r"\s+", " ", text.casefold().replace("-", " ")).strip()
    return _TOOL_DISPLAY_NAMES.get(key, text)


def _unique_tools(account):
    candidates = []
    for key in ("tools", "sources", "source", "tool"):
        candidates.extend(_as_items(account.get(key)))

    unique = {}
    for candidate in candidates:
        name = _normalise_tool_name(candidate)
        if name:
            unique[name.casefold()] = name
    return sorted(unique.values(), key=str.casefold)


def _platform_key(account):
    raw_platform = str(
        account.get("website")
        or account.get("platform")
        or account.get("site")
        or ""
    ).strip().casefold().removeprefix("www.")

    try:
        hostname = (
            urlparse(str(account.get("url") or "")).hostname or ""
        ).casefold().removeprefix("www.")
    except ValueError:
        hostname = ""

    for candidate in (raw_platform, hostname):
        if candidate in _PLATFORM_ALIASES:
            return _PLATFORM_ALIASES[candidate]
        first_label = candidate.split(".", 1)[0]
        if first_label in _PLATFORM_ALIASES:
            return _PLATFORM_ALIASES[first_label]

    return raw_platform or hostname or "unknown"


def _platform_label(account):
    value = (
        account.get("website")
        or account.get("platform")
        or account.get("site")
        or _platform_key(account)
        or "Unknown Platform"
    )
    return str(value).strip() or "Unknown Platform"


def _nested_containers(account):
    containers = [account]
    for key in ("details", "metadata", "profile", "verification_evidence"):
        nested = account.get(key)
        if isinstance(nested, dict):
            containers.append(nested)
    return containers


def _reason_texts(account):
    values = []
    values.extend(_as_items(account.get("verification_reason")))
    values.extend(_as_items(account.get("verification_reasons")))

    evidence = account.get("verification_evidence")
    if isinstance(evidence, dict):
        values.extend(_as_items(evidence.get("reason")))
        values.extend(_as_items(evidence.get("reasons")))

    return [str(value).strip() for value in values if str(value).strip()]


def _truthy_flag(account, keys):
    for container in _nested_containers(account):
        for key in keys:
            value = container.get(key)
            if value is True:
                return True
            if isinstance(value, str) and value.strip().casefold() in {
                "true",
                "yes",
                "matched",
                "verified",
                "found",
            }:
                return True
    return False


def _http_status(account):
    for container in _nested_containers(account):
        for key in (
            "http_status",
            "status_code",
            "response_status",
            "http_status_code",
        ):
            value = container.get(key)
            try:
                if value is not None:
                    return int(value)
            except (TypeError, ValueError):
                continue

    for reason in _reason_texts(account):
        match = re.search(r"\bHTTP\s+(\d{3})\b", reason, re.IGNORECASE)
        if match:
            return int(match.group(1))
    return None


def _verification_signals(account):
    verification = str(account.get("verification") or "Unknown").strip()
    verification_key = verification.casefold()
    reason_blob = " ".join(_reason_texts(account)).casefold()

    platform_api_verified = verification_key == "verified"

    username_on_page = _truthy_flag(
        account,
        (
            "username_found",
            "username_match",
            "page_username_match",
            "content_username_match",
            "exact_username_match",
        ),
    ) or any(
        phrase in reason_blob
        for phrase in (
            "username appears in page content",
            "username found in page",
            "username found on page",
            "exact username appears",
            "exact username found",
            "page content contains the username",
            "page contains the username",
        )
    )

    # The current generic verifier writes its username-content reason only
    # after HTTP 200, redirect, and not-found checks have passed.
    http_200 = (
        _http_status(account) == 200
        or username_on_page
        or platform_api_verified
    )

    direct_page_evidence = (
        username_on_page
        and http_200
        and verification_key not in {"false positive", "error"}
    )

    return {
        "verification": verification,
        "platform_api_verified": platform_api_verified,
        "direct_page_evidence": direct_page_evidence,
        "verification_error": verification_key == "error",
    }


def _metadata_flags(account):
    containers = _nested_containers(account)

    def first_present(keys, predicate=None):
        for container in containers:
            for key in keys:
                value = container.get(key)
                if value in (None, "", [], {}):
                    continue
                if predicate is None or predicate(value):
                    return True
        return False

    flags = []
    if first_present(("display_name", "full_name", "name")):
        flags.append(("display name", 2))
    if first_present(
        (
            "profile_picture",
            "profile_picture_url",
            "avatar",
            "avatar_url",
            "photo",
        ),
        lambda value: isinstance(value, str) and bool(value.strip()),
    ):
        flags.append(("profile picture", 2))
    if first_present(("bio", "biography", "description", "about")):
        flags.append(("bio", 2))
    if first_present(
        ("followers", "follower_count", "followers_count"),
        lambda value: isinstance(value, (int, float)) and value >= 0,
    ):
        flags.append(("followers", 1))
    if first_present(
        ("verified", "is_verified", "verified_status"),
        lambda value: value is True
        or str(value).strip().casefold() in {"true", "yes", "verified"},
    ):
        flags.append(("verified status", 2))
    return flags


def _agreement_points(tool_count):
    if tool_count >= 5:
        return USERNAME_FIVE_PLUS_POINTS
    return USERNAME_AGREEMENT_POINTS.get(max(tool_count, 0), 0)


def _tiered_bonus(count, table, maximum_bonus, maximum_from):
    if count >= maximum_from:
        return maximum_bonus
    return table.get(count, 0)


def _status_from_account_score(score, verification):
    if str(verification).casefold() == "false positive":
        return "Rejected"
    return f"{_confidence_level(score)} Confidence"


# ---------------------------------------------------------------------------
# Per-account username confidence
# ---------------------------------------------------------------------------


def _legacy_score_account(account):
    """Preserve the existing domain-path scoring behavior."""

    score = 0
    reasons = []
    tools = account.get("tools", [])
    website = str(account.get("website", "")).lower()
    tool_count = len(tools)

    if tool_count >= 4:
        score += 60
        reasons.append(f"Detected by {tool_count} OSINT tools.")
    elif tool_count == 3:
        score += 50
        reasons.append("Detected by 3 OSINT tools.")
    elif tool_count == 2:
        score += 35
        reasons.append("Detected by 2 OSINT tools.")
    elif tool_count == 1:
        score += 20
        reasons.append("Detected by a single OSINT tool.")

    if website in HIGH_VALUE_SITES:
        score += 20
        reasons.append("High-value platform.")

    score = min(score, 100)
    if score >= 70:
        status = "High Confidence"
    elif score >= 40:
        status = "Medium Confidence"
    else:
        status = "Low Confidence"

    account["confidence"] = score
    account["status"] = status
    account["reasons"] = reasons
    return account


def score_account(account):
    """Score one merged username account."""

    tools = _unique_tools(account)
    tool_count = len(tools)
    platform = _platform_key(account)
    platform_label = _platform_label(account)
    signals = _verification_signals(account)
    verification = signals["verification"]

    if verification.casefold() == "false positive":
        account["confidence"] = 0
        account["status"] = "Rejected"
        account["reasons"] = ["Platform verification rejected this candidate."]
        account["confidence_breakdown"] = {
            "tool_count": tool_count,
            "agreement_points": 0,
            "platform_api_verification_bonus": 0,
            "direct_page_evidence_bonus": 0,
            "verification_error_penalty": 0,
            "high_value_platform_bonus": 0,
            "metadata_bonus": 0,
            "direct_evidence": False,
        }
        return account

    agreement_points = _agreement_points(tool_count)
    api_bonus = (
        PLATFORM_API_VERIFICATION_BONUS
        if signals["platform_api_verified"]
        else 0
    )
    page_bonus = (
        DIRECT_PAGE_EVIDENCE_BONUS
        if signals["direct_page_evidence"]
        and not signals["platform_api_verified"]
        else 0
    )
    error_penalty = (
        -VERIFICATION_ERROR_PENALTY if signals["verification_error"] else 0
    )
    high_value_bonus = (
        HIGH_VALUE_PLATFORM_BONUS if platform in HIGH_VALUE_SITES else 0
    )

    metadata_flags = _metadata_flags(account)
    metadata_bonus = min(
        sum(points for _, points in metadata_flags),
        MAX_METADATA_BONUS,
    )

    score = round(
        _clamp(
            agreement_points
            + api_bonus
            + page_bonus
            + error_penalty
            + high_value_bonus
            + metadata_bonus
        )
    )

    reasons = []
    if tool_count:
        noun = "tool" if tool_count == 1 else "tools"
        verb = "reported by" if tool_count == 1 else "corroborated by"
        reasons.append(
            f"{platform_label} {verb} {tool_count} {noun}: "
            f"{_join_names(tools)}."
        )
    else:
        reasons.append("No named OSINT source was attached to this account.")

    if signals["platform_api_verified"]:
        if platform == "github":
            reasons.append(
                "GitHub API verified the exact username and account identity."
            )
        else:
            reasons.append(
                "A platform-specific verification check confirmed the account."
            )
    elif signals["direct_page_evidence"]:
        reasons.append(
            "The profile page passed availability checks and contained the exact username."
        )
    elif signals["verification_error"]:
        reasons.append("Platform verification failed, so the score was reduced.")
    else:
        reasons.append(
            "The account lacks direct page-content or platform-API verification."
        )

    if high_value_bonus:
        reasons.append(f"{platform_label} is a high-value identity platform.")
    if metadata_flags:
        reasons.append(
            "Profile metadata available: "
            + ", ".join(name for name, _ in metadata_flags)
            + "."
        )

    account["confidence"] = score
    account["status"] = _status_from_account_score(score, verification)
    account["reasons"] = reasons
    account["confidence_breakdown"] = {
        "tool_count": tool_count,
        "agreement_points": agreement_points,
        "platform_api_verification_bonus": api_bonus,
        "direct_page_evidence_bonus": page_bonus,
        "verification_error_penalty": error_penalty,
        "high_value_platform_bonus": high_value_bonus,
        "metadata_bonus": metadata_bonus,
        "direct_evidence": bool(
            signals["platform_api_verified"]
            or signals["direct_page_evidence"]
        ),
    }
    return account


def score_accounts(accounts, evidence_aware=True):
    """Score every merged account while retaining the existing list shape."""

    scorer = score_account if evidence_aware else _legacy_score_account
    return [scorer(account) for account in accounts if isinstance(account, dict)]


# ---------------------------------------------------------------------------
# Overall username confidence
# ---------------------------------------------------------------------------


def _weighted_top_account_score(accounts):
    ranked = sorted(
        accounts,
        key=lambda account: (
            -float(account.get("confidence", 0)),
            _platform_label(account).casefold(),
            str(account.get("url") or "").casefold(),
        ),
    )[: len(TOP_ACCOUNT_WEIGHTS)]

    if not ranked:
        return 0.0, []

    weights = TOP_ACCOUNT_WEIGHTS[: len(ranked)]
    weighted_score = sum(
        float(account.get("confidence", 0)) * weight
        for account, weight in zip(ranked, weights)
    ) / sum(weights)
    return weighted_score, ranked


def calculate_username_confidence(accounts, target_type="username"):
    """Calculate stable overall confidence for username evidence."""

    usable_accounts = [
        account
        for account in (accounts or [])
        if isinstance(account, dict)
        and str(account.get("verification") or "").casefold()
        != "false positive"
    ]

    for account in usable_accounts:
        breakdown = account.get("confidence_breakdown")
        current = (
            isinstance(breakdown, dict)
            and "direct_page_evidence_bonus" in breakdown
            and "platform_api_verification_bonus" in breakdown
        )
        if (
            target_type == "username" and not current
        ) or not isinstance(account.get("confidence"), (int, float)):
            score_account(account)

    if not usable_accounts:
        return {
            "score": 0,
            "level": _confidence_level(0),
            "reasons": ["No accepted account evidence was available for this target."],
            "breakdown": {
                "target_type": target_type,
                "weighted_account_score": 0,
                "top_accounts_used": 0,
                "directly_verified_accounts": 0,
                "verified_account_bonus": 0,
                "corroborated_accounts": 0,
                "corroborated_account_bonus": 0,
                "unique_tools": 0,
                "corroborating_tools": [],
                "high_value_platforms": [],
                "high_value_breadth_bonus": 0,
                "metadata_accounts": 0,
                "raw_score": 0,
                "applied_cap": 0,
            },
        }

    weighted_score, ranked_accounts = _weighted_top_account_score(usable_accounts)
    tool_sets = [_unique_tools(account) for account in usable_accounts]
    all_tools = sorted(
        {tool for tools in tool_sets for tool in tools},
        key=str.casefold,
    )
    signals = [_verification_signals(account) for account in usable_accounts]

    directly_verified = sum(
        signal["platform_api_verified"] or signal["direct_page_evidence"]
        for signal in signals
    )
    verified_bonus = _tiered_bonus(
        directly_verified,
        VERIFIED_ACCOUNT_BONUS,
        VERIFIED_FIVE_PLUS_BONUS,
        5,
    )

    corroborated_accounts = sum(len(tools) >= 2 for tools in tool_sets)
    corroborated_bonus = _tiered_bonus(
        corroborated_accounts,
        CORROBORATED_ACCOUNT_BONUS,
        CORROBORATED_FOUR_PLUS_BONUS,
        4,
    )

    corroborating_tools = sorted(
        {
            tool
            for tools in tool_sets
            if len(tools) >= 2
            for tool in tools
        },
        key=str.casefold,
    )

    high_value_platforms = sorted(
        {
            _platform_label(account)
            for account in usable_accounts
            if _platform_key(account) in HIGH_VALUE_SITES
        },
        key=str.casefold,
    )
    high_value_bonus = _tiered_bonus(
        len(high_value_platforms),
        HIGH_VALUE_BREADTH_BONUS,
        HIGH_VALUE_FIVE_PLUS_BONUS,
        5,
    )

    metadata_accounts = sum(
        bool(_metadata_flags(account)) for account in usable_accounts
    )

    raw_score = (
        weighted_score
        + verified_bonus
        + corroborated_bonus
        + high_value_bonus
    )

    max_tool_count = max((len(tools) for tools in tool_sets), default=0)
    applied_cap = 100
    if directly_verified == 0:
        if max_tool_count <= 1:
            applied_cap = 28
        elif max_tool_count == 2:
            applied_cap = 62
        elif max_tool_count == 3:
            applied_cap = 78
        else:
            applied_cap = 90

    score = round(_clamp(min(raw_score, applied_cap)))
    reasons = []

    most_corroborated = sorted(
        usable_accounts,
        key=lambda account: (
            -len(_unique_tools(account)),
            -float(account.get("confidence", 0)),
            _platform_label(account).casefold(),
        ),
    )

    for account in most_corroborated[:3]:
        tools = _unique_tools(account)
        if len(tools) >= 2:
            reasons.append(
                f"{_platform_label(account)} corroborated by {len(tools)} tools."
            )

    if corroborating_tools:
        reasons.append(
            "Independent tools agree on merged account evidence: "
            + _join_names(corroborating_tools)
            + "."
        )

    api_verified_platforms = sorted(
        {
            _platform_label(account)
            for account, signal in zip(usable_accounts, signals)
            if signal["platform_api_verified"]
        },
        key=str.casefold,
    )
    if api_verified_platforms:
        reasons.append(
            "Platform API verification confirmed: "
            + _join_names(api_verified_platforms)
            + "."
        )

    page_verified_platforms = sorted(
        {
            _platform_label(account)
            for account, signal in zip(usable_accounts, signals)
            if signal["direct_page_evidence"]
            and not signal["platform_api_verified"]
        },
        key=str.casefold,
    )
    if page_verified_platforms:
        reasons.append(
            "Exact usernames were confirmed in live profile pages: "
            + _join_names(page_verified_platforms)
            + "."
        )

    if directly_verified >= 2:
        reasons.append(
            f"Multiple legitimate profiles were directly verified "
            f"({directly_verified} accounts)."
        )

    if high_value_platforms:
        reasons.append(
            "High-value platforms detected: "
            + ", ".join(high_value_platforms)
            + "."
        )

    if metadata_accounts:
        noun = "account" if metadata_accounts == 1 else "accounts"
        reasons.append(
            f"Profile metadata was available on {metadata_accounts} {noun}."
        )

    if applied_cap < 100 and raw_score > applied_cap:
        reasons.append(
            "The score was capped because direct page-content or platform-API "
            "verification was unavailable."
        )

    if not reasons:
        strongest = most_corroborated[0]
        strongest_tools = _unique_tools(strongest)
        if strongest_tools:
            reasons.append(
                f"{_platform_label(strongest)} was reported by "
                f"{_join_names(strongest_tools)}, but direct verification was limited."
            )
        else:
            reasons.append("Accepted evidence was limited and lacked corroboration.")

    return {
        "score": score,
        "level": _confidence_level(score),
        "reasons": reasons,
        "breakdown": {
            "target_type": target_type,
            "weighted_account_score": round(weighted_score, 2),
            "top_accounts_used": len(ranked_accounts),
            "directly_verified_accounts": directly_verified,
            "verified_account_bonus": verified_bonus,
            "corroborated_accounts": corroborated_accounts,
            "corroborated_account_bonus": corroborated_bonus,
            "unique_tools": len(all_tools),
            "corroborating_tools": corroborating_tools,
            "high_value_platforms": high_value_platforms,
            "high_value_breadth_bonus": high_value_bonus,
            "metadata_accounts": metadata_accounts,
            "raw_score": round(raw_score, 2),
            "applied_cap": applied_cap,
        },
    }

def _account_score_value(account):
    """Return a safe numeric per-account confidence value."""

    try:
        return float(_clamp(float(account.get("confidence", 0))))
    except (TypeError, ValueError):
        return 0.0


def _is_rejected_account(account):
    """Identify an explicitly rejected or false-positive account."""

    verification = str(
        account.get("verification") or ""
    ).strip().casefold()

    status = str(
        account.get("status") or ""
    ).strip().casefold()

    return (
        verification == "false positive"
        or status == "rejected"
    )


def _needs_review_account(account):
    """Identify evidence that still requires analyst review."""

    signals = _verification_signals(account)

    if (
        signals["platform_api_verified"]
        or signals["direct_page_evidence"]
    ):
        return False

    verification = str(
        account.get("verification") or ""
    ).strip().casefold()

    status = str(
        account.get("status") or ""
    ).strip().casefold()

    review_markers = (
        "needs review",
        "review required",
        "inconclusive",
        "unknown",
        "candidate",
        "verification error",
    )

    return (
        verification == "error"
        or any(
            marker in verification
            for marker in review_markers
        )
        or any(
            marker in status
            for marker in review_markers
        )
    )


def _is_credible_account(account):
    """Return True when an account provides usable identity evidence."""

    signals = _verification_signals(account)

    if (
        signals["platform_api_verified"]
        or signals["direct_page_evidence"]
    ):
        return True

    return (
        _account_score_value(account) >= 45
        and not _needs_review_account(account)
    )


def _acceptance_ratio_penalty(credible_ratio):
    """Apply a bounded penalty when few detected candidates are credible."""

    ratio = _clamp(
        float(credible_ratio),
        0.0,
        1.0,
    )

    if ratio >= 0.75:
        return 0.0

    if ratio >= 0.50:
        return (
            (0.75 - ratio)
            / 0.25
        ) * 5.0

    if ratio >= 0.30:
        return 5.0 + (
            (0.50 - ratio)
            / 0.20
        ) * 7.0

    if ratio >= 0.15:
        return 12.0 + (
            (0.30 - ratio)
            / 0.15
        ) * 8.0

    if ratio >= 0.08:
        return 20.0 + (
            (0.15 - ratio)
            / 0.07
        ) * 5.0

    return 25.0


def _acceptance_ratio_cap(credible_ratio):
    """Limit maximum confidence when candidate precision is poor."""

    ratio = _clamp(
        float(credible_ratio),
        0.0,
        1.0,
    )

    if ratio >= 0.75:
        return 100

    if ratio >= 0.50:
        return 95

    if ratio >= 0.30:
        return 90

    if ratio >= 0.20:
        return 85

    if ratio >= 0.10:
        return 80

    if ratio >= 0.08:
        return 75

    return 65


def calculate_username_investigation_confidence(
    accounts,
    detected_account_count=None,
):
    """
    Calculate overall username confidence from evidence quality,
    verification strength, corroboration and investigation precision.
    """

    all_accounts = [
        account
        for account in (accounts or [])
        if isinstance(account, dict)
    ]

    usable_accounts = [
        account
        for account in all_accounts
        if not _is_rejected_account(account)
    ]

    for account in usable_accounts:
        breakdown = account.get(
            "confidence_breakdown"
        )

        current = (
            isinstance(breakdown, dict)
            and "direct_page_evidence_bonus" in breakdown
            and "platform_api_verification_bonus" in breakdown
        )

        if (
            not current
            or not isinstance(
                account.get("confidence"),
                (int, float),
            )
        ):
            score_account(account)

    try:
        supplied_detected_count = int(
            detected_account_count or 0
        )
    except (TypeError, ValueError):
        supplied_detected_count = 0

    detected_total = max(
        supplied_detected_count,
        len(all_accounts),
    )

    if not usable_accounts:
        return {
            "score": 0,
            "level": _confidence_level(0),
            "reasons": [
                "No accepted account evidence was available for this target."
            ],
            "breakdown": {
                "target_type": "username",
                "weighted_account_score": 0,
                "top_accounts_used": 0,
                "directly_verified_accounts": 0,
                "verified_account_bonus": 0,
                "corroborated_accounts": 0,
                "corroborated_account_bonus": 0,
                "unique_tools": 0,
                "corroborating_tools": [],
                "high_value_platforms": [],
                "high_value_breadth_bonus": 0,
                "metadata_accounts": 0,
                "raw_score": 0,
                "applied_cap": 0,
            },
        }

    weighted_score, ranked_accounts = (
        _weighted_top_account_score(
            usable_accounts
        )
    )

    signals = [
        _verification_signals(account)
        for account in usable_accounts
    ]

    credible_accounts = [
        account
        for account in usable_accounts
        if _is_credible_account(account)
    ]

    directly_verified = sum(
        signal["platform_api_verified"]
        or signal["direct_page_evidence"]
        for signal in signals
    )

    verified_bonus = _tiered_bonus(
        directly_verified,
        VERIFIED_ACCOUNT_BONUS,
        VERIFIED_FIVE_PLUS_BONUS,
        5,
    )

    credible_tool_sets = [
        _unique_tools(account)
        for account in credible_accounts
    ]

    corroborated_accounts = sum(
        len(tools) >= 2
        for tools in credible_tool_sets
    )

    corroborated_bonus = _tiered_bonus(
        corroborated_accounts,
        CORROBORATED_ACCOUNT_BONUS,
        CORROBORATED_FOUR_PLUS_BONUS,
        4,
    )

    corroborating_tools = sorted(
        {
            tool
            for tools in credible_tool_sets
            if len(tools) >= 2
            for tool in tools
        },
        key=str.casefold,
    )

    all_tools = sorted(
        {
            tool
            for tools in credible_tool_sets
            for tool in tools
        },
        key=str.casefold,
    )

    high_value_platforms = sorted(
        {
            _platform_label(account)
            for account in credible_accounts
            if _platform_key(account)
            in HIGH_VALUE_SITES
        },
        key=str.casefold,
    )

    high_value_bonus = _tiered_bonus(
        len(high_value_platforms),
        HIGH_VALUE_BREADTH_BONUS,
        HIGH_VALUE_FIVE_PLUS_BONUS,
        5,
    )

    metadata_accounts = sum(
        bool(_metadata_flags(account))
        for account in credible_accounts
    )

    explicit_rejected = (
        len(all_accounts)
        - len(usable_accounts)
    )

    inferred_rejected = max(
        detected_total
        - len(all_accounts),
        0,
    )

    rejected_count = (
        explicit_rejected
        + inferred_rejected
    )

    review_count = sum(
        _needs_review_account(account)
        for account in usable_accounts
    )

    low_confidence_count = sum(
        _account_score_value(account) < 45
        and not _needs_review_account(account)
        and not _is_credible_account(account)
        for account in usable_accounts
    )

    credible_count = len(
        credible_accounts
    )

    credible_ratio = (
        credible_count
        / detected_total
        if detected_total > 0
        else 0.0
    )

    acceptance_penalty = (
        _acceptance_ratio_penalty(
            credible_ratio
        )
    )

    denominator = max(
        detected_total,
        1,
    )

    low_confidence_penalty = min(
        6.0,
        (
            low_confidence_count
            / denominator
        ) * 8.0,
    )

    needs_review_penalty = min(
        8.0,
        (
            review_count
            / denominator
        ) * 12.0,
    )

    false_positive_penalty = min(
        8.0,
        (
            rejected_count
            / denominator
        ) * 10.0,
    )

    quality_penalty = min(
        25.0,
        acceptance_penalty
        + low_confidence_penalty
        + needs_review_penalty
        + false_positive_penalty,
    )

    raw_score = (
        weighted_score
        + verified_bonus
        + corroborated_bonus
        + high_value_bonus
    )

    applied_cap = _acceptance_ratio_cap(
        credible_ratio
    )

    score = round(
        _clamp(
            min(
                raw_score
                - quality_penalty,
                applied_cap,
            )
        )
    )

    reasons = []

    if directly_verified:
        noun = (
            "account"
            if directly_verified == 1
            else "accounts"
        )

        reasons.append(
            f"{directly_verified} {noun} passed direct page "
            "or platform-API verification."
        )

    high_confidence_count = sum(
        _account_score_value(account) >= 60
        for account in usable_accounts
    )

    moderate_confidence_count = sum(
        45
        <= _account_score_value(account)
        < 60
        and not _needs_review_account(account)
        for account in usable_accounts
    )

    if (
        high_confidence_count
        or moderate_confidence_count
    ):
        reasons.append(
            "Accepted evidence quality: "
            f"{high_confidence_count} high-confidence and "
            f"{moderate_confidence_count} moderate-confidence "
            "account(s)."
        )

    most_corroborated = sorted(
        credible_accounts,
        key=lambda account: (
            -len(
                _unique_tools(account)
            ),
            -_account_score_value(
                account
            ),
            _platform_label(
                account
            ).casefold(),
        ),
    )

    for account in most_corroborated[:3]:
        tools = _unique_tools(
            account
        )

        if len(tools) >= 2:
            reasons.append(
                f"{_platform_label(account)} was independently "
                f"confirmed by {len(tools)} tools."
            )

    if high_value_platforms:
        reasons.append(
            "Reliable identity platforms confirmed: "
            + _join_names(
                high_value_platforms
            )
            + "."
        )

    if (
        detected_total > 0
        and credible_count < detected_total
    ):
        reasons.append(
            f"{credible_count} of {detected_total} detected candidates "
            "provided credible evidence; weak, review-required, or "
            "rejected candidates reduced the overall confidence."
        )

    if review_count:
        reasons.append(
            f"{review_count} account(s) remain marked for review "
            "or inconclusive verification."
        )

    if low_confidence_count:
        reasons.append(
            f"{low_confidence_count} low-confidence account(s) "
            "reduced evidence reliability."
        )

    if rejected_count:
        reasons.append(
            f"{rejected_count} detected candidate(s) were rejected "
            "or removed as false positives."
        )

    if not reasons:
        reasons.append(
            "Accepted evidence was limited and lacked strong corroboration."
        )

    return {
        "score": score,
        "level": _confidence_level(
            score
        ),
        "reasons": reasons,
        "breakdown": {
            "target_type": "username",
            "weighted_account_score": round(
                weighted_score,
                2,
            ),
            "top_accounts_used": len(
                ranked_accounts
            ),
            "directly_verified_accounts": directly_verified,
            "verified_account_bonus": verified_bonus,
            "corroborated_accounts": corroborated_accounts,
            "corroborated_account_bonus": corroborated_bonus,
            "unique_tools": len(
                all_tools
            ),
            "corroborating_tools": corroborating_tools,
            "high_value_platforms": high_value_platforms,
            "high_value_breadth_bonus": high_value_bonus,
            "metadata_accounts": metadata_accounts,
            "raw_score": round(
                raw_score,
                2,
            ),
            "applied_cap": applied_cap,
        },
    }

# ---------------------------------------------------------------------------
# Email confidence
# ---------------------------------------------------------------------------


def _normalise_ghunt_result(ghunt):
    if not isinstance(ghunt, dict):
        return {}
    nested = ghunt.get("data")
    if isinstance(nested, dict):
        status = str(ghunt.get("status") or "").casefold()
        if not status or status in {"success", "partial"}:
            return nested
    return ghunt


def _normalise_holehe_findings(holehe):
    if isinstance(holehe, dict):
        findings = holehe.get("findings")
        return findings if isinstance(findings, list) else []
    return holehe if isinstance(holehe, list) else []


def _matching_holehe_findings(target, holehe):
    findings = []
    seen_platforms = set()

    for item in _normalise_holehe_findings(holehe):
        if not isinstance(item, dict):
            continue
        item_email = item.get("email")
        if item_email and str(item_email).casefold() != target.casefold():
            continue
        platform = item.get("website") or item.get("platform")
        if not platform:
            continue
        platform_key = str(platform).strip().casefold()
        if not platform_key or platform_key in seen_platforms:
            continue
        seen_platforms.add(platform_key)
        findings.append(item)

    return findings


def _ghunt_confirms_target(target, ghunt):
    ghunt = _normalise_ghunt_result(ghunt)
    return bool(
        ghunt.get("account_found") is True
        and ghunt.get("gaia_id")
        and isinstance(ghunt.get("email"), str)
        and ghunt["email"].casefold() == target.casefold()
    )


def _hibp_confirms_target(hibp):
    return bool(
        isinstance(hibp, dict)
        and hibp.get("configured") is True
        and hibp.get("breached") is True
        and isinstance(hibp.get("breaches"), list)
        and len(hibp["breaches"]) > 0
    )


def _ghunt_metadata_score(ghunt):
    score = 0
    reasons = []

    services = ghunt.get("google_services")
    service_count = len(services) if isinstance(services, list) else 0
    if service_count:
        if service_count <= 2:
            points = 2
        elif service_count <= 5:
            points = 4
        else:
            points = 6
        score += points
        reasons.append(f"{service_count} activated Google service(s)")

    if ghunt.get("maps_profile"):
        score += 4
        reasons.append("Google Maps profile")
    if ghunt.get("public_calendar") is True:
        score += 3
        reasons.append("public Google Calendar")

    calendar_events = ghunt.get("calendar_events")
    if isinstance(calendar_events, int) and calendar_events > 0:
        score += 2
        reasons.append("public calendar events")

    if ghunt.get("play_games") is True:
        score += 2
        reasons.append("Google Play Games profile")

    user_types = ghunt.get("user_types")
    if isinstance(user_types, list) and user_types:
        score += 2
        reasons.append("Google user-type metadata")

    if ghunt.get("last_profile_edit"):
        score += 2
        reasons.append("last profile edit metadata")
    if ghunt.get("entity_type"):
        score += 1
        reasons.append("entity-type metadata")
    if ghunt.get("enterprise_user") is not None:
        score += 1
        reasons.append("enterprise-account metadata")

    return min(score, GHUNT_METADATA_BONUS_CAP), reasons


def _holehe_service_points(service_count):
    if service_count <= 0:
        return 0
    if service_count == 1:
        return 14
    if service_count == 2:
        return 18
    if service_count <= 4:
        return 23
    if service_count <= 7:
        return 29
    if service_count <= 10:
        return 35
    if service_count <= 15:
        return 39
    return 42


def calculate_email_confidence(
    target,
    ghunt=None,
    holehe=None,
    hibp=None,
    **_unused,
):
    """Calculate email confidence from exact evidence and tool agreement."""

    target = str(
        target or ""
    ).strip()

    ghunt = _normalise_ghunt_result(
        ghunt
    )

    hibp = (
        hibp
        if isinstance(hibp, dict)
        else {}
    )

    ghunt_positive = _ghunt_confirms_target(
        target,
        ghunt,
    )

    holehe_findings = _matching_holehe_findings(
        target,
        holehe,
    )

    holehe_service_count = len(
        holehe_findings
    )

    holehe_positive = (
        holehe_service_count > 0
    )

    hibp_positive = _hibp_confirms_target(
        hibp
    )

    ghunt_base_points = (
        GHUNT_BASE_POINTS
        if ghunt_positive
        else 0
    )

    ghunt_metadata_bonus = 0
    ghunt_metadata_reasons = []

    if ghunt_positive:
        (
            ghunt_metadata_bonus,
            ghunt_metadata_reasons,
        ) = _ghunt_metadata_score(
            ghunt
        )

    holehe_points = _holehe_service_points(
        holehe_service_count
    )

    hibp_points = (
        HIBP_POSITIVE_POINTS
        if hibp_positive
        else 0
    )

    positive_tools = []

    if ghunt_positive:
        positive_tools.append(
            "GHunt"
        )

    if holehe_positive:
        positive_tools.append(
            "Holehe"
        )

    if hibp_positive:
        positive_tools.append(
            "HIBP"
        )

    agreement_bonus = (
        EMAIL_AGREEMENT_BONUS.get(
            len(positive_tools),
            20,
        )
    )

    raw_score = (
        ghunt_base_points
        + ghunt_metadata_bonus
        + holehe_points
        + hibp_points
        + agreement_bonus
    )

    if len(positive_tools) == 1:
        if ghunt_positive:
            applied_cap = 68
        elif holehe_positive:
            applied_cap = 45
        else:
            applied_cap = 25

    elif len(positive_tools) == 2:
        applied_cap = 95

    elif len(positive_tools) >= 3:
        applied_cap = 100

    else:
        applied_cap = 0

    score = round(
        _clamp(
            min(
                raw_score,
                applied_cap,
            )
        )
    )

    tool_scores = {
        "GHunt": (
            ghunt_base_points
            + ghunt_metadata_bonus
        ),
        "Holehe": holehe_points,
        "HIBP": hibp_points,
    }

    reasons = []

    if ghunt_positive:
        reasons.append(
            "GHunt confirmed the exact email address through "
            "a valid Google Gaia ID."
        )

        if ghunt_metadata_reasons:
            reasons.append(
                "Additional GHunt metadata: "
                + ", ".join(
                    ghunt_metadata_reasons
                )
                + "."
            )

    if holehe_positive:
        noun = (
            "service"
            if holehe_service_count == 1
            else "services"
        )

        reasons.append(
            f"Holehe confirmed the email on "
            f"{holehe_service_count} {noun}."
        )

    breach_count = 0

    if hibp_positive:
        breach_count = len(
            hibp.get(
                "breaches",
                [],
            )
        )

        noun = (
            "record"
            if breach_count == 1
            else "records"
        )

        reasons.append(
            f"HIBP returned {breach_count} breach {noun} "
            "for the exact email address."
        )

    if len(positive_tools) >= 2:
        reasons.append(
            "Independent email tools agree: "
            + _join_names(
                positive_tools
            )
            + "."
        )

    elif len(positive_tools) == 1:
        reasons.append(
            "Only one independent email source returned positive "
            "evidence, so confidence remains capped."
        )

    if not reasons:
        reasons.append(
            "No configured email tool returned positive evidence "
            "for the exact target address."
        )

    return {
        "score": score,
        "level": _confidence_level(
            score
        ),
        "reasons": reasons,
        "breakdown": {
            "target_type": "email",
            "positive_tools": positive_tools,
            "tool_scores": tool_scores,
            "ghunt_base_points": ghunt_base_points,
            "ghunt_metadata_bonus": ghunt_metadata_bonus,
            "holehe_service_count": holehe_service_count,
            "holehe_points": holehe_points,
            "hibp_breach_count": breach_count,
            "hibp_points": hibp_points,
            "agreement_bonus": agreement_bonus,
            "raw_score": raw_score,
        },
    }


# ---------------------------------------------------------------------------
# Confidence router
# ---------------------------------------------------------------------------


def calculate_investigation_confidence(
    target,
    accounts=None,
    ghunt=None,
    holehe=None,
    hibp=None,
    detected_account_count=None,
    **_unused,
):
    """Route confidence scoring without changing the response structure."""

    target_text = str(
        target or ""
    )

    if "@" in target_text:
        return calculate_email_confidence(
            target_text,
            ghunt=ghunt,
            holehe=holehe,
            hibp=hibp,
        )

    if "." in target_text:
        return calculate_username_confidence(
            accounts or [],
            target_type="domain",
        )

    return calculate_username_investigation_confidence(
        accounts or [],
        detected_account_count=detected_account_count,
    )