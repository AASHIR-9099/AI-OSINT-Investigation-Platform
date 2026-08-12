import json

from ollama_ai import analyze_with_llama


MAX_KEY_FINDINGS = 5


def _normalize_confidence(value):
    """
    Normalize confidence values.

    Supports:
        0.85 -> 85.0
        85   -> 85.0
    """

    if isinstance(value, bool):
        return None

    if not isinstance(value, (int, float)):
        return None

    score = float(value)

    if 0 <= score <= 1:
        score *= 100

    if 0 <= score <= 100:
        return round(score, 1)

    return None


def _normalize_text(value):
    if value is None:
        return ""

    return str(value).strip()


def _platform_name(account):
    """
    Return a consistent platform label without changing
    the underlying investigation result.
    """

    platform = (
        account.get("website")
        or account.get("platform")
        or account.get("site")
        or "Unknown Platform"
    )

    text = str(platform).strip()

    normalized = "".join(
        character
        for character in text.casefold()
        if character.isalnum()
    )

    aliases = {
        "github": "GitHub",
        "githubcom": "GitHub",

        "instagram": "Instagram",
        "instagramcom": "Instagram",

        "facebook": "Facebook",
        "facebookcom": "Facebook",

        "x": "X/Twitter",
        "xcom": "X/Twitter",
        "twitter": "X/Twitter",
        "twittercom": "X/Twitter",

        "linkedin": "LinkedIn",
        "linkedincom": "LinkedIn",

        "reddit": "Reddit",
        "redditcom": "Reddit",

        "snapchat": "Snapchat",
        "snapchatcom": "Snapchat",

        "discord": "Discord",
        "discordcom": "Discord",

        "tiktok": "TikTok",
        "tiktokcom": "TikTok",

        "youtube": "YouTube",
        "youtubecom": "YouTube",
    }

    return aliases.get(
        normalized,
        text or "Unknown Platform",
    )


def _verification_bucket(account):
    """
    Convert existing backend verification labels into
    report-only categories.

    This does NOT modify backend verification.
    """

    verification = _normalize_text(
        account.get("verification")
    ).casefold()

    status = _normalize_text(
        account.get("status")
    ).casefold()

    if any(
        term in verification
        for term in (
            "reject",
            "false positive",
            "invalid",
        )
    ):
        return "rejected"

    if any(
        term in status
        for term in (
            "reject",
            "false positive",
            "invalid",
        )
    ):
        return "rejected"

    if any(
        term in verification
        for term in (
            "verified",
            "accepted",
            "confirmed",
        )
    ):
        return "verified"

    if verification in {
        "needs review",
        "review",
        "unverified",
        "inconclusive",
    }:
        return "needs_review"

    if verification in {
        "error",
        "failed",
        "failure",
    }:
        return "error"

    return "unknown"


def _direct_evidence(account):
    """
    Return the backend's direct-evidence flag only.

    Direct evidence is NOT treated as proof of ownership.
    """

    breakdown = account.get("confidence_breakdown")

    return bool(
        isinstance(breakdown, dict)
        and breakdown.get("direct_evidence") is True
    )


def _account_tools(account):
    """
    Return evidence-source names associated with an account.
    """

    tools = account.get("tools")

    if isinstance(tools, list):
        return [
            str(tool)
            for tool in tools
            if tool
        ]

    source = account.get("source")

    if source:
        return [str(source)]

    return []


def _account_rank(account):
    """
    Rank findings only for deciding which ones are worth
    sending to the language model.

    This is NOT the investigation-confidence calculation.
    """

    confidence = _normalize_confidence(
        account.get("confidence")
    )

    bucket = _verification_bucket(account)

    verification_rank = {
        "verified": 4,
        "needs_review": 3,
        "unknown": 2,
        "error": 1,
        "rejected": 0,
    }.get(bucket, 0)

    return (
        verification_rank,
        1 if _direct_evidence(account) else 0,
        confidence if confidence is not None else -1,
        len(_account_tools(account)),
    )


def _best_findings_by_platform(accounts):
    """
    Keep only the strongest retained representation
    of each platform for AI summarization.

    The original accounts array is not modified.
    """

    best = {}

    for account in accounts:
        if not isinstance(account, dict):
            continue

        # Rejected evidence should not become a highlighted finding.
        if _verification_bucket(account) == "rejected":
            continue

        platform = _platform_name(account)
        key = platform.casefold()

        current = best.get(key)

        if (
            current is None
            or _account_rank(account) > _account_rank(current)
        ):
            best[key] = account

    findings = list(best.values())

    findings.sort(
        key=_account_rank,
        reverse=True,
    )

    return findings[:MAX_KEY_FINDINGS]


def _compact_finding(account):
    """
    Create a small evidence-led representation of a finding.

    URLs are intentionally excluded because they add model input
    without improving the investigation summary.
    """

    confidence = _normalize_confidence(
        account.get("confidence")
    )

    finding = {
        "platform": _platform_name(account),

        "confidence_percent": confidence,

        "confidence_label": (
            account.get("status")
            or "Not provided"
        ),

        "verification": (
            account.get("verification")
            or "Not provided"
        ),

        "direct_page_evidence": _direct_evidence(
            account
        ),

        "evidence_sources": _account_tools(
            account
        ),
    }

    reasons = account.get("reasons")

    if isinstance(reasons, list) and reasons:
        finding["evidence_notes"] = [
            str(reason)
            for reason in reasons[:3]
        ]

    verification_reason = account.get(
        "verification_reason"
    )

    if (
        isinstance(verification_reason, list)
        and verification_reason
    ):
        finding["verification_notes"] = [
            str(reason)
            for reason in verification_reason[:2]
        ]

    elif verification_reason:
        finding["verification_notes"] = [
            str(verification_reason)
        ]

    return finding


def _scope_notes(scan_results, target_type):
    """
    Capture explicit negative checks and technical scope
    without converting missing evidence into negative findings.
    """

    notes = []

    gitfive = scan_results.get("gitfive")

    if (
        target_type == "Username"
        and isinstance(gitfive, dict)
    ):
        if gitfive.get("github_found") is False:
            notes.append(
                "GitFive did not identify a GitHub account "
                "for the supplied username."
            )

        elif gitfive.get("github_found") is True:
            notes.append(
                "GitFive identified GitHub evidence "
                "for the supplied username."
            )

    hibp = scan_results.get("hibp")

    if isinstance(hibp, dict):

        if hibp.get("skipped") is True:
            reason = (
                hibp.get("reason")
                or "HIBP was skipped."
            )

            notes.append(str(reason))

        elif hibp.get("breached") is True:
            breaches = hibp.get("breaches")

            count = (
                len(breaches)
                if isinstance(breaches, list)
                else None
            )

            if count is None:
                notes.append(
                    "HIBP explicitly identified "
                    "credential or breach exposure."
                )
            else:
                notes.append(
                    "HIBP explicitly identified "
                    f"{count} breach record(s)."
                )

        elif hibp.get("breached") is False:
            notes.append(
                "HIBP explicitly reported no known "
                "breaches for the supplied email."
            )

        elif hibp.get("error"):
            notes.append(
                "HIBP check failed; breach status "
                "is unavailable."
            )

    return notes


def _explicit_threat_evidence(scan_results):
    """
    Collect only explicit threat-related evidence that already
    exists in the backend response.

    Account discovery itself is NOT considered threat evidence.
    """

    evidence = []

    for field in (
        "threat_evidence",
        "risk_indicators",
        "threat_indicators",
    ):
        value = scan_results.get(field)

        if isinstance(value, list):
            evidence.extend(
                str(item)
                for item in value
                if item
            )

        elif isinstance(value, str):
            value = value.strip()

            if value:
                evidence.append(value)

    hibp = scan_results.get("hibp")

    if (
        isinstance(hibp, dict)
        and hibp.get("breached") is True
    ):
        evidence.append(
            "Credential or breach exposure was "
            "explicitly reported by HIBP."
        )

    # Preserve order while removing duplicates.
    unique_evidence = []

    seen = set()

    for item in evidence:
        key = item.casefold()

        if key in seen:
            continue

        seen.add(key)
        unique_evidence.append(item)

    return unique_evidence


def _backend_threat_level(scan_results):
    """
    Read an existing backend threat/risk level if one exists.

    No new threat level is calculated here.
    """

    possible_fields = (
        "threat_level",
        "threatLevel",
        "risk_level",
        "riskLevel",
    )

    for field in possible_fields:
        value = scan_results.get(field)

        if value is not None and str(value).strip():
            return str(value).strip()

    return None


def generate_ai_summary(scan_results):
    """
    Convert the backend result into a compact evidence package
    for Ollama.

    External contract remains unchanged:

        generate_ai_summary(scan_results) -> str
    """

    if not isinstance(scan_results, dict):
        scan_results = {}

    summary = scan_results.get("summary")

    if not isinstance(summary, dict):
        summary = {}

    accounts = scan_results.get("accounts")

    if not isinstance(accounts, list):
        accounts = []

    target = scan_results.get(
        "target",
        "Unknown",
    )

    username = scan_results.get("username")

    explicit_target_type = scan_results.get(
        "target_type"
    )

    if explicit_target_type:
        target_type = str(
            explicit_target_type
        ).strip().title()

    elif "@" in str(target):
        target_type = "Email"

    else:
        target_type = "Username"

    # ---------------------------------------------------------
    # Authoritative overall confidence from backend
    # ---------------------------------------------------------

    overall_confidence = _normalize_confidence(
        scan_results.get("confidence")
    )

    confidence_level = (
        scan_results.get("confidence_level")
        or "Not provided"
    )

    confidence_reasons = scan_results.get(
        "confidence_reasons"
    )

    if not isinstance(confidence_reasons, list):
        confidence_reasons = []

    confidence_breakdown = scan_results.get(
        "confidence_breakdown"
    )

    if not isinstance(confidence_breakdown, dict):
        confidence_breakdown = {}

    # ---------------------------------------------------------
    # Verification overview
    # ---------------------------------------------------------

    verification_counts = {
        "verified_or_accepted": 0,
        "needs_review": 0,
        "rejected_in_retained_findings": 0,
        "error_or_failed": 0,
        "unknown": 0,
    }

    direct_evidence_count = 0

    tools_represented = set()

    for account in accounts:

        if not isinstance(account, dict):
            continue

        bucket = _verification_bucket(account)

        if bucket == "verified":
            verification_counts[
                "verified_or_accepted"
            ] += 1

        elif bucket == "needs_review":
            verification_counts[
                "needs_review"
            ] += 1

        elif bucket == "rejected":
            verification_counts[
                "rejected_in_retained_findings"
            ] += 1

        elif bucket == "error":
            verification_counts[
                "error_or_failed"
            ] += 1

        else:
            verification_counts[
                "unknown"
            ] += 1

        if _direct_evidence(account):
            direct_evidence_count += 1

        tools_represented.update(
            _account_tools(account)
        )

    strongest_findings = [
        _compact_finding(account)
        for account in _best_findings_by_platform(
            accounts
        )
    ]

    explicit_threat_evidence = (
        _explicit_threat_evidence(
            scan_results
        )
    )

    backend_threat_level = (
        _backend_threat_level(
            scan_results
        )
    )

    # ---------------------------------------------------------
    # Structured evidence package for Llama
    # ---------------------------------------------------------

    evidence_package = {
        "investigation": {
            "target": target,
            "target_type": target_type,
            "username": username,
            "retained_findings": len(accounts),
            "backend_unique_findings": summary.get(
                "unique"
            ),
            "interpretation": (
                "Retained or unique findings are candidate "
                "findings. They are not automatically accepted, "
                "verified, or confirmed."
            ),
        },

        "overall_confidence": {
            "score_percent": overall_confidence,
            "level": confidence_level,
            "backend_reasons": [
                str(reason)
                for reason in confidence_reasons
            ],
            "breakdown": confidence_breakdown,
            "authority_rule": (
                "The backend confidence value is authoritative. "
                "The AI must explain it, not recalculate it."
            ),
        },

        "verification_summary": {
            **verification_counts,

            "direct_evidence_findings": (
                direct_evidence_count
            ),

            "interpretation": (
                "Direct page evidence supports the presence "
                "of the investigated username or relevant "
                "evidence on a page. It does not automatically "
                "prove real-world identity or account ownership."
            ),
        },

        "tools_represented": sorted(
            tools_represented
        ),

        "tool_count_policy": (
            "Raw candidate counts produced by individual tools "
            "are deliberately excluded from this AI evidence "
            "package. Candidate quantity is not confidence."
        ),

        "strongest_findings": strongest_findings,

        "scope_and_explicit_negative_checks": (
            _scope_notes(
                scan_results,
                target_type,
            )
        ),

        "threat_assessment": {
            "backend_threat_level": (
                backend_threat_level
            ),

            "explicit_threat_evidence": (
                explicit_threat_evidence
            ),

            "interpretation": (
                "Threat assessment must be based only on "
                "explicitly supplied threat evidence. "
                "Public profile presence, username reuse, "
                "and cross-tool correlation are not threats "
                "by themselves."
            ),
        },

        "reporting_policy": {
            "primary_subject": (
                "username correlation and evidence quality"
                if target_type == "Username"
                else "the supplied investigation target"
            ),

            "backend_is_authoritative": True,

            "needs_review_means_unconfirmed": True,

            "rejected_findings_are_excluded_evidence": True,

            "do_not_claim_real_world_identity": (
                target_type == "Username"
            ),
        },
    }

    osint_data = json.dumps(
        evidence_package,
        ensure_ascii=False,
        indent=2,
        sort_keys=False,
    )

    return analyze_with_llama(osint_data)