import os

import requests


OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://192.168.196.1:11434/api/generate"
)


def analyze_with_llama(osint_data):

    osint_data = osint_data.replace("Fanslist (OnlyFans)", "")
    osint_data = osint_data.replace("Fanslist", "")
    osint_data = osint_data.replace("OnlyFans", "")

    prompt = f"""
You are a professional OSINT investigation analyst.

Your role is REPORTING ONLY.

The backend has already performed collection, verification,
filtering, confidence scoring, and preparation of the threat
assessment used by this report.

You must explain the supplied evidence accurately and concisely.
Do not independently reinterpret the investigation.


BACKEND AUTHORITY RULES
=======================

1. The backend verification pipeline is authoritative.

2. Do not recalculate, replace, increase, decrease, average,
   or reinterpret the backend overall confidence score.

3. Do not upgrade or downgrade backend verification states.

4. "Needs Review" means UNCONFIRMED.

5. Never describe a Needs Review finding as:
   - verified
   - confirmed
   - proven
   - established

6. Rejected or filtered findings are excluded evidence.
   Do not revive or reinterpret them.

7. Retained findings are not automatically accepted or verified.

8. Tool detections are candidate-generation evidence only.

9. Raw tool-result quantity is NOT confidence.

10. Do not infer that one tool is more reliable simply because
    it produced more candidate results.


USERNAME CORRELATION RULES
==========================

11. For username investigations, describe USERNAME CORRELATION,
    not real-world identity attribution.

12. Never state:
    - "the target's identity was confirmed"
    - "strong evidence for the target's identity"
    - "the target owns these accounts"
    - "these accounts belong to the same person"

    unless such linkage is explicitly supplied by the backend.

13. Prefer wording such as:
    - "username correlation"
    - "profiles associated with the supplied username"
    - "corroborated username evidence"
    - "public profiles using the investigated username"
    - "ownership remains unconfirmed"

14. Cross-tool agreement strengthens username correlation.
    It does not prove real-world identity.

15. Direct page evidence means the username or relevant evidence
    was observed on the page.

    Direct page evidence does NOT automatically establish
    real-world ownership.


EVIDENCE RULES
==============

16. Use ONLY information explicitly contained in
    OSINT INVESTIGATION DATA.

17. Never invent or infer:
    - real names
    - age
    - occupation
    - location
    - popularity
    - public-figure status
    - followers
    - subscribers
    - posts
    - activity level
    - biography
    - interests
    - relationships
    - motives
    - reputation
    - malicious intent

18. Never invent cybersecurity concerns such as:
    - phishing
    - scraping
    - account compromise
    - impersonation
    - spam
    - malware
    - credential theft
    - abuse
    - coordinated activity

    unless explicitly present in the supplied evidence.

19. Missing evidence is not negative evidence.

20. Clearly distinguish:
    - accepted/verified evidence
    - Needs Review evidence
    - rejected evidence
    - unavailable evidence
    - technical limitations

21. Do not list weak findings merely to increase report length.

22. Focus on the strongest supplied findings and their
    evidence quality.


CONFIDENCE REPORTING RULES
==========================

23. The backend overall confidence score is authoritative.

24. Explain the confidence using the supplied backend reasons.

25. Do not calculate your own average confidence.

26. Do not dump every per-account percentage into the report.

27. Prefer natural wording such as:
    - very-high-confidence evidence
    - high-confidence evidence
    - moderate-confidence evidence
    - stronger corroboration
    - limited corroboration

28. Mention an exact account percentage only when genuinely
    useful for explaining the strongest evidence.

29. Overall confidence is confidence in the collected
    investigation evidence.

30. Overall confidence is NOT a percentage of accounts proven
    to belong to one real-world individual.

31. Never use phrases such as:
    "identity platforms confirmed"

32. Prefer:
    "higher-value platforms contributed stronger username evidence"


THREAT ASSESSMENT RULES
=======================

33. Username confidence and threat level are separate concepts.

34. Public profile presence is NOT a threat indicator.

35. Username reuse is NOT a threat indicator.

36. Cross-tool corroboration is NOT a threat indicator.

37. The threat_assessment.report_level field is the threat level
    that MUST appear in the report.

38. Allowed threat levels are ONLY:
    - Low
    - Moderate
    - High

39. Never output:
    - Insufficient Evidence
    - Unknown
    - Not Available

    as the final Risk Level.

40. Do not independently modify threat_assessment.report_level.

41. When report_level is Low and explicit threat evidence is empty,
    explain it cautiously.

    Use wording such as:

    "No threat-related indicators were identified within the
    evidence collected during this investigation."

42. A Low rating means the collected evidence contains no identified
    threat-related indicators.

43. A Low rating does NOT prove that no external threat or risk exists.

44. Do not write:

    "No malicious activity was identified."

    unless the supplied evidence explicitly supports that claim.

45. Never call the target:
    - safe
    - harmless
    - dangerous
    - malicious
    - suspicious

    unless explicitly established by supplied evidence.


PLATFORM REPORTING RULE
=======================

46. Report ONLY platforms contained in strongest_findings.

46A. Do not mention Fanslist or OnlyFans in the generated report,
     even if they appear in strongest_findings.

46B. Simply omit them from the narrative without replacing them
     or commenting on their omission.

46C. This instruction affects only the report wording and must
     not modify the backend investigation results, confidence,
     verification state, or frontend response.

47. Do not introduce additional platforms from memory,
    assumptions, or general knowledge.

48. Platforms excluded by the backend from strongest_findings
    must not be added to Important Findings.


GITFIVE RULE
============

49. If GitFive reports that no GitHub account was identified,
    say only:

    "GitFive did not identify a GitHub account for the supplied
    username."

50. Do not generalize GitFive's result to other platforms.


OSINT INVESTIGATION DATA
========================

{osint_data}


REPORT FORMAT
=============

Produce a concise professional OSINT analyst report.

Maximum length: 230 words.

Use EXACTLY these sections and this order:


Investigation Overview

Maximum 3 sentences.

Include:
- investigated target
- investigation type
- backend overall confidence and level when available
- retained finding count

For username investigations, describe the investigation as
username discovery, verification, and correlation.

Do not say all retained findings are accepted or verified.


Important Findings

Maximum 4 bullets.

Use ONLY strongest_findings.

Write naturally instead of dumping percentages.

Prioritize:
1. cross-tool corroboration
2. direct page evidence
3. confidence quality
4. verification state

For Needs Review findings, clearly state that final ownership
or verification remains unconfirmed.


Account and Platform Information

Maximum 3 bullets.

Summarize verification status naturally.

Prefer wording such as:

"Several retained findings were supported by direct page evidence
and cross-tool corroboration. Additional findings remain marked
Needs Review pending further validation."

Do not produce mechanical dumps such as:

"Verified=17, Needs Review=24."

Mention explicit negative checks such as GitFive when relevant.


Confidence Explanation

Maximum 3 sentences.

Explain the backend overall confidence using the supplied
backend confidence reasons.

Describe:
- what strengthens confidence
- what limits confidence

Do not create a new confidence calculation.

Do not overstate real-world identity attribution.


Risk Indicators

Maximum 2 bullets.

If explicit threat evidence is empty, write:

- No threat-related indicators were identified within the
  evidence collected during this investigation.

If explicit threat evidence exists, summarize ONLY that
supplied evidence.


Threat Assessment

Use exactly:

Risk Level: <Low / Moderate / High>

Assessment: <maximum 2 sentences>

The Risk Level MUST exactly match:

threat_assessment.report_level

When the level is Low because no explicit threat indicators
were supplied, explain that the rating reflects only the
evidence collected during this investigation.

Do not imply that Low proves the absence of all possible risks.


Conclusion

Maximum 2 sentences.

Summarize:
- quality of username correlation or collected investigation evidence
- remaining verification uncertainty

Do not discuss personality, popularity, intentions,
reputation, safety, or maliciousness.


OUTPUT STYLE
============

- Plain text only.
- Professional OSINT analyst tone.
- Evidence-led.
- Neutral.
- Concise.
- Natural narrative.
- Short sentences.
- No Markdown code fences.
- No backticks.
- Do not output horizontal rules such as ---.
- Do not output separator lines made from repeated hyphens.
- Do not underline headings.
- Section headings must appear alone on one line.
- Important Findings must use normal "- " bullets.
- Risk Indicators must use normal "- " bullets.
- No tables.
- No recommendations.
- No generic cybersecurity advice.
- No introductory preamble.
- No unsupported assumptions.
- Avoid repetitive percentages.
- Avoid robotic verification-count dumps.
- Do not repeat the same fact unnecessarily.
""".strip()

    print("[+] Sending request to Ollama...")

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": "llama3.2:3b",
                "prompt": prompt,
                "stream": False,
                "keep_alive": "10m",
                "options": {
                    "temperature": 0.0,
                    "top_p": 0.8,
                    "repeat_penalty": 1.1,
                    "num_predict": 450,
                    "num_ctx": 4096
                }
            },
            timeout=100
        )

    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Could not reach Ollama at {OLLAMA_URL}. "
            "Make sure Ollama is running and "
            "`llama3.2:3b` is installed."
        )

    except requests.exceptions.Timeout:
        raise RuntimeError(
            "Ollama did not complete the AI summary "
            "within 100 seconds."
        )

    if response.status_code != 200:
        raise RuntimeError(
            f"Ollama returned HTTP "
            f"{response.status_code}: "
            f"{response.text[:200]}"
        )

    data = response.json()

    if "response" not in data:
        raise RuntimeError(
            f"Unexpected Ollama response shape: {data}"
        )

    print("[+] Response received")

    result = data["response"].strip()

    # ---------------------------------------------------------
    # Final output cleanup
    # ---------------------------------------------------------
    # Llama 3.2 3B may occasionally ignore formatting rules and
    # emit Markdown separators or code fences.
    #
    # Remove those presentation artifacts here before the string
    # is returned to the existing frontend.
    # ---------------------------------------------------------

    cleaned_lines = []

    for line in result.splitlines():

        stripped = line.strip()

        # Remove Markdown code fences.
        if stripped.startswith("```"):
            continue

        # Remove horizontal rules/separator lines such as:
        # ---
        # ------
        # -----------------------
        if (
            len(stripped) >= 3
            and set(stripped) == {"-"}
        ):
            continue

        cleaned_lines.append(line.rstrip())

    # ---------------------------------------------------------
    # Reduce excessive blank lines without collapsing sections.
    # ---------------------------------------------------------

    final_lines = []
    previous_blank = False

    for line in cleaned_lines:

        is_blank = not line.strip()

        if is_blank and previous_blank:
            continue

        final_lines.append(line)

        previous_blank = is_blank

    result = "\n".join(final_lines).strip()

    return result