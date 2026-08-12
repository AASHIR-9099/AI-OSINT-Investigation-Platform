import hashlib
import os
import requests


def check_password(password):

    sha1 = hashlib.sha1(
        password.encode("utf-8")
    ).hexdigest().upper()

    prefix = sha1[:5]
    suffix = sha1[5:]


    url = f"https://api.pwnedpasswords.com/range/{prefix}"


    try:

        response = requests.get(
            url,
            timeout=10,
            headers={
                "User-Agent": "AI-OSINT-System"
            }
        )


    except requests.exceptions.Timeout:

        return {
            "error": "HIBP request timeout"
        }


    except requests.exceptions.RequestException as e:

        return {
            "error": str(e)
        }



    if response.status_code != 200:

        return {
            "error": "HIBP API unavailable",
            "status": response.status_code
        }



    for line in response.text.splitlines():

        hash_suffix, count = line.split(":")


        if hash_suffix == suffix:

            return {

                "pwned": True,

                "count": int(count)

            }



    return {

        "pwned": False,

        "count": 0

    }



# -----------------------------------------------------------------
# Email / account breach lookup.
#
# NOTE: unlike the Pwned Passwords range API above (which is free
# and needs no key), HaveIBeenPwned's "breachedaccount" endpoint has
# required a paid API key since late 2024. There is no free way
# around this - so instead of silently faking a result, this reads
# an optional HIBP_API_KEY environment variable:
#   - key not set   -> returns a clear "not configured" status
#   - key set        -> does a real breach lookup for the email
#
# Get a key at https://haveibeenpwned.com/API/Key if you want this
# to actually run for email targets.
# -----------------------------------------------------------------
def check_email_breaches(email, api_key=None):

    api_key = api_key or os.environ.get("HIBP_API_KEY")

    if not api_key:

        return {

            "configured": False,

            "skipped": True,

            "status": "not_configured",

            "reason": (
                "HIBP_API_KEY not set. Get a key at "
                "https://haveibeenpwned.com/API/Key and set it as "
                "the HIBP_API_KEY environment variable to enable "
                "email breach checks."
            )

        }

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

    try:

        response = requests.get(
            url,
            timeout=10,
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "AI-OSINT-System"
            },
            params={"truncateResponse": "true"}
        )

    except requests.exceptions.Timeout:

        return {
            "configured": True,
            "status": "timeout",
            "error": "HIBP request timeout"
        }

    except requests.exceptions.RequestException as e:

        return {
            "configured": True,
            "status": "failed",
            "error": str(e)
        }

    if response.status_code == 404:

        # No breaches found for this account - not an error.
        return {
            "configured": True,
            "status": "no_results",
            "breached": False,
            "breaches": []
        }

    if response.status_code == 401:

        return {
            "configured": True,
            "status": "failed",
            "error": "HIBP rejected the API key (401 Unauthorized). Check HIBP_API_KEY."
        }

    if response.status_code == 429:

        return {
            "configured": True,
            "status": "rate_limited",
            "error": "HIBP rate limit hit. Try again shortly."
        }

    if response.status_code != 200:

        return {
            "configured": True,
            "status": "failed",
            "error": f"HIBP API returned HTTP {response.status_code}"
        }

    try:
        data = response.json()

    except ValueError as exc:
        return {
            "configured": True,
            "status": "parser_failure",
            "error": f"HIBP returned invalid JSON: {exc}"
        }

    if not isinstance(data, list):
        return {
            "configured": True,
            "status": "parser_failure",
            "error": "HIBP returned an unexpected response structure"
        }

    breach_names = [
        item.get("Name")
        for item in data
        if isinstance(item, dict) and item.get("Name")
    ]

    if data and not breach_names:
        return {
            "configured": True,
            "status": "parser_failure",
            "error": "HIBP breach entries did not contain expected names"
        }

    breach_names = list(dict.fromkeys(breach_names))

    return {
        "configured": True,
        "status": "success" if breach_names else "no_results",
        "breached": len(breach_names) > 0,
        "breaches": breach_names
    }



if __name__ == "__main__":


    password = input(
        "Enter password to check: "
    )


    result = check_password(password)


    print(result)
