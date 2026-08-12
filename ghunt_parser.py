import re


def parse_ghunt_output(output):

    data = {
        "email": None,
        "gaia_id": None,
        "last_profile_edit": None,
        "default_profile_picture": False,
        "user_types": [],
        "entity_type": None,
        "enterprise_user": None,
        "google_services": [],
        "maps_profile": None,
        "public_calendar": False,
        "calendar_events": None,
        "play_games": False,
    }

    if not output:
        return data

    # -----------------------------
    # Default profile picture
    # -----------------------------

    if "Default profile picture" in output:
        data["default_profile_picture"] = True

    # -----------------------------
    # Email
    # -----------------------------

    match = re.search(r"Email\s*:\s*(.+)", output)

    if match:
        data["email"] = match.group(1).strip()

    # -----------------------------
    # Gaia ID
    # -----------------------------

    match = re.search(r"Gaia ID\s*:\s*(.+)", output)

    if match:
        data["gaia_id"] = match.group(1).strip()

    # -----------------------------
    # Last profile edit
    # -----------------------------

    match = re.search(r"Last profile edit\s*:\s*(.+)", output)

    if match:
        data["last_profile_edit"] = match.group(1).strip()

    # -----------------------------
    # Entity Type
    # -----------------------------

    match = re.search(r"Entity Type\s*:\s*(.+)", output)

    if match:
        data["entity_type"] = match.group(1).strip()

    # -----------------------------
    # Enterprise User
    # -----------------------------

    match = re.search(r"Entreprise User\s*:\s*(.+)", output)

    if match:
        value = match.group(1).strip().lower()
        data["enterprise_user"] = value == "true"

    # -----------------------------
    # Maps Profile
    # -----------------------------

    match = re.search(
        r"Profile page\s*:\s*(https?://\S+)",
        output
    )

    if match:
        data["maps_profile"] = match.group(1)

    # -----------------------------
    # Public Calendar
    # -----------------------------

    if "Public Google Calendar found" in output:
        data["public_calendar"] = True

    # -----------------------------
    # Calendar Events
    # -----------------------------

    if "No recent events found" in output:
        data["calendar_events"] = 0

    # -----------------------------
    # Play Games
    # -----------------------------

    if (
        "Play Games data" in output
        and
        "No player profile found" not in output
    ):
        data["play_games"] = True

    # -----------------------------
    # User Types
    # -----------------------------

    match = re.search(
        r"User types :(.*?)(?:📞|🌐|🎮|🗺️|🗓️)",
        output,
        re.S
    )

    if match:

        for line in match.group(1).splitlines():

            line = line.strip()

            if line.startswith("-"):

                data["user_types"].append(

                    line.split("(")[0]
                    .replace("-", "")
                    .strip()

                )

    # -----------------------------
    # Activated Google Services
    # -----------------------------

    match = re.search(
        r"Activated Google services :(.*?)(?:🎮|🗺️|🗓️)",
        output,
        re.S
    )

    if match:

        for line in match.group(1).splitlines():

            line = line.strip()

            if line.startswith("-"):

                data["google_services"].append(

                    line.replace("-", "")
                    .strip()

                )

    return data