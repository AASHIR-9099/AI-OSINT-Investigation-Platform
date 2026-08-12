def generate_report(result):

    print("\n")
    print("=" * 70)
    print("                     AI OSINT REPORT")
    print("=" * 70)

    print(f"\nTarget   : {result.get('target')}")

    username = result.get("username")
    if username:
        print(f"Username : {username}")
    else:
        print("Username : Not applicable")

    # ================= ACCOUNTS =================

    print("\n" + "=" * 70)
    print("                  ACCOUNTS FOUND")
    print("=" * 70)

    accounts = result.get("accounts", [])

    if accounts:

        for account in accounts:

            platform = account.get("website") or account.get("platform")
            print(f"\n✓ {platform}")

            if account.get("url"):
                print(f"  {account.get('url')}")

    else:

        print("No accounts found.")


    # ================= GITHUB =================

    print("\n" + "=" * 70)
    print("                GITHUB INTELLIGENCE")
    print("=" * 70)

    gitfive = result.get("gitfive", {})

    if gitfive.get("github_found"):

        print("GitHub Profile : FOUND")
        print(f"Username       : {gitfive.get('username')}")
        print(f"Profile URL    : https://github.com/{gitfive.get('username')}")

    else:

        print("GitHub Profile : NOT FOUND")


    # ================= GOOGLE =================

    print("\n" + "=" * 70)
    print("                GOOGLE INTELLIGENCE")
    print("=" * 70)

    ghunt = result.get("ghunt", {})

    if ghunt:

        print("Google account information found.")

    else:

        print("No Google information available.")


    # ================= BREACH INTELLIGENCE =================

    print("\n" + "=" * 70)
    is_email_target = "@" in str(result.get("target", ""))

    if is_email_target:
        print("                EMAIL BREACH CHECK")
    else:
        print("              PASSWORD BREACH CHECK")
    print("=" * 70)

    hibp = result.get("hibp", {})

    if hibp.get("skipped"):

        if is_email_target:
            print("Email breach check not configured or skipped.")
        else:
            print("Password breach check skipped.")

    elif hibp.get("error"):

        print("Error :", hibp["error"])

    elif "breached" in hibp:

        if hibp.get("breached"):

            breaches = hibp.get("breaches", [])
            print("Email Status : BREACHED")
            print("Breaches     :", len(breaches))

            if breaches:
                print("Sources      :", ", ".join(breaches))

        else:

            print("Email Status : NO KNOWN BREACHES FOUND")

    elif hibp.get("pwned"):

        print("Status      : BREACHED")
        print("Occurrences :", hibp["count"])

    else:

        print("Status      : NOT FOUND")
        print("Occurrences : 0")


    # ================= AI ANALYSIS =================

    print("\n" + "=" * 70)
    print("                 AI INTELLIGENCE ANALYSIS")
    print("=" * 70)

    ai_summary = result.get("ai_summary", "")

    if ai_summary:

        print(ai_summary)

    else:

        print("AI summary not available.")


    # ================= SUMMARY =================

    print("\n" + "=" * 70)
    print("                     SUMMARY")
    print("=" * 70)

    summary = result.get("summary", {})

    print(f"Sherlock Accounts  : {summary.get('sherlock',0)}")
    print(f"Blackbird Accounts : {summary.get('blackbird',0)}")
    print(f"Maigret Accounts   : {summary.get('maigret',0)}")
    print(f"WhatsMyName        : {summary.get('whatsmyname',0)}")
    print(f"GitFive Results    : {summary.get('gitfive',0)}")
    print(f"Holehe Results     : {summary.get('holehe',0)}")
    print(f"GHunt Results      : {summary.get('ghunt',0)}")
    print(f"HIBP Status        : {summary.get('hibp','Skipped')}")
    print(f"Unique Accounts    : {summary.get('unique',0)}")


    print("\n" + "=" * 70)
    print("            SCAN COMPLETED SUCCESSFULLY")
    print("=" * 70)
