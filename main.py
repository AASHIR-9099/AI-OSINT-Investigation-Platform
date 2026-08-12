from investigator import verify_profiles
from report_generator import generate_report
from hibp_tool import check_password


def main():

    print("""
====================================
        AI OSINT SYSTEM
====================================
""")

    while True:

        print("\nSelect Investigation Type")
        print("----------------------------")
        print("1. Email Investigation")
        print("2. Username Investigation")
        print("3. Domain Investigation")
        print("4. Password Breach Check")
        print("5. Exit")
        print()

        choice = input("Enter your choice: ").strip()

        # ---------------- EMAIL ----------------

        if choice == "1":

            target = input("\nEnter Email: ").strip()

            print("\n[+] Running Email Investigation...\n")

            result = verify_profiles(target)

            generate_report(result)

        # ---------------- USERNAME ----------------

        elif choice == "2":

            target = input("\nEnter Username: ").strip()

            print("\n[+] Running Username Investigation...\n")

            result = verify_profiles(target)

            generate_report(result)

        # ---------------- DOMAIN ----------------

        elif choice == "3":

            target = input("\nEnter Domain: ").strip()

            print("\n[+] Running Domain Investigation...\n")

            result = verify_profiles(target)

            generate_report(result)

        # ---------------- PASSWORD ----------------

        elif choice == "4":

            password = input("\nEnter Password: ").strip()

            print("\n[+] Checking password against Have I Been Pwned...\n")

            result = check_password(password)

            print("\n" + "=" * 60)
            print("              PASSWORD BREACH REPORT")
            print("=" * 60)

            if result.get("error"):

                print("\nError:", result["error"])

            elif result.get("pwned"):

                print("\nPassword Status : BREACHED")
                print("Times Found     :", result["count"])

            else:

                print("\nPassword Status : NOT FOUND")
                print("Times Found     : 0")

            print("\n" + "=" * 60)

        # ---------------- EXIT ----------------

        elif choice == "5":

            print("\nThank you for using AI OSINT System.")
            break

        else:

            print("\nInvalid choice. Please try again.")


if __name__ == "__main__":
    main()
