import unittest

from verification.confidence import (
    calculate_username_confidence,
    score_account,
)


HIGH_VALUE_PLATFORMS = (
    "GitHub",
    "Instagram",
    "YouTube",
    "Reddit",
    "TikTok",
    "X",
)


def make_account(
    index,
    verification="Verified",
    tools=None,
    platform=None,
    identity_linked=False,
    metadata=False,
):
    platform = platform or HIGH_VALUE_PLATFORMS[
        index % len(HIGH_VALUE_PLATFORMS)
    ]
    account = {
        "website": platform,
        "url": f"https://profiles.example/{index}/target",
        "username": "target",
        "tools": tools or ["Sherlock", "Blackbird"],
        "verification": verification,
        "verification_reason": [],
    }

    if verification == "Verified":
        account["verification_evidence"] = {
            "source": f"{platform} API",
            "id": index + 1000,
        }
        if metadata:
            account["verification_evidence"].update({
                "display_name": "Same Person",
                "avatar_url": "https://images.example/avatar.jpg",
                "bio": "Consistent profile biography",
            })

    if identity_linked:
        account["identity_linked"] = True

    return score_account(account)


class UsernameConfidenceRedesignTests(unittest.TestCase):
    def test_four_verified_from_thirty_eight_is_moderate(self):
        accounts = [make_account(index) for index in range(4)]
        accounts.extend(
            make_account(
                index + 10,
                verification="Needs Review",
                tools=["Sherlock"],
            )
            for index in range(6)
        )
        accounts.extend(
            make_account(
                index + 20,
                verification="False Positive",
                tools=["Sherlock"],
            )
            for index in range(28)
        )

        result = calculate_username_confidence(accounts)

        self.assertGreaterEqual(result["score"], 45)
        self.assertLessEqual(result["score"], 64)
        self.assertEqual(result["level"], "Moderate")
        self.assertEqual(result["breakdown"]["total_candidates"], 38)
        self.assertEqual(result["breakdown"]["directly_verified_accounts"], 4)
        self.assertEqual(result["breakdown"]["rejected_accounts"], 28)
        self.assertEqual(result["breakdown"]["need_review_accounts"], 6)

    def test_rejected_accounts_reduce_confidence(self):
        verified = [make_account(index) for index in range(4)]
        clean_score = calculate_username_confidence(verified)["score"]
        noisy_score = calculate_username_confidence(
            verified
            + [
                make_account(
                    index + 20,
                    verification="False Positive",
                    tools=["Sherlock"],
                )
                for index in range(20)
            ]
        )["score"]

        self.assertLess(noisy_score, clean_score)

    def test_need_review_accounts_reduce_confidence(self):
        verified = [make_account(index) for index in range(4)]
        clean_score = calculate_username_confidence(verified)["score"]
        uncertain_score = calculate_username_confidence(
            verified
            + [
                make_account(
                    index + 20,
                    verification="Needs Review",
                    tools=["Sherlock"],
                )
                for index in range(10)
            ]
        )["score"]

        self.assertLess(uncertain_score, clean_score)

    def test_false_high_value_matches_receive_no_breadth_credit(self):
        accounts = [
            make_account(
                index,
                verification="False Positive",
                platform=platform,
            )
            for index, platform in enumerate(HIGH_VALUE_PLATFORMS)
        ]

        result = calculate_username_confidence(accounts)

        self.assertEqual(result["breakdown"]["high_value_platforms"], [])
        self.assertEqual(result["breakdown"]["high_value_breadth_bonus"], 0)

    def test_enumerator_agreement_alone_cannot_create_high_confidence(self):
        accounts = [
            make_account(
                index,
                verification="Needs Review",
                tools=[
                    "Sherlock",
                    "Blackbird",
                    "Maigret",
                    "WhatsMyName",
                    "Social Analyzer",
                ],
            )
            for index in range(8)
        ]

        result = calculate_username_confidence(accounts)

        self.assertLessEqual(result["score"], 44)
        self.assertEqual(result["breakdown"]["directly_verified_accounts"], 0)
        self.assertEqual(result["breakdown"]["high_value_platforms"], [])

    def test_username_text_on_page_is_not_direct_verification(self):
        account = score_account({
            "website": "Instagram",
            "url": "https://instagram.com/target",
            "username": "target",
            "tools": ["Sherlock", "Blackbird"],
            "verification": "Needs Review",
            "verification_reason": [
                "Username appears in page content; platform verification required."
            ],
        })

        self.assertFalse(account["confidence_breakdown"]["direct_evidence"])
        self.assertEqual(
            account["confidence_breakdown"]["direct_page_evidence_bonus"],
            0,
        )
        self.assertEqual(account["status"], "Needs Review")

    def test_strong_identity_linkage_can_reach_very_strong(self):
        accounts = [
            make_account(
                index,
                tools=["Sherlock", "Blackbird", "WhatsMyName"],
                identity_linked=(index == 0),
                metadata=True,
            )
            for index in range(5)
        ]
        accounts.append(
            make_account(
                20,
                verification="Needs Review",
                tools=["Sherlock"],
            )
        )

        result = calculate_username_confidence(accounts)

        self.assertGreaterEqual(result["score"], 80)
        self.assertLessEqual(result["score"], 89)
        self.assertEqual(result["level"], "Very Strong")


if __name__ == "__main__":
    unittest.main()
