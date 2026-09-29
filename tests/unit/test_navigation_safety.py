from __future__ import annotations

import unittest

from vulnspider.discovery.navigation_safety import (
    authentication_state_change_token,
    automatic_navigation_within_root_path,
)


class NavigationSafetyTests(unittest.TestCase):
    def test_clear_authentication_termination_segments_are_suppressed(self) -> None:
        cases = {
            "http://example.test/logout.php": "logout",
            "http://example.test/auth/signout": "signout",
            "http://example.test/LOGOFF": "logoff",
            "http://example.test/auth/LOGOUT.HTML?next=/": "logout",
            "http://example.test/auth/%73ignout": "signout",
            "http://example.test/account?action=logout": "logout",
            "http://example.test/account?do=SIGNOUT.PHP": "signout",
            "http://example.test/account?logoff=1": "logoff",
        }

        for url, expected in cases.items():
            with self.subTest(url=url):
                self.assertEqual(authentication_state_change_token(url), expected)

    def test_substrings_and_non_path_values_are_not_suppressed(self) -> None:
        for url in (
            "http://example.test/docs/logout-behavior",
            "http://example.test/logout-history.html",
            "http://example.test/account?next=/logout.php",
            "http://example.test/account#logout",
        ):
            with self.subTest(url=url):
                self.assertIsNone(authentication_state_change_token(url))

    def test_classification_is_deterministic(self) -> None:
        url = "http://example.test/auth/SignOut.PHP?nonce=ignored"
        self.assertEqual(
            [authentication_state_change_token(url) for _ in range(3)],
            ["signout", "signout", "signout"],
        )

    def test_directory_root_bounds_implicit_navigation_by_path_segment(self) -> None:
        root = "http://example.test/vulnerabilities/sqli/"

        self.assertTrue(
            automatic_navigation_within_root_path(
                root,
                "http://example.test/vulnerabilities/sqli/help",
            )
        )
        self.assertFalse(
            automatic_navigation_within_root_path(
                root,
                "http://example.test/vulnerabilities/sqli-other",
            )
        )
        self.assertFalse(
            automatic_navigation_within_root_path(
                root,
                "http://example.test/about.php",
            )
        )

    def test_encoded_traversal_and_separators_fail_path_scope_closed(self) -> None:
        root = "http://example.test/area/"
        for path in (
            "/area/%2e%2e/admin",
            "/area/%252e%252e/admin",
            "/area%2fadmin",
            "/area/%5cadmin",
            "/area/../admin",
        ):
            with self.subTest(path=path):
                self.assertFalse(
                    automatic_navigation_within_root_path(
                        root,
                        "http://example.test" + path,
                    )
                )

    def test_file_shaped_root_retains_origin_wide_path_behavior(self) -> None:
        self.assertTrue(
            automatic_navigation_within_root_path(
                "http://example.test/area/start",
                "http://example.test/account/profile",
            )
        )


if __name__ == "__main__":
    unittest.main()
