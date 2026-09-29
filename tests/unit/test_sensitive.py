from __future__ import annotations

import unittest

from vulnspider.sensitive import contains_credential_material, credential_field_name


class SensitivePolicyTests(unittest.TestCase):
    def test_csrf_and_xsrf_security_token_names_are_sensitive(self) -> None:
        names = (
            "csrf",
            "xsrf",
            "csrf_token",
            "xsrf_token",
            "x-csrf-token",
            "x-xsrf-token",
            "X-CSRF-Token",
            "X-XSRF-Token",
        )

        for name in names:
            with self.subTest(name=name):
                self.assertTrue(credential_field_name(name))
                self.assertTrue(
                    contains_credential_material(((name, "security-token"),))
                )

    def test_generic_id_and_key_names_are_not_sensitive(self) -> None:
        for name in ("id", "product_id", "key", "keyboard", "monkey"):
            with self.subTest(name=name):
                self.assertFalse(credential_field_name(name))


if __name__ == "__main__":
    unittest.main()
