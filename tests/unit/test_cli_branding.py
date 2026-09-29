from __future__ import annotations

import unittest

from vulnspider.cli_branding import BannerCapabilities, ColorMode, render_banner


class CliBrandingTests(unittest.TestCase):
    def test_wide_truecolor_snapshot_has_suit_palette_and_wordmark(self) -> None:
        rendered = render_banner(
            BannerCapabilities(
                width=100,
                is_tty=True,
                color_mode=ColorMode.TRUECOLOR,
                unicode=True,
            )
        )

        self.assertIn("\x1b[38;2;30;90;230m", rendered)
        self.assertIn("\x1b[38;2;245;35;45m", rendered)
        self.assertIn("TEAM SPIDER-MAN", rendered)
        self.assertIn("LOCAL-FIRST · EVIDENCE-DRIVEN", rendered)
        self.assertEqual(len(rendered.splitlines()), 13)

    def test_wide_no_color_snapshot_is_stable(self) -> None:
        rendered = render_banner(
            BannerCapabilities(
                width=100,
                is_tty=True,
                color_mode=ColorMode.NONE,
                unicode=False,
            )
        )

        self.assertEqual(
            rendered.splitlines()[0],
            "     /    \\",
        )
        self.assertEqual(
            rendered.splitlines()[4],
            "     \\(@@)/      #   # #   # #     #   #  #### ####  ##### ####  ##### ####",
        )
        self.assertEqual(
            rendered.splitlines()[-1],
            "LOCAL-FIRST | EVIDENCE-DRIVEN | AUTHORIZED TARGETS ONLY",
        )
        self.assertNotIn("\x1b[", rendered)
        self.assertTrue(rendered.isascii())

    def test_narrow_and_dumb_term_use_compact_fallbacks(self) -> None:
        unicode_rendered = render_banner(
            BannerCapabilities(
                width=40,
                is_tty=True,
                color_mode=ColorMode.ANSI16,
                unicode=True,
            )
        )
        ascii_rendered = render_banner(
            BannerCapabilities(
                width=100,
                is_tty=True,
                color_mode=ColorMode.ANSI16,
                unicode=False,
                term_dumb=True,
            )
        )

        self.assertEqual(unicode_rendered, "🕷 VULNSPIDER\n")
        self.assertEqual(ascii_rendered, "VULNSPIDER\n")
        self.assertNotIn("\x1b[", unicode_rendered + ascii_rendered)

    def test_redirected_or_hidden_banner_is_silent(self) -> None:
        for capabilities in (
            BannerCapabilities(100, False, ColorMode.NONE, True),
            BannerCapabilities(100, True, ColorMode.TRUECOLOR, True, hidden=True),
        ):
            with self.subTest(capabilities=capabilities):
                self.assertEqual(render_banner(capabilities), "")


if __name__ == "__main__":
    unittest.main()
