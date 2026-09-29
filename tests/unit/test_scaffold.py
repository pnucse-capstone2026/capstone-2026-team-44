from __future__ import annotations

import unittest

import vulnspider
from vulnspider import cli


class ScaffoldTests(unittest.TestCase):
    def test_package_exposes_version(self) -> None:
        self.assertEqual(vulnspider.__version__, "0.1.0")

    def test_cli_entrypoint_accepts_empty_args(self) -> None:
        self.assertEqual(cli.main([]), 0)


if __name__ == "__main__":
    unittest.main()

