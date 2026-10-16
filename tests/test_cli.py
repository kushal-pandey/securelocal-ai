from __future__ import annotations

import unittest

from scanner.__main__ import _terminal_safe


class CliTests(unittest.TestCase):
    def test_terminal_control_characters_are_escaped(self):
        self.assertEqual(_terminal_safe("safe\x1b[31mred\x07"), r"safe\x1b[31mred\x07")


if __name__ == "__main__":
    unittest.main()
