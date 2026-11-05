"""Temporary negative control for PR #128: this test fails on purpose. Never merge."""
import unittest


class NegativeControl(unittest.TestCase):
    def test_deliberately_fails(self):
        self.fail("deliberate negative control: the qc-unit job must go red")
