#!/usr/bin/python3.6
from dcsexp import string_of_dcsexp
from sexpdata import String, Symbol
import unittest


class Tests(unittest.TestCase):
    def test_nil(self):
        self.assertEqual(string_of_dcsexp([]), "Z0:")

    def test_one_element_list(self):
        self.assertEqual(string_of_dcsexp([5]), ".N1:5Z0:")

    def test_multi_element_list(self):
        self.assertEqual(
            string_of_dcsexp([1, 2, Symbol("foo")]), ".N1:1.N1:2.Y3:fooZ0:"
        )

    def test_empty_symbol(self):
        self.assertEqual(string_of_dcsexp(Symbol("")), "Y0:")

    def test_symbol(self):
        self.assertEqual(string_of_dcsexp(Symbol("foo")), "Y3:foo")

    def test_positive_int(self):
        self.assertEqual(string_of_dcsexp(5), "N1:5")

    def test_negative_int(self):
        self.assertEqual(string_of_dcsexp(-5), "N2:-5")

    def test_true(self):
        self.assertEqual(string_of_dcsexp(True), "B1:t")

    def test_false(self):
        self.assertEqual(string_of_dcsexp(False), "B1:f")

    def test_string(self):
        self.assertEqual(string_of_dcsexp(String("foo")), "S3:foo")


if __name__ == "__main__":
    unittest.main()
