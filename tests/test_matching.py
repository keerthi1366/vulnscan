import unittest

from vulnscan.matching import VersionBound, VersionRange, match_version, nvd_range


class VersionMatchingTests(unittest.TestCase):
    def test_inclusive_bounds_match(self):
        span = VersionRange(VersionBound("1.2", True), VersionBound("2.0", True))
        self.assertEqual(match_version("1.2", span), "potential_match")
        self.assertEqual(match_version("2.0", span), "potential_match")

    def test_exclusive_bounds_do_not_match_at_boundary(self):
        span = VersionRange(VersionBound("1.2", False), VersionBound("2.0", False))
        self.assertEqual(match_version("1.2", span), "not_affected")
        self.assertEqual(match_version("2.0", span), "not_affected")

    def test_inside_and_outside(self):
        span = VersionRange(VersionBound("1.2", True), VersionBound("2.0", False))
        self.assertEqual(match_version("1.9", span), "potential_match")
        self.assertEqual(match_version("2.1", span), "not_affected")

    def test_unsupported_version_syntax_is_uncertain(self):
        span = VersionRange(end=VersionBound("2.0", True))
        self.assertEqual(match_version("1.2-ubuntu1", span), "uncertain")

    def test_unbounded_range_is_uncertain(self):
        self.assertEqual(match_version("1.2", VersionRange()), "uncertain")

    def test_nvd_inclusive_and_exclusive_bounds(self):
        inclusive = nvd_range({"criteria": "cpe:2.3:a:vendor:thing:*:*:*:*:*:*:*:*",
                               "versionStartIncluding": "1.0", "versionEndIncluding": "2.0"})
        exclusive = nvd_range({"criteria": "cpe:2.3:a:vendor:thing:*:*:*:*:*:*:*:*",
                               "versionStartExcluding": "1.0", "versionEndExcluding": "2.0"})
        self.assertEqual(match_version("1.0", inclusive), "potential_match")
        self.assertEqual(match_version("1.0", exclusive), "not_affected")
        self.assertEqual(match_version("2.0", exclusive), "not_affected")


if __name__ == "__main__":
    unittest.main()
