"""
Unit tests for SpecterGraph Subdomain Takeover Analyzer.
"""

import unittest
from spectergraph.core.models import RiskLevel
from spectergraph.engine.takeover import TakeoverAnalyzer


class TestTakeoverAnalyzer(unittest.TestCase):

    def setUp(self):
        self.analyzer = TakeoverAnalyzer()

    def test_detect_aws_s3_takeover(self):
        subdomain = "assets.target.com"
        cname = "mybucket.s3.amazonaws.com"
        body = "<?xml version='1.0'?><Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"

        finding = self.analyzer.analyze(subdomain, cname, body)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.provider, "Amazon S3")
        self.assertEqual(finding.severity, RiskLevel.HIGH)
        self.assertIn("The specified bucket does not exist", finding.evidence)

    def test_detect_github_pages_takeover(self):
        subdomain = "docs.target.com"
        cname = "target-docs.github.io"
        body = "<html><body>404 There isn't a GitHub Pages site here.</body></html>"

        finding = self.analyzer.analyze(subdomain, cname, body)
        self.assertIsNotNone(finding)
        self.assertEqual(finding.provider, "GitHub Pages")
        self.assertEqual(finding.severity, RiskLevel.HIGH)

    def test_ignore_safe_cname(self):
        subdomain = "mail.target.com"
        cname = "mail.google.com"
        body = "Google Workspace Login"

        finding = self.analyzer.analyze(subdomain, cname, body)
        self.assertIsNone(finding)


if __name__ == "__main__":
    unittest.main()
