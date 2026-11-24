"""
Unit tests for SpecterGraph Exposure Prober.
"""

import unittest
from spectergraph.core.models import RiskLevel
from spectergraph.engine.prober import ExposureProber


class TestExposureProber(unittest.IsolatedAsyncioTestCase):

    async def test_detect_git_head_leak(self):
        async def mock_http(method: str, url: str):
            if url.endswith("/.git/HEAD"):
                return 200, "ref: refs/heads/main\n"
            return 404, "Not Found"

        prober = ExposureProber(http_client_func=mock_http)
        findings = await prober.probe_subdomain("dev.target.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "/.git/HEAD")
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    async def test_detect_env_file_leak(self):
        async def mock_http(method: str, url: str):
            if url.endswith("/.env"):
                return 200, "APP_ENV=production\nDB_PASSWORD=supersecret99\n"
            return 404, "Not Found"

        prober = ExposureProber(http_client_func=mock_http)
        findings = await prober.probe_subdomain("staging.target.com")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "/.env")
        self.assertEqual(findings[0].severity, RiskLevel.CRITICAL)

    async def test_safe_endpoint_no_exposures(self):
        async def mock_http(method: str, url: str):
            return 404, "Not Found"

        prober = ExposureProber(http_client_func=mock_http)
        findings = await prober.probe_subdomain("secure.target.com")
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
