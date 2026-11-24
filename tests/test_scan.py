"""
Integration test for SpecterScanner attack surface graph construction.
"""

import unittest
from spectergraph.core.models import NodeType, RiskLevel
from spectergraph.engine.scanner import SpecterScanner
from spectergraph.engine.takeover import TakeoverAnalyzer
from spectergraph.engine.prober import ExposureProber


class TestSpecterScanner(unittest.IsolatedAsyncioTestCase):

    async def test_full_graph_construction(self):
        # Mock prober to avoid real network calls
        async def mock_http(method: str, url: str):
            if "admin" in url and url.endswith("/.git/HEAD"):
                return 200, "ref: refs/heads/main"
            return 404, "Not Found"

        prober = ExposureProber(http_client_func=mock_http)
        scanner = SpecterScanner(exposure_prober=prober)

        # Mock resolve_domain to simulate DNS records deterministically
        def mock_resolve(domain: str):
            if domain == "bucket.target.com":
                return ["52.216.1.1"], "my-dead-bucket.s3.amazonaws.com"
            elif domain == "admin.target.com":
                return ["104.21.2.2"], None
            return ["1.1.1.1"], None

        scanner.resolve_domain = mock_resolve

        graph = await scanner.scan_target(
            root_domain="target.com",
            subdomains=["bucket.target.com", "admin.target.com"],
            probe_endpoints=True,
            simulate_fetch_body="The specified bucket does not exist",
        )

        summary = graph.get_summary()
        self.assertGreaterEqual(summary["total_nodes"], 4)
        self.assertGreaterEqual(summary["total_edges"], 3)

        # Check that takeover risk node was created
        takeover_node = graph.get_node("takeover:bucket.target.com")
        self.assertIsNotNone(takeover_node)
        self.assertEqual(takeover_node.type, NodeType.TAKEOVER_RISK)

        # Check that exposure node was created
        exposure_node = graph.get_node("exp:admin.target.com/.git/HEAD")
        self.assertIsNotNone(exposure_node)
        self.assertEqual(exposure_node.type, NodeType.EXPOSURE)
        self.assertEqual(exposure_node.risk, RiskLevel.CRITICAL)


if __name__ == "__main__":
    unittest.main()
