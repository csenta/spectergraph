"""
Unit tests for SpecterGraph PropertyGraph primitives.
"""

import unittest
from spectergraph.core.models import AssetNode, AssetEdge, NodeType, EdgeType, RiskLevel
from spectergraph.core.graph import PropertyGraph


class TestPropertyGraph(unittest.TestCase):

    def setUp(self):
        self.graph = PropertyGraph()

    def test_add_nodes_and_deduplication(self):
        node1 = AssetNode(id="corp.com", type=NodeType.ROOT_DOMAIN, label="corp.com", risk=RiskLevel.INFO)
        self.graph.add_node(node1)
        self.assertEqual(len(self.graph.nodes), 1)

        # Adding same node with higher risk should upgrade risk
        node1_risk = AssetNode(id="corp.com", type=NodeType.ROOT_DOMAIN, label="corp.com", risk=RiskLevel.HIGH)
        self.graph.add_node(node1_risk)
        self.assertEqual(len(self.graph.nodes), 1)
        self.assertEqual(self.graph.get_node("corp.com").risk, RiskLevel.HIGH)

    def test_add_edges_and_traversal(self):
        root = AssetNode(id="corp.com", type=NodeType.ROOT_DOMAIN, label="corp.com")
        sub = AssetNode(id="api.corp.com", type=NodeType.SUBDOMAIN, label="api.corp.com")
        self.graph.add_node(root)
        self.graph.add_node(sub)

        edge = AssetEdge(source_id="corp.com", target_id="api.corp.com", relationship=EdgeType.CONTAINS)
        self.graph.add_edge(edge)
        self.assertEqual(len(self.graph.edges), 1)

        # Duplicate edge should be ignored
        self.graph.add_edge(edge)
        self.assertEqual(len(self.graph.edges), 1)

        neighbors = self.graph.get_neighbors("corp.com")
        self.assertIn("api.corp.com", neighbors)

    def test_json_export(self):
        root = AssetNode(id="test.com", type=NodeType.ROOT_DOMAIN, label="test.com")
        self.graph.add_node(root)
        data = self.graph.to_dict()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)
        self.assertEqual(len(data["nodes"]), 1)


if __name__ == "__main__":
    unittest.main()
