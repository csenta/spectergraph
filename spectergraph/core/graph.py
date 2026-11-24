"""
In-memory Property Graph Engine for SpecterGraph.
Maintains relational nodes and directed edges representing infrastructure assets and exposure paths.
"""

from spectergraph.core.models import AssetNode, AssetEdge, NodeType, RiskLevel


class PropertyGraph:
    def __init__(self):
        self.nodes: dict[str, AssetNode] = {}
        self.edges: list[AssetEdge] = []
        self._adj: dict[str, list[AssetEdge]] = {}

    def add_node(self, node: AssetNode) -> AssetNode:
        if node.id not in self.nodes:
            self.nodes[node.id] = node
            self._adj[node.id] = []
        else:
            # Upgrade risk level if higher risk is found
            current = self.nodes[node.id]
            if self._risk_weight(node.risk) > self._risk_weight(current.risk):
                current.risk = node.risk
            current.attributes.update(node.attributes)
        return self.nodes[node.id]

    def add_edge(self, edge: AssetEdge):
        # Ensure source and target are known
        if edge.source_id in self._adj:
            # Prevent exact duplicate edges
            exists = any(
                e.target_id == edge.target_id and e.relationship == edge.relationship
                for e in self._adj[edge.source_id]
            )
            if not exists:
                self.edges.append(edge)
                self._adj[edge.source_id].append(edge)

    def get_node(self, node_id: str) -> AssetNode | None:
        return self.nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> list[str]:
        return [e.target_id for e in self._adj.get(node_id, [])]

    @staticmethod
    def _risk_weight(risk: RiskLevel) -> int:
        order = {
            RiskLevel.INFO: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        return order.get(risk, 0)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type.value,
                    "label": n.label,
                    "risk": n.risk.value,
                    "attributes": n.attributes,
                }
                for n in self.nodes.values()
            ],
            "edges": [
                {
                    "source": e.source_id,
                    "target": e.target_id,
                    "relationship": e.relationship.value,
                    "attributes": e.attributes,
                }
                for e in self.edges
            ],
        }

    def get_summary(self) -> dict:
        counts_by_type = {}
        counts_by_risk = {}
        for n in self.nodes.values():
            counts_by_type[n.type.value] = counts_by_type.get(n.type.value, 0) + 1
            counts_by_risk[n.risk.value] = counts_by_risk.get(n.risk.value, 0) + 1

        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "by_type": counts_by_type,
            "by_risk": counts_by_risk,
        }
