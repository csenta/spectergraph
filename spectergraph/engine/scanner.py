"""
SpecterGraph Orchestrator and Recon Scanner.
Executes DNS resolution, takeover verification, and sensitive path probing to build the PropertyGraph.
"""

import asyncio
import socket
from spectergraph.core.models import (
    AssetNode,
    AssetEdge,
    NodeType,
    EdgeType,
    RiskLevel,
    TakeoverFinding,
    ExposureFinding,
)
from spectergraph.core.graph import PropertyGraph
from spectergraph.engine.takeover import TakeoverAnalyzer
from spectergraph.engine.prober import ExposureProber


class SpecterScanner:
    def __init__(
        self,
        takeover_analyzer: TakeoverAnalyzer | None = None,
        exposure_prober: ExposureProber | None = None,
    ):
        self.takeover = takeover_analyzer or TakeoverAnalyzer()
        self.prober = exposure_prober or ExposureProber()
        self.graph = PropertyGraph()
        self.takeover_findings: list[TakeoverFinding] = []
        self.exposure_findings: list[ExposureFinding] = []

    def resolve_domain(self, domain: str) -> tuple[list[str], str | None]:
        """
        Resolves domain to A records and CNAME alias.
        """
        ips = []
        cname = None
        try:
            # Check CNAME
            cname = socket.getfqdn(domain)
            if cname == domain:
                cname = None
        except Exception:
            pass

        try:
            # Resolve A records
            _, _, ip_list = socket.gethostbyname_ex(domain)
            ips = ip_list
        except Exception:
            pass

        return ips, cname

    async def scan_target(
        self,
        root_domain: str,
        subdomains: list[str],
        probe_endpoints: bool = True,
        simulate_fetch_body: str | None = None,
    ) -> PropertyGraph:
        """
        Performs full attack surface graph construction across subdomains.
        """
        # 1. Add Root Domain Node
        root_node = AssetNode(
            id=root_domain,
            type=NodeType.ROOT_DOMAIN,
            label=root_domain,
            risk=RiskLevel.INFO,
        )
        self.graph.add_node(root_node)

        for sub in subdomains:
            # 2. Add Subdomain Node
            sub_node = AssetNode(
                id=sub,
                type=NodeType.SUBDOMAIN,
                label=sub,
                risk=RiskLevel.INFO,
            )
            self.graph.add_node(sub_node)
            self.graph.add_edge(
                AssetEdge(
                    source_id=root_domain,
                    target_id=sub,
                    relationship=EdgeType.CONTAINS,
                )
            )

            # 3. DNS Resolution
            ips, cname = self.resolve_domain(sub)

            # Add CNAME and Check Takeover
            if cname:
                cname_node = AssetNode(
                    id=cname,
                    type=NodeType.CNAME_RECORD,
                    label=cname,
                    risk=RiskLevel.INFO,
                )
                self.graph.add_node(cname_node)
                self.graph.add_edge(
                    AssetEdge(
                        source_id=sub,
                        target_id=cname,
                        relationship=EdgeType.ALIAS_OF,
                    )
                )

                # Check Subdomain Takeover
                takeover_finding = self.takeover.analyze(
                    subdomain=sub,
                    cname=cname,
                    http_body=simulate_fetch_body,
                )
                if takeover_finding:
                    self.takeover_findings.append(takeover_finding)
                    risk_id = f"takeover:{sub}"
                    risk_node = AssetNode(
                        id=risk_id,
                        type=NodeType.TAKEOVER_RISK,
                        label=f"Takeover ({takeover_finding.provider})",
                        risk=takeover_finding.severity,
                        attributes={"evidence": takeover_finding.evidence},
                    )
                    self.graph.add_node(risk_node)
                    self.graph.add_edge(
                        AssetEdge(
                            source_id=sub,
                            target_id=risk_id,
                            relationship=EdgeType.VULNERABLE_TO,
                        )
                    )

            # Add IP Nodes
            for ip in ips:
                ip_node = AssetNode(
                    id=ip,
                    type=NodeType.IP_ADDRESS,
                    label=ip,
                    risk=RiskLevel.INFO,
                )
                self.graph.add_node(ip_node)
                self.graph.add_edge(
                    AssetEdge(
                        source_id=sub,
                        target_id=ip,
                        relationship=EdgeType.RESOLVES_TO,
                    )
                )

            # 4. Probe Sensitive Endpoints
            if probe_endpoints:
                exp_findings = await self.prober.probe_subdomain(sub)
                for exp in exp_findings:
                    self.exposure_findings.append(exp)
                    exp_id = f"exp:{sub}{exp.path}"
                    exp_node = AssetNode(
                        id=exp_id,
                        type=NodeType.EXPOSURE,
                        label=f"{exp.path} ({exp.status_code})",
                        risk=exp.severity,
                        attributes={
                            "url": exp.url,
                            "snippet": exp.content_snippet,
                        },
                    )
                    self.graph.add_node(exp_node)
                    self.graph.add_edge(
                        AssetEdge(
                            source_id=sub,
                            target_id=exp_id,
                            relationship=EdgeType.EXPOSES,
                        )
                    )

        return self.graph
