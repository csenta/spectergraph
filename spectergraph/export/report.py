"""
Report and JSON export modules for SpecterGraph.
"""

import json
from spectergraph.core.graph import PropertyGraph
from spectergraph.core.models import TakeoverFinding, ExposureFinding


class ReportGenerator:

    @staticmethod
    def generate_markdown(
        root_domain: str,
        graph: PropertyGraph,
        takeovers: list[TakeoverFinding],
        exposures: list[ExposureFinding],
    ) -> str:
        summary = graph.get_summary()

        lines = [
            f"# SpecterGraph Attack Surface & Exposure Report",
            f"**Target Root Domain**: `{root_domain}`",
            f"**Total Discovered Nodes**: {summary['total_nodes']}",
            f"**Infrastructure Relationships**: {summary['total_edges']}",
            "",
            "## Risk Summary",
            f"- **Critical Vulnerabilities**: `{summary['by_risk'].get('CRITICAL', 0)}`",
            f"- **High Severity Risks**: `{summary['by_risk'].get('HIGH', 0)}`",
            f"- **Medium / Low Exposures**: `{summary['by_risk'].get('MEDIUM', 0) + summary['by_risk'].get('LOW', 0)}`",
            "",
            "---",
            "",
        ]

        # 1. Subdomain Takeover Findings
        lines.append("## 🚨 Subdomain Takeover Vulnerabilities")
        if not takeovers:
            lines.append("No dangling CNAME records or subdomain takeovers detected.")
        else:
            for i, t in enumerate(takeovers, 1):
                lines.extend([
                    f"### {i}. [{t.severity.value}] {t.subdomain} (Provider: {t.provider})",
                    f"- **Dangling CNAME**: `{t.cname}`",
                    f"- **Evidence**: {t.evidence}",
                    f"- **Remediation**: Remove the dangling DNS CNAME record or claim the orphaned cloud asset immediately.",
                    "",
                ])

        lines.extend(["", "---", "", "## ⚠️ Sensitive Endpoint & Data Exposures"])
        if not exposures:
            lines.append("No sensitive paths (.git, .env, API docs) exposed on scanned endpoints.")
        else:
            for i, e in enumerate(exposures, 1):
                lines.extend([
                    f"### {i}. [{e.severity.value}] {e.url} (Status: {e.status_code})",
                    f"- **Exposed Path**: `{e.path}`",
                    f"- **Snippet Proof**: `{e.content_snippet}`",
                    f"- **Remediation**: Restrict web server access to dotfiles and internal endpoints via reverse proxy rules.",
                    "",
                ])

        return "\n".join(lines)

    @staticmethod
    def export_json(graph: PropertyGraph) -> str:
        return json.dumps(graph.to_dict(), indent=2)
