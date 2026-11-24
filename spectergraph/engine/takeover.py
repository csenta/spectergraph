"""
Subdomain Takeover Analyzer for SpecterGraph.
Correlates dangling CNAME records and HTTP response bodies against cloud provider fingerprints.
"""

import os
import re
import yaml
from spectergraph.core.models import TakeoverFinding, RiskLevel


class TakeoverAnalyzer:
    def __init__(self, fingerprints_path: str | None = None):
        self.providers: list[dict] = []
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        default_fp = os.path.join(base_dir, "config", "fingerprints.yaml")
        path = fingerprints_path or default_fp
        self._load_fingerprints(path)

    def _load_fingerprints(self, path: str):
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
                self.providers = data.get("providers", [])

    def analyze(
        self,
        subdomain: str,
        cname: str | None,
        http_body: str | None,
        http_status: int = 0,
    ) -> TakeoverFinding | None:
        if not cname:
            return None

        cname_clean = cname.lower().rstrip(".")
        body_clean = http_body or ""

        for prov in self.providers:
            name = prov.get("name", "Unknown Cloud Provider")
            cname_pats = prov.get("cname_patterns", [])
            resp_pats = prov.get("response_patterns", [])
            sev_str = prov.get("severity", "High").upper()
            severity = getattr(RiskLevel, sev_str, RiskLevel.HIGH)

            # Check if CNAME matches provider pattern
            cname_match = any(re.search(pat, cname_clean, re.IGNORECASE) for pat in cname_pats)
            if not cname_match:
                continue

            # Check if response matches unclaimed/missing resource pattern
            for rpat in resp_pats:
                if re.search(rpat, body_clean, re.IGNORECASE):
                    return TakeoverFinding(
                        subdomain=subdomain,
                        cname=cname,
                        provider=name,
                        severity=severity,
                        evidence=f"CNAME '{cname}' matches {name} and response contains unclaimed marker: '{rpat}'.",
                    )

        return None
