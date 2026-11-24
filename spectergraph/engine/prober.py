"""
Sensitive Endpoint and Misconfiguration Prober for SpecterGraph.
"""

import asyncio
from typing import Callable, Any
from spectergraph.core.models import ExposureFinding, RiskLevel


class ExposureProber:

    TARGET_PATHS = [
        (
            "/.git/HEAD",
            "ref: refs/",
            RiskLevel.CRITICAL,
            "Exposed Git Repository metadata (.git/HEAD)",
        ),
        (
            "/.env",
            "DB_PASSWORD|SECRET|APP_KEY|AWS_",
            RiskLevel.CRITICAL,
            "Exposed Environment Variables (.env)",
        ),
        (
            "/swagger.json",
            "swagger|openapi",
            RiskLevel.LOW,
            "Exposed OpenAPI / Swagger Documentation",
        ),
        (
            "/actuator/health",
            "\"status\":\"UP\"|UP",
            RiskLevel.MEDIUM,
            "Exposed Spring Boot Actuator Health",
        ),
        (
            "/metrics",
            "# HELP|# TYPE",
            RiskLevel.MEDIUM,
            "Exposed Prometheus Metrics endpoint",
        ),
    ]

    def __init__(self, http_client_func: Callable | None = None):
        self.http_client_func = http_client_func

    async def probe_subdomain(
        self,
        subdomain: str,
        timeout: float = 5.0,
    ) -> list[ExposureFinding]:
        import re
        import httpx

        findings: list[ExposureFinding] = []
        base_url = f"https://{subdomain}"

        # If custom client provided (for testing or proxying)
        if self.http_client_func:
            for path, marker, severity, desc in self.TARGET_PATHS:
                url = f"{base_url}{path}"
                status, body = await self.http_client_func("GET", url)
                if status == 200 and re.search(marker, body, re.IGNORECASE):
                    findings.append(
                        ExposureFinding(
                            subdomain=subdomain,
                            path=path,
                            url=url,
                            status_code=status,
                            severity=severity,
                            content_snippet=body[:100].replace("\n", " "),
                        )
                    )
            return findings

        # Async HTTP scanning
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        async with httpx.AsyncClient(verify=False, timeout=timeout, limits=limits) as client:
            for path, marker, severity, desc in self.TARGET_PATHS:
                url = f"{base_url}{path}"
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and re.search(marker, resp.text, re.IGNORECASE):
                        findings.append(
                            ExposureFinding(
                                subdomain=subdomain,
                                path=path,
                                url=url,
                                status_code=resp.status_code,
                                severity=severity,
                                content_snippet=resp.text[:100].replace("\n", " "),
                            )
                        )
                except Exception:
                    continue

        return findings
