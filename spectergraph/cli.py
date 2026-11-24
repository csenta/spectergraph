#!/usr/bin/env python3
"""
CLI entry point for SpecterGraph: Autonomous Attack Surface & Threat Exposure Graph Platform.
"""

import argparse
import asyncio
import os
import sys
from spectergraph.engine.scanner import SpecterScanner
from spectergraph.export.html import generate_html_graph
from spectergraph.export.report import ReportGenerator


def main():
    parser = argparse.ArgumentParser(
        description="SpecterGraph: Autonomous Attack Surface & Threat Exposure Graph Platform"
    )
    parser.add_argument("-d", "--domain", required=True, help="Target root domain (e.g. example.com)")
    parser.add_argument(
        "-s", "--subdomains", help="Comma-separated subdomains list (e.g. api.example.com,dev.example.com)"
    )
    parser.add_argument(
        "-f", "--file", help="Path to file containing subdomains list (one per line)"
    )
    parser.add_argument(
        "--no-probe", action="store_true", help="Skip HTTP sensitive endpoint probing (.git, .env)"
    )
    parser.add_argument("--out-html", help="Path to save interactive HTML visualization")
    parser.add_argument("--out-md", help="Path to save Markdown audit report")
    parser.add_argument("--out-json", help="Path to save raw JSON property graph")

    args = parser.parse_args()

    subs = []
    if args.subdomains:
        subs.extend([s.strip() for s in args.subdomains.split(",") if s.strip()])

    if args.file and os.path.isfile(args.file):
        with open(args.file, "r", encoding="utf-8") as f:
            subs.extend([line.strip() for line in f if line.strip()])

    if not subs:
        # Default to probing root and common standard targets
        subs = [
            args.domain,
            f"www.{args.domain}",
            f"api.{args.domain}",
            f"dev.{args.domain}",
        ]

    scanner = SpecterScanner()
    print(f"[*] Starting SpecterGraph reconnaissance on '{args.domain}' ({len(subs)} targets)...")

    graph = asyncio.run(
        scanner.scan_target(
            root_domain=args.domain,
            subdomains=subs,
            probe_endpoints=not args.no_probe,
        )
    )

    summary = graph.get_summary()
    print(f"[+] Scan completed! Mapped {summary['total_nodes']} nodes and {summary['total_edges']} relationships.")
    print(f"    - Subdomain Takeovers: {len(scanner.takeover_findings)}")
    print(f"    - Sensitive Exposures: {len(scanner.exposure_findings)}")

    # Exports
    if args.out_html:
        html = generate_html_graph(graph, title=args.domain)
        with open(args.out_html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] Saved interactive HTML graph to: {args.out_html}")

    if args.out_json:
        raw_json = ReportGenerator.export_json(graph)
        with open(args.out_json, "w", encoding="utf-8") as f:
            f.write(raw_json)
        print(f"[+] Saved JSON attack graph to: {args.out_json}")

    report_md = ReportGenerator.generate_markdown(
        root_domain=args.domain,
        graph=graph,
        takeovers=scanner.takeover_findings,
        exposures=scanner.exposure_findings,
    )

    if args.out_md:
        with open(args.out_md, "w", encoding="utf-8") as f:
            f.write(report_md)
        print(f"[+] Saved Markdown report to: {args.out_md}")
    else:
        print("\n" + report_md)


if __name__ == "__main__":
    main()
