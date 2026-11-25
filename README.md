# SpecterGraph

> **Status:** prototype. A personal security-research project, not a production product. Expect rough edges; issues and pull requests are welcome.

**Autonomous Attack Surface Management & Threat Exposure Knowledge Graph Platform.**

[![CI](https://github.com/csenta/spectergraph/actions/workflows/ci.yml/badge.svg)](https://github.com/csenta/spectergraph/actions)
[![Python: 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

SpecterGraph solves the "flat recon list problem" by mapping multi-cloud assets, DNS relationships, and sensitive exposures into an interactive **Relational Property Graph** ($G = (V, E)$). 

It autonomously detects **dangling CNAME subdomain takeovers** across 15+ cloud providers (AWS S3, GitHub Pages, Azure, Heroku, Shopify, Zendesk) and unearths sensitive exposure vectors (`.git/HEAD`, `.env`, OpenAPI documentation, actuator endpoints).

---

## Key Capabilities

* 🕸️ **Relational Property Graph**: Correlates Root Domains $\to$ Subdomains $\to$ CNAME Aliases $\to$ IP Addresses $\to$ Exposures.
* ☁️ **Cloud Subdomain Takeover Engine**: Pattern-matches CNAME aliases and HTTP response signatures to detect hijackable cloud assets (AWS, Azure, Heroku, Fastly, GitHub).
* 🔍 **Sensitive Endpoint Prober**: Asynchronously detects exposed source code (`/.git/HEAD`), secrets (`/.env`), Spring Boot endpoints (`/actuator/health`), and Prometheus metrics (`/metrics`).
* 📊 **Interactive HTML Graph Visualizer**: Generates an offline, standalone HTML5 Canvas force-directed graph with zero external dependencies.
* 📁 **Multi-Format Export**: Generates SIEM-ready JSON property graphs and Markdown executive summary reports.

---

## Quick Start

### 1. Installation
```bash
git clone https://github.com/csenta/spectergraph.git
cd spectergraph
pip install -r requirements.txt
```

### 2. Run a Surface Scan
```bash
# Scan a domain and export interactive graph & report:
python3 -m spectergraph.cli \
  -d example.com \
  -s dev.example.com,api.example.com,docs.example.com \
  --out-html attack_graph.html \
  --out-md report.md \
  --out-json graph.json
```

### 3. Scan from a Subdomain Wordlist
```bash
python3 -m spectergraph.cli -d target.com -f subdomains.txt --out-html target_graph.html
```

---

## Architecture

```
Target Domain & Subdomain Seeds
              │
              ▼
    [Async DNS Resolver] ──► A Records & CNAMEs
              │
              ├──► [Cloud Takeover Analyzer] (AWS S3, GitHub, Azure, Heroku)
              │
              └──► [HTTP Exposure Prober] (.git, .env, API Docs)
              │
              ▼
    [In-Memory Property Graph]
              │
              ├──► Interactive HTML5 Canvas Graph (Offline SVG/Canvas)
              ├──► SIEM / CI/CD JSON Graph Specification
              └──► Executive Summary Markdown Report
```

For detailed architectural specifications, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Documentation Index

- [ARCHITECTURE.md](ARCHITECTURE.md) — Architectural design, entity relationships, and takeover mechanics.
- [ROADMAP.md](ROADMAP.md) — Future development phases and feature roadmap.
- [TASKS.md](TASKS.md) — Implementation task checklist and verification matrix.
- [API.md](API.md) — JSON graph schema and CLI command reference.
- [SECURITY.md](SECURITY.md) — Responsible usage, safe probing guidelines, and threat model.
- [CONTRIBUTING.md](CONTRIBUTING.md) — Setup and contribution instructions.

## License

MIT. See [LICENSE](LICENSE).
