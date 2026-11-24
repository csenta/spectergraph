# SpecterGraph Engineering Roadmap

## Milestones

### Milestone 1: Core Graph Engine & Probing (v1.0 - Current)
- [x] Property Graph model (`Node`, `Edge`, `GraphStore`).
- [x] Asynchronous DNS resolution engine (A, CNAME).
- [x] Cloud provider takeover fingerprint database (AWS S3, GitHub, Azure, Heroku, Shopify, Zendesk, Fastly).
- [x] Sensitive exposure probe (`.git/HEAD`, `.env`, `/swagger.json`, `/metrics`, `/graphql`).
- [x] Standalone interactive HTML Graph generator.
- [x] JSON & Markdown export formats.
- [x] Comprehensive automated test suite with mock DNS/HTTP responders.
- [x] Dockerfile & CI/CD workflow.

### Milestone 2: Active Surface Expansion (v1.1)
- [ ] Integration with Certificate Transparency logs (crt.sh).
- [ ] TLS certificate expiry and weak cipher suite analyzer.
- [ ] Technology fingerprint correlation against CVE databases.

### Milestone 3: Distributed Multi-Tenant Scanning (v2.0)
- [ ] Distributed Celery/Redis worker cluster for enterprise-scale CIDR scanning.
- [ ] Neo4j / Cypher query export integration for deep enterprise asset querying.
