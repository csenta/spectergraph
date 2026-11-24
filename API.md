# SpecterGraph Data Model & CLI Reference

## 1. Property Graph JSON Schema

SpecterGraph exports relational property graphs in standard JSON format:

```json
{
  "nodes": [
    {
      "id": "target.com",
      "type": "ROOT_DOMAIN",
      "label": "target.com",
      "risk": "INFO",
      "attributes": {}
    },
    {
      "id": "dev.target.com",
      "type": "SUBDOMAIN",
      "label": "dev.target.com",
      "risk": "CRITICAL",
      "attributes": {}
    },
    {
      "id": "takeover:dev.target.com",
      "type": "TAKEOVER_RISK",
      "label": "Takeover (Amazon S3)",
      "risk": "HIGH",
      "attributes": {
        "evidence": "CNAME 'bucket.s3.amazonaws.com' matches Amazon S3 and response contains NoSuchBucket."
      }
    }
  ],
  "edges": [
    {
      "source": "target.com",
      "target": "dev.target.com",
      "relationship": "CONTAINS",
      "attributes": {}
    },
    {
      "source": "dev.target.com",
      "target": "takeover:dev.target.com",
      "relationship": "VULNERABLE_TO",
      "attributes": {}
    }
  ]
}
```

---

## 2. CLI Command Reference

```bash
spectergraph -d <domain> [options]

Options:
  -d, --domain DOMAIN       Target root domain (required)
  -s, --subdomains SUBS     Comma-separated subdomains list
  -f, --file PATH           Path to line-delimited subdomains file
  --no-probe                Skip HTTP sensitive path probing (.git, .env)
  --out-html PATH           Path to save interactive HTML visualization
  --out-md PATH             Path to save Markdown audit report
  --out-json PATH           Path to save raw JSON property graph
```
