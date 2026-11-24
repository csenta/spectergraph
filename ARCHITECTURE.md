# SpecterGraph System Architecture

## 1. Executive Overview

**SpecterGraph** is an autonomous Attack Surface Management (ASM) and Threat Exposure Knowledge Graph platform. 

It solves the "flat list problem" in security reconnaissance: instead of dumping disconnected text files of subdomains and IP addresses, SpecterGraph maps all discovered infrastructure into a **relational property graph** ($G = (V, E)$), correlating domain names, cloud CNAME aliases, exposed endpoints, and misconfigurations into clear, actionable attack paths.

---

## 2. End-to-End System Architecture

```mermaid
flowchart TD
    Input["Target Domains / Seeds / Subdomain List"] --> Dispatcher["Recon & Probing Dispatcher<br/>(AsyncIO Concurrency Controller)"]

    subgraph Discovery Engines
        Dispatcher --> DNS["Asynchronous DNS Resolver<br/>(A, AAAA, CNAME, TXT)"]
        Dispatcher --> Prober["HTTP Exposure Probe<br/>(.git, .env, API Docs, Admin)"]
        Dispatcher --> Takeover["Cloud Takeover Analyzer<br/>(AWS, GitHub, Azure, Heroku)"]
    end

    subgraph Knowledge Graph Engine
        DNS --> Builder["Graph Model Builder"]
        Prober --> Builder
        Takeover --> Builder
        Builder --> GraphStore["In-Memory Property Graph<br/>(Nodes & Directed Edges)"]
    end

    subgraph Analysis & Export
        GraphStore --> RiskScorer["Attack Path & Risk Scoring"]
        RiskScorer --> HTMLGen["Interactive HTML Graph Visualizer<br/>(Standalone SVG/Canvas)"]
        RiskScorer --> JSONExporter["JSON Graph Spec (SIEM/CI)"]
        RiskScorer --> MarkdownRep["Executive Summary Report"]
    end
```

---

## 3. Entity-Relationship Graph Model

```mermaid
erDiagram
    ROOT_DOMAIN ||--o{ SUBDOMAIN : contains
    SUBDOMAIN ||--o{ CNAME_RECORD : alias_of
    SUBDOMAIN ||--o{ IP_ADDRESS : resolves_to
    SUBDOMAIN ||--o{ EXPOSURE : exposes
    CNAME_RECORD ||--o{ CLOUD_PROVIDER : hosted_on
    CNAME_RECORD ||--o{ TAKEOVER_RISK : triggers
    EXPOSURE ||--o{ VULNERABILITY : indicates

    SUBDOMAIN {
        string fqdn
        int http_status
        string title
        string web_server
    }
    IP_ADDRESS {
        string ip
        string asn
        string cloud_region
    }
    EXPOSURE {
        string path
        int status_code
        string proof_snippet
    }
    TAKEOVER_RISK {
        string provider
        string dangling_cname
        string severity
    }
```

---

## 4. Subdomain Takeover Detection Mechanics

When a service is deleted (e.g. an Amazon S3 bucket or GitHub Pages site), DNS records often linger pointing to the cloud provider's shared domain name:
1. `docs.target.com` $\to$ CNAME `target-docs.s3.amazonaws.com`
2. If `target-docs` S3 bucket has been deleted, an attacker can register the bucket `target-docs` in any AWS account and achieve complete domain hijacking.
3. SpecterGraph performs fingerprint pattern matching against HTTP response bodies and DNS NXDOMAIN statuses across 15+ major cloud providers.
