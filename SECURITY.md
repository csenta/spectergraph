# Security Policy & Responsible Usage for SpecterGraph

## 1. Security Architecture & Controls

SpecterGraph is built for defensive visibility and authorized penetration testing:

- **Asynchronous Safe Probing**: Employs non-intrusive `GET` requests against public metadata paths (`.git/HEAD`, `.env`, OpenAPI docs). Never executes invasive state-changing verbs (`POST`, `PUT`, `DELETE`).
- **Rate-Limited Concurrent Connections**: Defaults to a safe connection semaphore to prevent accidental denial of service against target infrastructure.
- **Zero Ingestion of Untrusted Code**: Uses static regex matching and JSON parsing without dynamic code evaluation or unsanitized command construction.

---

## 2. Rules of Engagement & Permitted Use

- **Authorized Testing Only**: Use SpecterGraph exclusively against domains and infrastructure you own or have explicit authorization to test under a formal bug bounty / vulnerability disclosure program.
- **Dangling Resource Ownership**: When a subdomain takeover is identified, do not claim the orphaned asset for malicious purposes. Immediately report the vulnerability to the domain owner.

---

## 3. Reporting Security Issues

To report a vulnerability in SpecterGraph itself:
1. Contact the repository maintainer (`csenta`).
2. Provide details and reproduction steps.
