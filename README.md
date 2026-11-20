# Incident Radar

**Early warning for major security events: the next Log4Shell, as it breaks.**

Incident Radar watches authoritative sources every 15 minutes. It groups reports
about the same event into one incident, scores it with a transparent formula, and
pushes an alert when something big is happening. Every point of every score is
shown, so you can judge it yourself.

Part of [Rachel Coleman's portfolio](https://pakhet-portfolio.web.app).

## How it works

```
Cloud Scheduler (every 15 min)
        │
        ▼
Cloud Run Job: radar-collector ──► CISA KEV · NVD · GitHub Advisories · FIRST EPSS
        │                          security press RSS · vendor PSIRTs · CISA advisories
        │  dedupe → enrich (EPSS) → cluster → score → alert
        ├──► ntfy push (personal, high+ or watchlist elevated+)
        ▼
Firestore (3 small documents: state, seen, public)
        ▲
Cloud Run: radar-web ──► dashboard · /api/incidents · /feed.xml (Atom)
        ▲
Firebase Hosting (CDN, TLS, custom domain)
```

**Clustering:** reports are the same event if they share a CVE ID, or (within 72h)
if their headlines share enough distinctive words. A coined nickname like
`nginx2root` is enough on its own. Roundup articles that cite many CVEs are kept
from merging unrelated bugs.

**Scoring:** CISA KEV, CVSS, EPSS, breadth and speed of news coverage, official
advisories, exploitation and impact language (with negation detection), and a
personal watchlist. A single uncorroborated source is capped below alert level.
The full table is on the dashboard's *How it works* page and in
[`engine.py`](src/radar/engine.py).

## Security design

- **Untrusted input everywhere.** Every headline and link comes from a third party:
  - HTML and control characters are stripped.
  - Only `http(s)` links are kept, so `javascript:` URLs never get through.
  - Responses are capped in size, and redirects must stay on HTTPS.
  - The dashboard renders with `textContent` and never `innerHTML`.
  - The Atom feed escapes everything.
  - Push alerts go out as JSON, which prevents header injection.
- **Strict CSP:** `default-src 'none'; script-src 'self'; connect-src 'self'`, with no inline scripts or styles.
- **Least privilege:** each workload runs as its own service account.
  - The web service can only *read* Firestore.
  - The collector can write Firestore and read exactly one secret.
  - The scheduler can only start the job.
- **No long-lived credentials:** CI deploys through GitHub OIDC and Workload Identity Federation, pinned to this repo's numeric ID and its `production` environment.
- **Secrets stay out of Terraform state:** Terraform creates the secret container, and the value is added with `gcloud`.
- **Supply chain:**
  - Actions are pinned to commit SHAs, and lockfiles are used for Python and npm.
  - Dependabot sends weekly updates.
  - Trivy scans the image and IaC, and gitleaks scans for secrets.
  - Each release ships with an SBOM and a cosign keyless signature.
  - A weekly scheduled rebuild picks up base-image patches.
- **Runtime hardening:** non-root user (uid 10001); CI smoke-tests the image with a read-only root filesystem; no server banner; GET and HEAD only.
- **Public push is intentionally not enabled yet.** On open ntfy servers, anyone who knows a topic name can publish to it, which would let someone spoof alerts to subscribers. Public subscribers use the Atom feed for now.

## Cost

About $0 a month. Every component scales to zero or stays well within the free tier:
- **Firestore:** about 300 operations a day, against a free tier of 50,000 reads and 20,000 writes.
- **Cloud Run:** a 10-second job run 96 times a day.
- **Cloud Scheduler:** 1 job, against a free tier of 3.

## Local development

```bash
uv sync
uv run python -m radar.collector          # one scan → .data/
(cd web && npm install && npm run build)
uv run uvicorn radar.api:app --port 8080  # http://localhost:8080
uv run pytest
```
