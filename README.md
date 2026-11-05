# The CVE Desk 🛡️

The latest CVE vulnerabilities, mapped. The desk tracks fresh CVEs from
the National Vulnerability Database, flags the ones CISA lists as known
exploited (KEV), enriches them with EPSS exploit-probability scores from
FIRST and ecosystem data from the GitHub Advisory Database — then draws
the whole thing as a Neo4j-style node graph: CVEs connected to their CWE
weaknesses, affected products and ecosystems.

- Live desk: https://bishowpratap7.github.io/thecvedesk/
- Run by **Bishow Pandey** (application security is his day job) —
  X: https://x.com/bishowppandey · LinkedIn: https://www.linkedin.com/in/bishowpandey

## What's on the desk
- **The Vulnerability Graph** — an interactive force-directed map of the
  newest and most severe CVEs; node size follows CVSS, red rings mark
  CISA KEV entries; hover to inspect, click through to the official record
- **Actively Exploited board** — in-window CVEs already on the KEV list
- **The Latest Board** — cards with CVSS chips, EPSS percentages, CWE
  families and publication dates
- **Where the Storm Is** — top CWE weakness families and ecosystems

## How it works
- `tools/scan.py` queries the NVD API (4-day window), downloads CISA's
  KEV catalog, calls FIRST's EPSS API and the GitHub Advisory Database,
  merges everything per CVE, builds the graph JSON, and writes
  `data/feed.json`. It bakes an SEO catalogue into `index.html` and
  regenerates `feed.xml` / `sitemap.xml`. Any source failing keeps the
  previous data rather than blanking the desk.
- A GitHub Actions loop re-runs the scanner every 30 minutes around the
  clock, handing off to its successor like the other desks in the network.

## Sister desks
The Dev Desk · Scroll Patrol · The World Desk · The Stock Desk ·
The Shopping Desk · The Cozy Desk · The Foodie Desk · The Style Desk ·
Museum of Outages

## Repos
- `thecvedesk` (public) — the live site, served by GitHub Pages
- `the-cve-desk` (private) — the archive twin

## Good to know
Data: NVD (NIST), CISA KEV, FIRST EPSS, GitHub Advisory Database. Scores
mature over time — new CVEs may show CVSS as pending. Always confirm
remediation in the official record and vendor advisories. Information
only; not a patch-management service.
