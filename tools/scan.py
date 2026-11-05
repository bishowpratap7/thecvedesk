#!/usr/bin/env python3
"""The CVE Desk scanner. Pulls the latest vulnerabilities from the NVD
API, flags the ones CISA lists as known-exploited (KEV), enriches them
with EPSS exploitation-probability scores (FIRST) and GitHub Advisory
data (ecosystems/packages), then builds a Neo4j-style node graph:
CVE -[HAS_WEAKNESS]-> CWE, CVE -[AFFECTS]-> Product, CVE -[IN]-> Ecosystem.
Writes data/feed.json, bakes an SEO catalogue + ItemList into index.html,
regenerates feed.xml and sitemap.xml. Source failures keep prior data."""
import json, os, re, subprocess, sys, time
import urllib.request, urllib.parse
from collections import Counter
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
SITE = "https://bishowpratap7.github.io/thecvedesk/"

def fetch(url, timeout=40):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", "replace")
    except Exception:
        out = subprocess.run(["curl", "-s", "--max-time", str(timeout), "-A", UA, url],
                             capture_output=True, text=True)
        if out.returncode == 0 and out.stdout:
            return out.stdout
        raise

def esc(t):
    return (t or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def nvd_scan():
    now = datetime.now(timezone.utc)
    start = (now - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = now.strftime("%Y-%m-%dT%H:%M:%S.000")
    url = ("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=90"
           f"&pubStartDate={urllib.parse.quote(start)}&pubEndDate={urllib.parse.quote(end)}")
    data = json.loads(fetch(url))
    out = {}
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        cid = c.get("id")
        if not cid:
            continue
        desc = ""
        for d in c.get("descriptions", []):
            if d.get("lang") == "en":
                desc = re.sub(r"\s+", " ", d.get("value", "")).strip()
                break
        score, sev = None, "NONE"
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
            if metrics.get(key):
                m = metrics[key][0].get("cvssData", {})
                score = m.get("baseScore")
                sev = m.get("baseSeverity", sev)
                break
        cwes = []
        for w in c.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-") and val not in cwes:
                    cwes.append(val)
        products = []
        for conf in c.get("configurations", []):
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    parts = (match.get("criteria", "")).split(":")
                    if len(parts) >= 5 and parts[3] not in ("*", "-", ""):
                        p = {"vendor": parts[3].replace("_", " ").title(),
                             "product": parts[4].replace("_", " ").title()}
                        if p not in products:
                            products.append(p)
                    if len(products) >= 3:
                        break
        out[cid] = {"id": cid, "published": c.get("published", "")[:10],
                    "desc": desc[:220], "cvss": score, "severity": sev,
                    "cwes": cwes[:3], "products": products, "ecosystems": [],
                    "kev": False, "epss": None, "percentile": None,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cid}", "ghsa": ""}
    return out

def kev_scan():
    data = json.loads(fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"))
    return {v["cveID"]: {"vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
                         "date_added": v.get("dateAdded", ""), "ransomware": v.get("knownRansomwareCampaignUse", "")}
            for v in data.get("vulnerabilities", [])}

def ghsa_scan():
    data = json.loads(fetch("https://api.github.com/advisories?per_page=60&sort=published&direction=desc"))
    out = {}
    for a in data:
        cid = a.get("cve_id")
        if not cid:
            continue
        ecos, pkgs = [], []
        for v in a.get("vulnerabilities", []) or []:
            pkg = v.get("package") or {}
            eco = pkg.get("ecosystem", "")
            if eco and eco not in ecos:
                ecos.append(eco)
            if pkg.get("name") and pkg["name"] not in pkgs:
                pkgs.append(pkg["name"])
        cwes = []
        for w in a.get("cwes", []) or []:
            wid = w.get("cwe_id", "")
            if wid.startswith("CWE-") and wid not in cwes:
                cwes.append(wid)
        out[cid] = {"summary": (a.get("summary") or "")[:160], "ecosystems": ecos,
                    "packages": pkgs[:3], "cwes": cwes[:3], "html_url": a.get("html_url", ""),
                    "severity": (a.get("severity") or "").upper()}
    return out

def epss_scan(ids):
    scores = {}
    ids = sorted(ids)
    for i in range(0, min(len(ids), 90), 30):
        chunk = ids[i:i + 30]
        try:
            data = json.loads(fetch("https://api.first.org/data/v1/epss?cve=" + ",".join(chunk)))
            for row in data.get("data", []):
                scores[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
        except Exception as e:
            print(f"  epss chunk: {e}", file=sys.stderr)
        time.sleep(0.3)
    return scores

def rank_key(c):
    return (1 if c["kev"] else 0, c["cvss"] or 0, c["epss"] or 0)

def build_graph(cves):
    top = sorted(cves, key=rank_key, reverse=True)[:60]
    by_id = {c["id"]: c for c in top}
    cwe_count = Counter(w for c in top for w in c["cwes"])
    prod_count = Counter(f"{p['vendor']} {p['product']}" for c in top for p in c["products"])
    eco_count = Counter(e for c in top for e in c["ecosystems"])
    nodes, edges = [], []
    for c in top:
        nodes.append({"id": c["id"], "type": "cve", "label": c["id"], "cvss": c["cvss"],
                      "severity": c["severity"], "kev": c["kev"], "url": c["url"]})
    for cwe, n in cwe_count.most_common(12):
        nodes.append({"id": cwe, "type": "cwe", "label": cwe, "count": n,
                      "url": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"})
    for prod, n in prod_count.most_common(24):
        nodes.append({"id": "prod:" + prod, "type": "product", "label": prod, "count": n, "url": ""})
    for eco, n in eco_count.most_common(8):
        nodes.append({"id": "eco:" + eco, "type": "ecosystem", "label": eco, "count": n, "url": ""})
    node_ids = {n["id"] for n in nodes}
    for c in top:
        for w in c["cwes"]:
            if w in node_ids:
                edges.append({"s": c["id"], "t": w, "kind": "weakness"})
        for p in c["products"]:
            pid = "prod:" + f"{p['vendor']} {p['product']}"
            if pid in node_ids:
                edges.append({"s": c["id"], "t": pid, "kind": "affects"})
        for e in c["ecosystems"]:
            eid = "eco:" + e
            if eid in node_ids:
                edges.append({"s": c["id"], "t": eid, "kind": "ecosystem"})
    return {"nodes": nodes, "edges": edges}

def main():
    prev = {}
    pdata = os.path.join(ROOT, "data", "feed.json")
    if os.path.exists(pdata):
        try:
            prev = json.load(open(pdata))
        except Exception:
            prev = {}
    try:
        cves = nvd_scan()
        print(f"nvd: {len(cves)} CVEs (last 4 days)")
    except Exception as e:
        print(f"nvd FAILED: {e}", file=sys.stderr)
        cves = {}
    if not cves and prev.get("cves"):
        out = prev
        out["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        with open(pdata, "w") as f:
            json.dump(out, f, ensure_ascii=False, separators=(",", ":"))
        print("kept previous feed in full")
        return 0
    try:
        kev = kev_scan()
        hits = 0
        for cid, c in cves.items():
            if cid in kev:
                c["kev"] = True
                c["kev_date"] = kev[cid]["date_added"]
                hits += 1
        print(f"kev: catalog {len(kev)}, in-window hits {hits}")
    except Exception as e:
        print(f"kev FAILED: {e}", file=sys.stderr)
    try:
        ghsa = ghsa_scan()
        merged = 0
        for cid, g in ghsa.items():
            if cid in cves:
                c = cves[cid]
                c["ecosystems"] = g["ecosystems"]
                c["packages"] = g["packages"]
                c["ghsa"] = g["html_url"]
                for w in g["cwes"]:
                    if w not in c["cwes"]:
                        c["cwes"].append(w)
                if not c["desc"] and g["summary"]:
                    c["desc"] = g["summary"]
                merged += 1
            else:
                cves[cid] = {"id": cid, "published": "", "desc": g["summary"], "cvss": None,
                             "severity": g["severity"] or "NONE", "cwes": g["cwes"],
                             "products": [], "ecosystems": g["ecosystems"],
                             "packages": g["packages"], "kev": cid in (kev if 'kev' in dir() else {}),
                             "epss": None, "percentile": None,
                             "url": f"https://nvd.nist.gov/vuln/detail/{cid}", "ghsa": g["html_url"]}
        print(f"ghsa: {len(ghsa)} advisories, {merged} merged into NVD set")
    except Exception as e:
        print(f"ghsa FAILED: {e}", file=sys.stderr)
    try:
        scores = epss_scan(set(cves.keys()))
        for cid, s in scores.items():
            if cid in cves:
                cves[cid]["epss"] = s["epss"]
                cves[cid]["percentile"] = s["percentile"]
        print(f"epss: {len(scores)} scores")
    except Exception as e:
        print(f"epss FAILED: {e}", file=sys.stderr)
    clist = sorted(cves.values(), key=lambda c: c["published"] or "", reverse=True)
    clist.sort(key=rank_key, reverse=True)
    graph = build_graph(list(cves.values()))
    stats = {
        "tracked": len(clist),
        "critical": sum(1 for c in clist if (c["cvss"] or 0) >= 9),
        "kev": sum(1 for c in clist if c["kev"]),
        "graph_nodes": len(graph["nodes"]), "graph_edges": len(graph["edges"]),
        "top_cwe": Counter(w for c in clist for w in c["cwes"]).most_common(6),
        "top_ecosystems": Counter(e for c in clist for e in c["ecosystems"]).most_common(6),
    }
    out = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
           "stats": stats, "cves": clist[:90],
           "kev_spotlight": [c for c in clist if c["kev"]][:12],
           "graph": graph}
    with open(pdata, "w") as f:
        json.dump(out, f, ensure_ascii=False, separators=(",", ":"))
    bake(out)
    return 0

def bake(out):
    ipath = os.path.join(ROOT, "index.html")
    html = open(ipath).read()
    lines = ["<ul>"]
    items, pos = [], 1
    for c in out["cves"][:40]:
        bits = []
        if c["cvss"] is not None:
            bits.append(f"CVSS {c['cvss']} ({esc(c['severity'])})")
        if c["epss"] is not None:
            bits.append(f"EPSS {c['epss']:.1%}")
        if c["kev"]:
            bits.append("CISA KEV — known exploited")
        meta = " · ".join(bits)
        lines.append(f"<li><a href=\"{c['url']}\">{c['id']}</a> — {esc(c['desc'][:150])} <span>({meta})</span></li>")
        items.append({"@type": "ListItem", "position": pos, "name": f"{c['id']} — {c['desc'][:90]}", "url": c["url"]})
        pos += 1
    lines.append("</ul>")
    ld = {"@context": "https://schema.org", "@type": "ItemList",
          "name": "Latest CVE vulnerabilities tracked by The CVE Desk", "itemListElement": items}
    ld_html = '<script type="application/ld+json">\n' + json.dumps(ld, ensure_ascii=False) + "\n</script>"
    new = re.sub(r"<!--FEED:START-->.*?<!--FEED:END-->",
                 "<!--FEED:START-->\n" + "\n".join(lines) + "\n<!--FEED:END-->", html, flags=re.S)
    new = re.sub(r"<!--ITEMLIST:START-->.*?<!--ITEMLIST:END-->",
                 "<!--ITEMLIST:START-->\n" + ld_html + "\n<!--ITEMLIST:END-->", new, flags=re.S)
    if new != html:
        open(ipath, "w").write(new)
        feed = ('<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel>'
                f"<title>The CVE Desk</title><link>{SITE}</link>"
                "<description>Latest CVE vulnerabilities with CVSS, EPSS, CISA KEV status and a live weakness graph.</description>\n")
        for c in out["cves"][:15]:
            feed += (f"<item><title>{c['id']} ({esc(c['severity'])})</title><link>{c['url']}</link>"
                     f"<guid>{c['url']}</guid><pubDate>{out['generated_at']}</pubDate></item>\n")
        feed += "</channel></rss>"
        open(os.path.join(ROOT, "feed.xml"), "w").write(feed)
        sm = ('<?xml version="1.0" encoding="UTF-8"?>\n'
              '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
              f"<url><loc>{SITE}</loc><lastmod>{out['generated_at']}</lastmod>"
              "<changefreq>hourly</changefreq><priority>1.0</priority></url></urlset>")
        open(os.path.join(ROOT, "sitemap.xml"), "w").write(sm)
        print("baked: changed")
    else:
        print("baked: unchanged")

if __name__ == "__main__":
    sys.exit(main())
