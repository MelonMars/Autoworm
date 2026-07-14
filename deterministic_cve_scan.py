import requests
import time
from utils import merge

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cve_cache = {}

def _extract_cvss(cve_data):
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            cd = m.get("cvssData", {})
            return {
                "score": cd.get("baseScore", 0),
                "severity": m.get("baseSeverity") or cd.get("baseSeverity", ""),
                "vector": cd.get("vectorString", ""),
                "attack_vector": cd.get("attackVector", ""),
            }
    return {}

def _parse_nvd_response(data, service, product_filter=None):
    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln["cve"]
        desc = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d["lang"] == "en"),
            "",
        )

        if product_filter:
            haystack = (desc + str(cve_data.get("configurations", []))).lower()
            if product_filter.lower() not in haystack:
                continue

        refs = cve_data.get("references", [])
        weaknesses = [
            w.get("description", [{}])[0].get("value", "")
            for w in cve_data.get("weaknesses", [])
        ]

        cves.append({
            "id": cve_data["id"],
            "description": desc[:500],
            "cvss": _extract_cvss(cve_data),
            "cwe_ids": weaknesses,
            "exploit_available": any(
                "exploit" in r.get("url", "").lower() for r in refs
            ),
            "references": [r["url"] for r in refs[:10]],
            "source": "nvd",
            "matched_service": service.get("name"),
            "matched_product": service.get("product") or service.get("name"),
            "matched_version": service.get("version"),
        })

    cves.sort(key=lambda c: c["cvss"].get("score", 0), reverse=True)
    return cves

def lookup_cves_for_service(service, timeout=20):
    product = service.get("product") or service.get("name")
    version = service.get("version", "")
    vendor = service.get("vendor", "")
    if product == "" or version == "":
        product = service
        version = ""
    
    cache_key = f"{vendor}:{product}:{version}".lower()
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]
    try:
        resp = requests.get(
            NVD_API_URL,
            params={"keywordSearch": f"{product} {version}"},
            timeout=timeout,
        )
        if resp.ok:
            cves = _parse_nvd_response(
                resp.json(), service, product_filter=product
            )
    except Exception as e:
        print(f"  [-] NVD keyword lookup error: {e}")
    time.sleep(0.6)

    _cve_cache[cache_key] = cves
    return cves

def deterministic_cve_scan(host):
    print("\n[*] === Deterministic CVE Scan (NVD) ===")
    all_cves = []

    for port, svc in host.services.items():
        if not isinstance(svc, dict):
            continue
        product = svc.get("product") or svc.get("name")
        version = svc.get("version")
        if not product or not version:
            print(f"  [{port}] {product or '?'} — no version, skipping")
            continue

        print(f"  [{port}] {product} {version} — querying NVD…")
        cves = lookup_cves_for_service(svc)
        for c in cves:
            tag = " [EXPLOIT]" if c["exploit_available"] else ""
            print(
                f"    → {c['id']}  "
                f"CVSS={c['cvss'].get('score', '?')} "
                f"({c['cvss'].get('severity', '?')}){tag}"
            )
        all_cves.extend(cves)

    if all_cves:
        merge(
            host.vulnerabilities,
            {"cve_scan": {"source": "nvd", "count": len(all_cves), "cves": all_cves}},
        )
        print(f"[+] Deterministic scan found {len(all_cves)} CVE(s).\n")
    else:
        print("[*] No CVEs found.\n")
    return all_cves