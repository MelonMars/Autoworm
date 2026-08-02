import requests
import time
import re
from utils import merge

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_cve_cache = {}

GENERIC_PRODUCTS = {"http", "https", "tcp", "udp", "linux", "unix", "os", "shell", "openssl", "rpc"}

EDB_RE = re.compile(r'exploit-db\.com/exploits/(\d+)', re.I)

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

def _has_exploit(cve_data):
    for r in cve_data.get("references", []):
        url = r.get("url", "").lower()
        tags = r.get("tags", [])
        if "exploit" in tags or "exploit-db" in url or "metasploit" in url or "packetstorm" in url:
            return True
    return False

def _extract_edb_ids(cve_data):
    ids = []
    for r in cve_data.get("references", []):
        url = r.get("url", "")
        m = EDB_RE.search(url)
        if m and m.group(1) not in ids:
            ids.append(m.group(1))
    return ids

def _cve_affects_product(cve_data: dict, product: str, version: str) -> bool:
    product_l = product.lower()
    version_l = (version or "").lower()
    
    for node in cve_data.get("configurations", []):
        for n in node.get("nodes", []):
            for cpe in n.get("cpeMatch", []):
                criteria = (cpe.get("criteria") or "").lower()
                parts = criteria.split(":")
                if len(parts) < 6:
                    continue
                cpe_vendor, cpe_product, cpe_version = parts[3], parts[4], parts[5]
                
                if product_l in cpe_product or cpe_product in product_l:
                    if cpe_version in ("*", "-") or cpe_version == version_l:
                        return True
                    
                    start_inc = cpe.get("versionStartIncluding")
                    start_exc = cpe.get("versionStartExcluding")
                    end_inc = cpe.get("versionEndIncluding")
                    end_exc = cpe.get("versionEndExcluding")
                    
                    start_ok = True
                    if start_inc and version_l < start_inc.lower(): start_ok = False
                    if start_exc and version_l <= start_exc.lower(): start_ok = False
                        
                    end_ok = True
                    if end_inc and version_l > end_inc.lower(): end_ok = False
                    if end_exc and version_l >= end_exc.lower(): end_ok = False

                    if (start_inc or start_exc or end_inc or end_exc) and start_ok and end_ok:
                        return True
                        
    if product_l not in GENERIC_PRODUCTS:
        desc = next((d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"), "").lower()

        if product_l in desc and version_l and version_l in desc:
            return True
            
    return False

def _parse_nvd_response(data, service, product_filter=None):
    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_data = vuln["cve"]
        desc = next(
            (d["value"] for d in cve_data.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )

        if product_filter and not _cve_affects_product(cve_data, product_filter, service.get("version", "")):
            continue

        refs = cve_data.get("references", [])
        weaknesses = [
            w.get("description", [{}])[0].get("value", "")
            for w in cve_data.get("weaknesses", [])
        ]

        cves.append({
            "id": cve_data["id"],
            "description": desc[:300],
            "cvss": _extract_cvss(cve_data),
            "cwe_ids": weaknesses,
            "exploit_available": _has_exploit(cve_data),
            "references": [r["url"] for r in refs[:5]],
            "source": "nvd",
            "matched_service": service.get("name"),
            "matched_product": service.get("product") or service.get("name"),
            "matched_version": service.get("version"),
            "matched_port": service.get("port"),
            "edb_ids": _extract_edb_ids(cve_data)
        })

    cves.sort(key=lambda c: (c["exploit_available"], c["cvss"].get("score", 0)), reverse=True)
    return cves

def lookup_cves_for_service(service, timeout=20):
    product = service.get("product") or service.get("name")
    version = service.get("version", "")
    vendor = service.get("vendor", "")
    cpe = service.get("cpe", "")
    
    if not product or not version or str(product).lower() in GENERIC_PRODUCTS:
        return []
    
    if cpe:
        cache_key = cpe.lower()
        params = {"cpeName": cpe}
    else:
        cache_key = f"{vendor}:{product}:{version}".lower()
        params = {"keywordSearch": f"{product} {version}"}

    if cache_key in _cve_cache:
        return _cve_cache[cache_key]
    
    cves = []
    try:
        resp = requests.get(NVD_API_URL, params=params, timeout=timeout)
        if resp.ok:
            cves = _parse_nvd_response(resp.json(), service, product_filter=product)
            cves = cves[:10]
    except Exception as e:
        print(f"  [-] NVD lookup error for {product} {version}: {e}")
    
    time.sleep(0.6)
    _cve_cache[cache_key] = cves
    return cves

def deterministic_cve_scan(host):
    print("\n[*] === Deterministic CVE Scan (NVD) ===")
    all_cves = []

    for port, svc in host.services.items():
        if not isinstance(svc, dict):
            continue
            
        svc["port"] = port
        
        product = svc.get("product") or svc.get("name")
        version = svc.get("version")
        if not product or not version:
            continue

        print(f"  [{port}] {product} {version} — querying NVD...")
        cves = lookup_cves_for_service(svc)
        for c in cves:
            tag = " [EXPLOIT]" if c["exploit_available"] else ""
            print(f"    -> {c['id']}  CVSS={c['cvss'].get('score', '?')} ({c['cvss'].get('severity', '?')}){tag}")
        all_cves.extend(cves)

    if all_cves:
        all_cves = sorted(all_cves, key=lambda c: (c["exploit_available"], c["cvss"].get('score', 0)), reverse=True)[:20]
        
        merge(
            host.vulnerabilities,
            {"cve_scan": {"source": "nvd", "count": len(all_cves), "cves": all_cves}},
        )
        print(f"[+] Deterministic scan found {len(all_cves)} prioritized CVE(s) (Top 20 saved).\n")
    else:
        print("[*] No CVEs found.\n")
    return all_cves
