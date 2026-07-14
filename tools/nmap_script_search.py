# tools/nmap_script_search.py

import os
import re
import json
import time
import requests
from tools.registry import register
from tools.base import Tool, Param

NSE_SCRIPT_DIR = os.path.abspath("nmap_scripts")
os.makedirs(NSE_SCRIPT_DIR, exist_ok=True)

SCRIPT_DB_URL = "https://raw.githubusercontent.com/nmap/nmap/master/scripts/script.db"
SCRIPT_DB_CACHE = os.path.join(NSE_SCRIPT_DIR, "_script_db.json")
CACHE_TTL = 86400  # 24 hours


def _fetch_script_db() -> list[dict]:
    """Fetch and parse nmap's official script.db (names + categories), cached locally."""
    # ── try cache ──
    if os.path.exists(SCRIPT_DB_CACHE):
        try:
            with open(SCRIPT_DB_CACHE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if time.time() - data.get("fetched", 0) < CACHE_TTL:
                return data["scripts"]
        except (json.JSONDecodeError, KeyError):
            pass

    # ── fetch from GitHub ──
    try:
        print("[*] Fetching NSE script database from GitHub...")
        resp = requests.get(SCRIPT_DB_URL, timeout=15)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}")
        content = resp.text
    except Exception as e:
        # fall back to stale cache if network fails
        if os.path.exists(SCRIPT_DB_CACHE):
            with open(SCRIPT_DB_CACHE, "r", encoding="utf-8") as f:
                return json.load(f)["scripts"]
        return {"code": 1, "stdout": "", "stderr": f"Cannot reach GitHub: {e}"}

    # ── parse  ──
    # Each line looks like:
    #   Entry { filename = "smb-vuln-ms17-010.nse", categories = { "vuln", "safe", } }
    scripts = []
    for line in content.splitlines():
        m_name = re.search(r'filename\s*=\s*"(.+?)\.nse"', line)
        if not m_name:
            continue
        name = m_name.group(1)
        m_cats = re.search(r'categories\s*=\s*\{([^}]+)\}', line)
        categories = re.findall(r'"(\w+)"', m_cats.group(1)) if m_cats else []
        scripts.append({"name": name, "categories": categories})

    # ── write cache ──
    with open(SCRIPT_DB_CACHE, "w", encoding="utf-8") as f:
        json.dump({"scripts": scripts, "fetched": time.time()}, f)

    print(f"[+] Cached {len(scripts)} NSE scripts.")
    return scripts


# ── Keyword → likely service prefix mapping ──
_SERVICE_PREFIXES = {
    "ssh": "ssh", "ftp": "ftp", "http": "http", "https": "http",
    "smb": "smb", "samba": "smb", "mysql": "mysql", "rdp": "rdp",
    "vnc": "vnc", "smtp": "smtp", "dns": "dns", "ldap": "ldap",
    "ssl": "ssl", "tls": "ssl", "redis": "redis", "mongo": "mongodb",
    "mssql": "mssql", "oracle": "oracle", "snmp": "snmp",
    "ntp": "ntp", "nfs": "nfs", "ajp": "ajp",
}


def _search_nse_execute(args: dict) -> dict:
    keyword = args.get("keyword", "").lower().strip()
    service = args.get("service", "").lower().strip()
    category = args.get("category", "").lower().strip()

    # resolve friendly service names to NSE name prefixes
    prefix = _SERVICE_PREFIXES.get(service, service)

    try:
        all_scripts = _fetch_script_db()
    except Exception as e:
        return {"code": 1, "stdout": "", "stderr": str(e)}

    # ── filter ──
    matches = []
    for s in all_scripts:
        name = s["name"].lower()
        cats = [c.lower() for c in s["categories"]]

        score = 0

        # category filter (hard filter)
        if category and category not in cats:
            continue

        # prefix / service match (highest value)
        if prefix and name.startswith(prefix + "-"):
            score += 10

        # keyword anywhere in name
        if keyword and keyword in name:
            score += 5

        # vuln/exploit bonus — these are usually what the agent wants
        if "vuln" in cats or "exploit" in cats:
            score += 2
        if "safe" in cats:
            score += 1

        # must match at least something
        if not keyword and not prefix and not category:
            score = 1  # list all if no filters

        if score > 0:
            matches.append((score, s))

    # sort by score descending
    matches.sort(key=lambda x: -x[0])
    matches = matches[:40]  # cap output

    # ── format output ──
    lines = [f"Found {len(matches)} matching NSE scripts:\n"]

    # Group by category for readability
    vuln_scripts = []
    safe_scripts = []
    other_scripts = []
    for score, s in matches:
        entry = f"  {s['name']}  [{', '.join(s['categories'])}]"
        if "vuln" in s["categories"] or "exploit" in s["categories"]:
            vuln_scripts.append(entry)
        elif "safe" in s["categories"]:
            safe_scripts.append(entry)
        else:
            other_scripts.append(entry)

    if vuln_scripts:
        lines.append("Vuln / Exploit scripts:")
        lines.extend(vuln_scripts)
    if safe_scripts:
        lines.append("\nSafe / Discovery scripts:")
        lines.extend(safe_scripts)
    if other_scripts:
        lines.append("\nOther scripts:")
        lines.extend(other_scripts)

    # Add guidance
    lines.append("\nUsage hints:")
    lines.append("  - Use EXACT script name in the 'nmap' tool's script_name parameter")
    lines.append("  - Or use a CATEGORY as script_name: 'vuln', 'safe', 'discovery', 'auth', 'exploit'")
    lines.append("  - Categories run ALL scripts in that category — more reliable than guessing names")

    return {
        "code": 0,
        "stdout": "\n".join(lines),
        "stderr": "",
    }


# ── Register as a SEARCH tool ──
nmap_script_search = register(Tool(
    name="nmap_script_search",
    description=(
        "Searches the OFFICIAL Nmap NSE script repository for valid script names. "
        "ALWAYS use this tool before running any nmap NSE script to confirm the script "
        "actually exists. Returns exact script names and their categories."
    ),
    params=[
        Param("keyword", "string",
              "Keyword to search for in script names (e.g. 'vuln', 'ms17', 'heartbleed')",
              required=False),
        Param("service", "string",
              "Service name to find scripts for (e.g. 'ssh', 'http', 'smb', 'ftp')",
              required=False),
        Param("category", "string",
              "NSE category to filter by: vuln, safe, exploit, auth, discovery, default, intrusive",
              required=False),
    ],
    execute_fn=_search_nse_execute,
    category=["search"],
    examples=[
        "Find SSH vulnerability scripts: service='ssh', category='vuln'",
        "Find all vuln scripts: category='vuln'",
        "Find scripts related to MS17-010: keyword='ms17-010'",
        "Find HTTP enum scripts: service='http', keyword='enum'",
    ],
))