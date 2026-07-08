from tools.registry import register
from tools.base import Tool, Param

def cve_search_cmd(a: dict) -> list[str]:
    cve_id = a["cve_id"]

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    cmd = ["curl", "-s", "-X", "GET", url]

    return cmd

cve_search_api = register(Tool(
    name="cve_search_api",
    description="Queries the NVD (National Vulnerability Database) API for detailed information about a specific CVE, including description, CVSS score, affected products, and references. Use when you have a CVE ID and need full vulnerability details.",
    params=[
        Param("cve_id", "string", "CVE ID to look up (e.g. CVE-2021-44228)."),
    ],
    build_command=cve_search_cmd,
    category=["search"],
))
