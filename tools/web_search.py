from tools.registry import register
from tools.base import Tool, Param


def _web_search_execute(args: dict) -> dict:
    query = args["query"]
    max_results = args.get("max_results", 5)

    try:
        from duckduckgo_search import DDGS

        results = []
        with DDGS() as ddgs:
            for r in ddgs.text(query, max_results=max_results):
                results.append({
                    "title": r.get("title", ""),
                    "href": r.get("href", ""),
                    "body": r.get("body", ""),
                })

        output = {
            "query": query,
            "total_results": len(results),
            "results": results,
        }

        import json
        stdout = json.dumps(output, ensure_ascii=False)
        return {"cmd": f"web_search:{query}", "code": 0,
                "stdout": stdout, "stderr": ""}

    except ImportError:
        return {"cmd": f"web_search:{query}",
                "code": 1, "stdout": "",
                "stderr": "duckduckgo-search package not installed. Run: pip install duckduckgo-search"}
    except Exception as exc:
        return {"cmd": f"web_search:{query}",
                "code": 1, "stdout": "", "stderr": str(exc)}


web_search = register(Tool(
    name="web_search",
    description=(
        "Search the web via DuckDuckGo for security research. Use this to find: "
        "CVE details and proof-of-concept exploits, default credentials for specific software, "
        "known misconfigurations or logic flaws, exploit write-ups and walkthroughs, "
        "CWE-specific attack techniques, and version-specific vulnerability advisories. "
        "Always prefer specific queries over generic ones (e.g. 'Apache Tomcat 9.0.30 CVE' "
        "rather than just 'Tomcat exploit'). "
        "Results include title, URL, and a text snippet for each match."
    ),
    params=[
        Param("query", "string",
              "Search query — be specific: include software name, version, and vulnerability type."),
        Param("max_results", "integer",
              "Maximum number of results to return (1-20).",
              required=False),
    ],
    execute_fn=_web_search_execute,
    category="search",
    examples=[
        'Search for "Apache Tomcat 9.0.30 default credentials exploit"',
        'Search for "CVE-2021-44228 Log4Shell exploit PoC"',
        'Search for "OpenSSH 8.2 username enumeration CWE"',
        'Search for "vsftpd 2.3.4 backdoor exploit"',
    ],
))
