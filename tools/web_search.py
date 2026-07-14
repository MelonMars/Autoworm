from tools.registry import register
from tools.base import Tool, Param

def _web_search_execute(args: dict) -> dict:
    query = args["query"]
    max_results = args.get("max_results", 5)

    try:
        import warnings
        from ddgs import DDGS

        results = []
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with DDGS() as ddgs:
                for r in ddgs.text(query, max_results=max_results):
                    results.append({
                        "title": r.get("title", ""),
                        "href": r.get("href", ""),
                        "body": r.get("body", ""),
                    })

        if not results:
            return {"cmd": f"web_search:{query}", "code": 0, "stdout": "No results found.", "stderr": ""}

        stdout = f"Web Search Results for: '{query}'\n\n"
        for i, r in enumerate(results, 1):
            stdout += f"[{i}] {r.get('title', 'No Title')}\n"
            stdout += f"    URL: {r.get('href', '')}\n"
            stdout += f"    Snippet: {r.get('body', '')}\n\n"

        return {"cmd": f"web_search:{query}", "code": 0, "stdout": stdout, "stderr": ""}

    except ImportError:
        return {"cmd": f"web_search:{query}",
                "code": 1, "stdout": "",
                "stderr": "duckduckgo-search package not installed."}
    except Exception as exc:
        return {"cmd": f"web_search:{query}",
                "code": 1, "stdout": "", "stderr": str(exc)}

web_search = register(Tool(
    name="web_search",
    description=(
        "Search the web via DuckDuckGo for security research. Use this to find: "
        "CVE details and proof-of-concept exploits, default credentials for specific software, "
        "known misconfigurations or logic flaws, exploit write-ups and walkthroughs, "
        "and version-specific vulnerability advisories. "
        "Always prefer specific queries over generic ones."
    ),
    params=[
        Param("query", "string",
              "Search query — be specific: include software name, version, and vulnerability type."),
        Param("max_results", "integer",
              "Maximum number of results to return (1-20).",
              required=False),
    ],
    execute_fn=_web_search_execute,
    category=["search"],
))