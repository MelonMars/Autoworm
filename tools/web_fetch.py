import re
import html
import httpx
from tools.registry import register
from tools.base import Tool, Param

def _strip_html(text: str) -> str:
    text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</p>', '\n\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = html.unescape(text)
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n\s*\n', '\n\n', text)
    return text.strip()

def _web_fetch_execute(args: dict) -> dict:
    url = args["url"]
    max_length = args.get("max_length", 4000)

    if "github.com" in url and "/blob/" in url:
        url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        print(f"[*] Auto-converted GitHub URL to raw: {url}")

    try:
        with httpx.Client(follow_redirects=True, timeout=10, verify=False) as client:
            resp = client.get(url)
            
        content_type = resp.headers.get("content-type", "").lower()
        
        if any(ct in content_type for ct in ["text/plain", "python", "json", "application/octet-stream"]):
            text = resp.text
        else:
            text = _strip_html(resp.text)

        if len(text) > max_length:
            text = text[:max_length] + "\n\n... [CONTENT TRUNCATED TO SAVE CONTEXT SPACE]"

        return {
            "cmd": f"web_fetch:{url}",
            "code": 0,
            "stdout": f"Content fetched from {url}:\n\n{text}",
            "stderr": ""
        }

    except Exception as exc:
        return {"cmd": f"web_fetch:{url}", "code": 1, "stdout": "", "stderr": str(exc)}

web_fetch = register(Tool(
    name="web_fetch",
    description=(
        "Fetches the content of a specific URL and returns it as clean, readable text. "
        "Use this after a web_search to read full exploit writeups, CVE details, or PoC code. "
        "If you provide a GitHub link to a Python file, it automatically fetches the raw code. "
        "Output is truncated to 4000 characters to save memory."
    ),
    params=[
        Param("url", "string", "The exact URL to fetch (e.g., 'https://example.com/exploit.html')."),
        Param("max_length", "integer", "Maximum characters to return.", required=False),
    ],
    execute_fn=_web_fetch_execute,
    category=["search"],
    examples=[
        "Fetch a GitHub exploit script: url='https://github.com/user/repo/blob/main/exploit.py'",
        "Fetch a blog post about a vulnerability: url='https://blog.example.com/cve-2024-writeup'",
    ],
))