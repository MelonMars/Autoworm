import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tools.registry import register
from tools.base import Tool, Param

def _fuzz_worker(url, timeout=5):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False)
        size = len(r.content)
        return r.status_code, size, url
    except requests.RequestException:
        return None, None, url

def execute_web_fuzz(args: dict) -> dict:
    target_url = args["target_url"].rstrip("/")
    wordlist_path = "wordlists/web_common.txt"
    extensions = args.get("extensions", "").split(",") if args.get("extensions") else [""]
    threads = args.get("threads", 10)
    
    paths_to_test = []
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        return {"code": 1, "stdout": "", "stderr": f"Wordlist not found at {wordlist_path}"}

    for word in words:
        for ext in extensions:
            if ext and not ext.startswith("."):
                ext = "." + ext
            paths_to_test.append(f"{word}{ext}")

    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_fuzz_worker, f"{target_url}/{path}"): path for path in paths_to_test}
        for future in as_completed(futures):
            status, size, url = future.result()
            if status and status != 404:
                results.append((status, size, url))
    
    results.sort(key=lambda x: (x[0], x[1]))
    
    output_lines = [f"[{status}] [SIZE={size}] {url}" for status, size, url in results]
    stdout = "\n".join(output_lines) if output_lines else "No non-404 responses found."
    
    return {"code": 0, "stdout": stdout, "stderr": ""}

web_dir_fuzz = register(Tool(
    name="web_dir_fuzz",
    description="Pure Python web path fuzzer. Discovers hidden directories and files on web servers. Formats output like gobuster.",
    params=[
        Param("target_url", "string", "Base URL to scan (e.g., http://10.0.0.1)."),
        Param("extensions", "string", "Comma-separated extensions to append (e.g., 'php,txt,html').", required=False),
        Param("threads", "integer", "Number of concurrent requests.", required=False),
    ],
    execute_fn=execute_web_fuzz,
    category=["recon"],
))