from tools.registry import register
from tools.base import Tool, Param

import json
import httpx


def _parse_headers(headers_str: str) -> dict:
    if not headers_str:
        return {}
    try:
        parsed = json.loads(headers_str)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, TypeError):
        pass
    headers = {}
    for line in headers_str.strip().splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            headers[key.strip()] = val.strip()
    return headers


def _http_request_execute(args: dict) -> dict:
    method = args["method"]
    url = args["url"]
    headers = _parse_headers(args.get("headers", ""))
    body = args.get("body", "")
    auth_type = args.get("auth_type", "none")
    auth_credential = args.get("auth_credential", "")
    follow_redirects = args.get("follow_redirects", True)
    timeout = args.get("timeout", 10)

    auth = None
    if auth_type == "basic":
        if ":" in auth_credential:
            user, pw = auth_credential.split(":", 1)
            auth = (user, pw)
    elif auth_type == "bearer":
        headers["Authorization"] = f"Bearer {auth_credential}"
    elif auth_type == "cookie":
        headers["Cookie"] = auth_credential

    try:
        with httpx.Client(follow_redirects=follow_redirects, timeout=timeout,
                          verify=False) as client:
            resp = client.request(
                method=method,
                url=url,
                headers=headers,
                content=body if body else None,
                auth=auth,
            )

        resp_text = resp.text[:4096]
        if len(resp.text) > 4096:
            resp_text += f"\n... [truncated, total {len(resp.text)} chars]"

        resp_headers = {k: v for k, v in resp.headers.items()}
        headers_text = json.dumps(resp_headers, ensure_ascii=False)

        output = {
            "status_code": resp.status_code,
            "reason": resp.reason_phrase,
            "response_headers": resp_headers,
            "body": resp_text,
            "url": str(resp.url),
            "history_count": len(resp.history),
        }

        stdout = json.dumps(output, ensure_ascii=False)
        cmd = f"HTTP {method} {url}"
        return {"cmd": cmd, "code": 0 if resp.status_code < 400 else 1,
                "stdout": stdout, "stderr": ""}

    except httpx.TimeoutException:
        return {"cmd": f"HTTP {method} {url}",
                "code": 1, "stdout": "", "stderr": "Request timed out"}
    except httpx.ConnectError as exc:
        return {"cmd": f"HTTP {method} {url}",
                "code": 1, "stdout": "", "stderr": f"Connection failed: {exc}"}
    except Exception as exc:
        return {"cmd": f"HTTP {method} {url}",
                "code": 1, "stdout": "", "stderr": str(exc)}


http_request = register(Tool(
    name="http_request",
    description=(
        "Send an HTTP request to a target URL for testing web application security. "
        "Supports all HTTP methods, custom headers, request bodies, and authentication. "
        "Designed for testing logic flaws: try different parameter values, swap user IDs, "
        "test authentication with different credentials, probe path traversal, test for injection. "
        "Headers can be provided as a JSON object or newline-separated 'Key: Value' pairs. "
        "Auth types: 'none', 'basic' (user:pass), 'bearer' (token string), 'cookie' (cookie string). "
        "Returns status code, response headers, and body (truncated if large)."
    ),
    params=[
        Param("method", "string", "HTTP method to use.",
              enum=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]),
        Param("url", "string", "Target URL (e.g. 'http://192.168.1.5:8080/admin')."),
        Param("headers", "string",
              "Request headers as JSON object or 'Key: Value' lines.",
              required=False),
        Param("body", "string",
              "Request body content (for POST, PUT, PATCH).",
              required=False),
        Param("auth_type", "string", "Authentication method.",
              enum=["none", "basic", "bearer", "cookie"], required=False),
        Param("auth_credential", "string",
              "Auth credential: 'user:pass' for basic, token for bearer, cookie string for cookie.",
              required=False),
        Param("follow_redirects", "boolean",
              "Follow HTTP redirects (default true).", required=False),
        Param("timeout", "integer",
              "Request timeout in seconds (default 10).", required=False),
    ],
    execute_fn=_http_request_execute,
    category="recon",
    examples=[
        'GET request to http://192.168.1.5:8080/ to check what runs on port 8080',
        'POST login form with admin:admin credentials to test default credentials',
        'GET request with cookie auth to test IDOR on /api/users/1',
        'POST request to test path traversal in /download?file=../../etc/passwd',
    ],
))
