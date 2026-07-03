from tools.registry import register
from tools.base import Tool, Param

def curl_headers_cmd(a: dict) -> list[str]:
    method = a.get("method", "HEAD")
    cmd = ["curl", "-s", "-i", "-X", method, "--max-time", "10"]
    
    if a.get("follow_redirects", False):
        cmd.append("-L")
        
    cmd.append(a["url"])
    return cmd

curl_headers = register(Tool(
    name="curl_headers",
    description="Fetches HTTP headers and status codes from a web URL. Fast way to identify technologies, frameworks, and redirect logic without downloading the full page.",
    params=[
        Param("url", "string", "Full URL including scheme (e.g. http://10.0.0.1:8080)."),
        Param("method", "string", "HTTP method.", required=False, 
              enum=["HEAD", "GET"]),
        Param("follow_redirects", "boolean", "Follow 3xx redirects.", required=False),
    ],
    build_command=curl_headers_cmd,
))