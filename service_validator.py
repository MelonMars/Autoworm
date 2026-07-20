import socket
import ssl
import json
import logging
from llm import request_llm, extract_json

logger = logging.getLogger(__name__)

VALIDATOR_SYSTEM = """You are a strict service validation engine. 
You compare raw network banners against a structured service record.
Output ONLY one JSON object. No prose, no markdown fences.

Schema:
{
  "corrected_services": {
    "port_number": {
      "name": "string",
      "product": "string",
      "version": "string",
      "more_info": "string"
    }
  },
  "corrections_made": ["string"]
}

Rules:
1. The raw banner is GROUND TRUTH. 
2. If the raw banner explicitly identifies a different product or version than the structured record, FIX the structured record to match the banner.
3. For example, if the record says {"product": "ProFTPD"} but the banner says "(vsFTPd 2.3.4)", you must change the product to "vsftpd" and version to "2.3.4".
4. If the banner is empty or uninformative, keep the original record intact.
5. Do not guess or hallucinate. Only correct fields if the banner explicitly proves them wrong.
"""

def _grab_raw_banner(ip: str, port: int, timeout: int = 3) -> str:
    """Connects to a port and grabs the raw banner. Sends HTTP GET for web ports."""
    banner = ""
    try:
        if port in [443, 8443]:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    ssock.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                    banner = ssock.recv(2048).decode('utf-8', errors='ignore')
        else:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                # Web ports usually don't send a banner until you send a request
                if port in [80, 8080, 8000, 81, 82, 8081]:
                    s.send(b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                banner = s.recv(2048).decode('utf-8', errors='ignore')
    except Exception:
        pass
        
    # Clean up the banner for the LLM context
    return banner.strip()[:500] if banner else ""

def validate_services(host) -> dict:
    print("\n[*] === Validating Service Banners ===")
    
    if not host.services:
        return {"corrections_made": []}

    services_to_check = {}
    raw_banners = {}

    for port, svc in host.services.items():
        if not isinstance(svc, dict):
            continue
            
        port_int = int(port)
        services_to_check[port] = svc
        
        print(f"  [{port}] Connecting to grab raw banner...")
        banner = _grab_raw_banner(host.ip, port_int)
        
        if banner:
            first_line = banner.splitlines()[0] if banner else ""
            print(f"      → {first_line[:80]}")
            raw_banners[port] = banner
        else:
            print("      → No banner received (might be non-interactive or filtered).")
            raw_banners[port] = ""

    if not raw_banners:
        return {"corrections_made": []}

    prompt = f"""
Target IP: {host.ip}

Current Discovered Services (JSON):
{json.dumps(services_to_check, indent=2)}

Raw Network Banners Grabbed (JSON):
{json.dumps(raw_banners, indent=2)}

Task: Compare the raw banners against the discovered services. If the raw banner explicitly proves a DIFFERENT product or version than what is currently recorded, correct it. 
Return the full corrected_services dictionary.
"""

    raw = request_llm(
        prompt,
        system=VALIDATOR_SYSTEM,
        enable_thinking=False,
        do_sample=False,
        max_new_tokens=2048
    )

    try:
        data = extract_json(raw)
        corrected_services = data.get("corrected_services", {})
        corrections_made = data.get("corrections_made", [])

        if corrections_made:
            print(f"[+] Service Validator made corrections: {corrections_made}")
            for port, corrected_svc in corrected_services.items():
                if port in host.services and isinstance(host.services[port], dict):
                    host.services[port].update(corrected_svc)
        else:
            print("[*] No service corrections needed. Services are accurate.")

        return data

    except Exception as e:
        logger.error(f"Service Validator failed to parse LLM JSON: {e}")
        return {"corrections_made": [], "error": str(e)}
    