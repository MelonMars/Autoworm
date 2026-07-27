from memory import Host
import socket

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def merge(dst, src):
    for k, v in src.items():
        if (
            k in dst
            and isinstance(dst[k], dict)
            and isinstance(v, dict)
        ):
            merge(dst[k], v)
        else:
            dst[k] = v

def apply_update(host, update, campaign):
    merge(host.facts, update.get("facts", {}))
    merge(host.services, update.get("services", {}))
    for edge in update.get("new_edges", []):
        if "from" not in edge or "to" not in edge:
            continue
        campaign.graph.add_edge(edge["from"], edge["to"], type=edge.get("type", ""))
    if "vulnerabilities" in update:
        merge(host.vulnerabilities, update["vulnerabilities"])

def sanity_check_args(args: dict, tool, host: Host) -> str | None:
    if "target_ip" in args and args["target_ip"] != host.ip:
        return f"Sanity Check Failed: target_ip {args['target_ip']} does not match host IP {host.ip}."
    
    for key, val in args.items():
        try:
            if isinstance(val, str) and val.strip() == "" and key in tool.required_args:
                return f"Sanity Check Failed: Required argument '{key}' is empty."
        except Exception as e:
            return None
    return None

def build_isolated_context(host: Host, hypothesis: dict) -> dict:
    isolated_facts = {}
    isolated_services = {}
    
    hyp_text = hypothesis.get("description", "") + " " + " ".join(hypothesis.get("evidence", []))
    
    for port, svc in host.services.items():
        if port in hyp_text or (isinstance(svc, dict) and svc.get("name", "") in hyp_text):
            isolated_services[port] = svc
            
    if not isolated_services:
        isolated_services = host.services
        
    for k, v in host.facts.items():
        if k in ["os", "hostname", "ip"] or any(word in str(k) for word in hyp_text.split()):
            isolated_facts[k] = v

    return {
        "ip": host.ip,
        "os": host.os,
        "hostname": host.hostname,
        "services": isolated_services,
        "facts": isolated_facts,
        "vulnerabilities": host.vulnerabilities
    }