from memory import Host


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
        if isinstance(val, str) and val.strip() == "" and key in tool.required_args:
            return f"Sanity Check Failed: Required argument '{key}' is empty."
            
    return None

