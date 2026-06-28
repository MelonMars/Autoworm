from tools.tool import Tool
import ipaddress
import re
import subprocess

class Nmap(Tool):
    name = "nmap"
    description = "Nmap is a network scanning tool that can be used to discover hosts and services on a computer network."
    stages = ["discover_network", "discover_host"]
    parameters = {
        "target": "required. single host, hostname, CIDR (10.0.0.0/24), or range (10.0.0.1-50)",
        "scan_type": "one of: ping_sweep, connect, syn, udp. default connect",
        "ports": "optional, e.g. '22,80,443' or '1-1024'. omit for default top ports",
        "service_detection": "bool, adds -sV version detection. default false",
        "os_detection": "bool, adds -O fingerprinting (needs root). default false",
        "skip_host_discovery": "bool, -Pn, treat host as up. default false",
        "timing": "int 0-5 (-T template). default 3",
    }
    guidance = (
        "Choose scan_type by goal: ping_sweep enumerates live hosts on a network "
        "(no port scan); connect/syn finds open ports on a known host; udp only when "
        "UDP services are suspected (slow). service_detection identifies what's running. "
        "Narrow 'ports' when you already know what you're after — far faster than all ports. "
        "syn and os_detection need root; use connect otherwise.\n"
        "Examples:\n"
        "  enumerate subnet -> {target:'10.0.0.0/24', scan_type:'ping_sweep'}\n"
        "  profile a host   -> {target:'10.0.0.5', scan_type:'connect', service_detection:true}\n"
        "  check web ports  -> {target:'10.0.0.5', ports:'80,443,8080'}"
    )

    SCAN_FLAGS = {
        "ping_sweep": ["-sn"],
        "connect": ["-sT"],
        "syn": ["-sS"],
        "udp": ["-sU"],
    }

    def run(self, target, scan_type="connect", ports=None,
            service_detection=False, os_detection=False,
            skip_host_discovery=False, timing=3):

        if not self._valid_target(target):
            return f"Refused: '{target}' is not a valid host/CIDR/range."
        if scan_type not in self.SCAN_FLAGS:
            return f"Refused: unknown scan_type '{scan_type}'."
        if not 0 <= int(timing) <= 5:
            return "Refused: timing must be 0-5."

        argv = ["nmap", *self.SCAN_FLAGS[scan_type], f"-T{int(timing)}"]
        if ports and scan_type != "ping_sweep":
            if not re.fullmatch(r"[0-9,\-]+", ports):
                return f"Refused: invalid port spec '{ports}'."
            argv += ["-p", ports]
        if service_detection:
            argv.append("-sV")
        if os_detection:
            argv.append("-O")
        if skip_host_discovery:
            argv.append("-Pn")
        argv.append(target)

        try:
            r = subprocess.run(argv, capture_output=True, text=True,
                               check=True, timeout=600)
            return r.stdout
        except subprocess.CalledProcessError as e:
            return f"nmap failed: {e.stderr}"
        except subprocess.TimeoutExpired:
            return "nmap timed out after 600s — narrow the target or ports."

    @staticmethod
    def _valid_target(t):
        try:
            ipaddress.ip_network(t, strict=False)
            return True
        except ValueError:
            return bool(t) and not any(c in t for c in " ;|&$")