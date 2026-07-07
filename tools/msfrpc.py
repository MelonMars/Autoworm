import os
import json

_client = None


def get_client():
    global _client
    if _client is not None:
        return _client

    from pymetasploit3.msfrpc import MsfRpcClient

    host = os.environ.get("MSFRPC_HOST", "localhost")
    port = int(os.environ.get("MSFRPC_PORT", "55553"))
    user = os.environ.get("MSFRPC_USER", "msf")
    password = os.environ.get("MSFRPC_PASS", "password")

    try:
        _client = MsfRpcClient(
            password,
            host=host,
            port=port,
            username=user,
        )
        _client.modules.search("")
        return _client
    except Exception as exc:
        _client = None
        raise ConnectionError(
            f"Failed to connect to msfrpcd at {host}:{port}: {exc}"
        ) from exc


def reset_client():
    global _client
    _client = None


def rpc_result_dict(data: dict, cmd_desc: str = "") -> dict:
    raw = json.dumps(data, default=str) if not isinstance(data, str) else data
    return {
        "cmd": cmd_desc,
        "code": 0,
        "stdout": raw,
        "stderr": "",
    }
