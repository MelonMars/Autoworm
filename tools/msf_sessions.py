from tools.registry import register
from tools.base import Tool, Param
from tools.msfrpc import get_client, reset_client

import json
import time


def run_session_command(session_id: str, command: str, foothold_type: str) -> dict:
    if foothold_type == "meterpreter":
        command = f"shell {command}"
    return _msf_sessions_execute({
        "action": "write_and_read",
        "session_id": session_id,
        "command": command,
    })


def parse_session_output(result: dict) -> str:
    if not result or result.get("code") != 0:
        return (result or {}).get("stderr", "")
    try:
        data = json.loads(result.get("stdout", ""))
        return str(data.get("output", ""))
    except (json.JSONDecodeError, TypeError):
        return result.get("stdout", "")


def _msf_sessions_execute(args: dict) -> dict:
    action = args["action"]

    try:
        client = get_client()
    except ConnectionError as exc:
        return {"cmd": f"msf_sessions:{action}",
                "code": 1, "stdout": "", "stderr": str(exc)}

    try:
        if action == "list":
            sessions = client.sessions.list
            output = {
                "action": "list",
                "sessions": {
                    sid: {
                        "type": info.get("type", "unknown"),
                        "tunnel_local": info.get("tunnel_local", ""),
                        "tunnel_peer": info.get("tunnel_peer", ""),
                        "via_payload": info.get("via_payload", ""),
                        "platform": info.get("platform", ""),
                        "workspace": info.get("workspace", ""),
                    }
                    for sid, info in sessions.items()
                },
                "count": len(sessions),
            }
            return {"cmd": f"msf_sessions:list",
                    "code": 0, "stdout": json.dumps(output, default=str), "stderr": ""}

        elif action == "write":
            session_id = args.get("session_id")
            command = args.get("command", "")

            if not session_id:
                return {"cmd": f"msf_sessions:write",
                        "code": 1, "stdout": "", "stderr": "session_id is required for write action"}

            session = client.sessions.session(int(session_id))
            session.write(command)

            time.sleep(1)

            output_data = {
                "action": "write",
                "session_id": str(session_id),
                "command": command,
                "status": "written",
            }

            return {"cmd": f"msf_sessions:write:{session_id}",
                    "code": 0, "stdout": json.dumps(output_data), "stderr": ""}

        elif action == "read":
            session_id = args.get("session_id")

            if not session_id:
                return {"cmd": f"msf_sessions:read",
                        "code": 1, "stdout": "", "stderr": "session_id is required for read action"}

            session = client.sessions.session(int(session_id))

            if hasattr(session, 'gather_output') and callable(session.gather_output):
                output = session.gather_output()
            elif hasattr(session, 'read') and callable(session.read):
                output = session.read()
            else:
                output = "(no output method available for this session type)"

            output_data = {
                "action": "read",
                "session_id": str(session_id),
                "output": str(output),
            }
            return {"cmd": f"msf_sessions:read:{session_id}",
                    "code": 0, "stdout": json.dumps(output_data, default=str), "stderr": ""}

        elif action == "write_and_read":
            session_id = args.get("session_id")
            command = args.get("command", "")

            if not session_id or not command:
                return {"cmd": f"msf_sessions:write_and_read",
                        "code": 1, "stdout": "",
                        "stderr": "session_id and command are required for write_and_read action"}

            session = client.sessions.session(int(session_id))
            session.write(command)
            time.sleep(2)

            if hasattr(session, 'gather_output') and callable(session.gather_output):
                output = session.gather_output()
            elif hasattr(session, 'read') and callable(session.read):
                output = session.read()
            else:
                output = "(no output method available)"

            output_data = {
                "action": "write_and_read",
                "session_id": str(session_id),
                "command": command,
                "output": str(output),
            }
            return {"cmd": f"msf_sessions:write_and_read:{session_id}",
                    "code": 0, "stdout": json.dumps(output_data, default=str), "stderr": ""}

        elif action == "close":
            session_id = args.get("session_id")

            if not session_id:
                return {"cmd": f"msf_sessions:close",
                        "code": 1, "stdout": "", "stderr": "session_id is required for close action"}

            session = client.sessions.session(int(session_id))
            if hasattr(session, 'kill'):
                session.kill()
            elif hasattr(session, 'stop'):
                session.stop()

            output_data = {
                "action": "close",
                "session_id": str(session_id),
                "status": "closed",
            }
            return {"cmd": f"msf_sessions:close:{session_id}",
                    "code": 0, "stdout": json.dumps(output_data), "stderr": ""}

        else:
            return {"cmd": f"msf_sessions:{action}",
                    "code": 1, "stdout": "", "stderr": f"Unknown action: {action}"}

    except Exception as exc:
        reset_client()
        return {"cmd": f"msf_sessions:{action}",
                "code": 1, "stdout": "", "stderr": str(exc)}


msf_sessions = register(Tool(
    name="msf_sessions",
    description=(
        "Interact with active Metasploit sessions (Meterpreter or shell) via RPC. "
        "Actions: 'list' shows all active sessions with their IDs, types, and tunnel info. "
        "'write' sends a command to a session. 'read' reads buffered output from a session. "
        "'write_and_read' sends a command then waits and reads the output (most useful). "
        "'close' terminates a session. "
        "Use 'write_and_read' for executing commands on compromised hosts through MSF sessions."
    ),
    params=[
        Param("action", "string", "Action to perform on sessions.",
              enum=["list", "write", "read", "write_and_read", "close"]),
        Param("session_id", "string",
              "Session ID to interact with (required for write/read/close).",
              required=False),
        Param("command", "string",
              "Command to execute in the session (required for write and write_and_read).",
              required=False),
    ],
    execute_fn=_msf_sessions_execute,
    category=["foothold"],
    examples=[
        'List all active Metasploit sessions',
        'Write "whoami" to session 1 and read output',
        'Close session 1',
    ],
))
