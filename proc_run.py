import subprocess

def run(argv, timeout=15):
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return {
            "code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except FileNotFoundError:
        missing_cmd = argv[0] if isinstance(argv, list) else argv
        return {
            "code": 127,
            "stdout": "",
            "stderr": f"Error: '{missing_cmd}' not found. Ensure it is installed and on PATH.",
        }
    except subprocess.TimeoutExpired:
        return {
            "code": 124,
            "stdout": "",
            "stderr": f"Error: Command '{argv[0]}' timed out after {timeout}s.",
        }
    except Exception as e:
        return {
            "code": 1,
            "stdout": "",
            "stderr": f"Error executing command: {e}",
        }
    