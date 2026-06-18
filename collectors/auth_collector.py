import subprocess
from pathlib import Path
from typing import Any, Dict, List

AUTH_LOG_PATHS = [
    Path("/var/log/auth.log"),
    Path("/var/log/auth.log.1"),
]

def collect_authentication_data() -> Dict[str, Any]:
    """Collect Linux authentication-related artifacts."""
    return {
        "auth_logs": _collect_auth_logs(),
        "last_logins": _run_command(["last", "-F", "-w"]),
        "failed_logins": _run_command(["lastb", "-F", "-w"]),
    }

def _collect_auth_logs() -> List[Dict[str, Any]]:
    logs = []

    for path in AUTH_LOG_PATHS:
        if not path.exists():
            continue

        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                logs.append(
                    {
                        "path": str(path),
                        "lines": f.readlines(),
                    }
                )
        except PermissionError:
            logs.append(
                {
                    "path": str(path),
                    "error": "permission_denied",
                    "lines": [],
                }
            )
    
    return logs

def _run_command(command: List[str]) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        return {
            "command": " ". join(command),
            "returncode": result.returncode,
            "stdout": result.stdout.splitlines(),
            "stderr": result.stderr.splitlines(),
        }
    
    except FileNotFoundError:
        return {
            "command": " ".join(command),
            "error": "command_not_found",
            "stdout": [],
            "stderr": []
        }
    
    except subprocess.TimeoutExpired:
        return {
            "command": " ".join(command),
            "error": "timeout",
            "stdout": [],
            "stderr": []
        }