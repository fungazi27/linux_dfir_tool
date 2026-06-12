from typing import Any, Dict, List

import psutil

def collect_processes() -> List[Dict[str, Any]]:
    """Collect running process information from the Linux Host"""
    processes = []

    for proc in psutil.process_iter(
        attrs=[
            "pid",
            "ppid",
            "name",
            "username",
            "exe",
            "cmdline",
            "status",
            "create_time",
        ]
    ):
        try:
            info = proc.info

            processes.append(
                {
                    "pid": info.get("pid"),
                    "ppid": info.get("ppid"),
                    "name": info.get("name"),
                    "username": info.get("username"),
                    "exe": info.get("exe"),
                    "cmdline": " ".join(info.get("cmdline") or []),
                    "status": info.get("status"),
                    "create_time": info.get("create_time"),
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    
    return processes