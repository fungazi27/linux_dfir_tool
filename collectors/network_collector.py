from typing import Any, Dict, List

import psutil

def collect_network_connections() -> List[Dict[str, Any]]:
    """Collect network connections"""

    connections = []

    for conn in psutil.net_connections(kind="inet"):

        try:
            local_addr = ""
            remote_addr = ""

            if conn.laddr:
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"

            if conn.raddr:
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"

            process_name = None

            if conn.pid:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except Exception:
                    process_name = None

            connections.append(
                {
                    "pid": conn.pid,
                    "process_name": process_name,
                    "family": str(conn.family),
                    "type": str(conn.type),
                    "status": conn.status,
                    "local_address": local_addr,
                    "remote_address": remote_addr,
                }
            )
        except Exception:
            continue

    return connections