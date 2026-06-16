from typing import Any, Dict, List
import ipaddress


SUSPICIOUS_NETWORK_TOOLS = {
    "nc",
    "ncat",
    "netcat",
    "socat",
}

SHELL_PROCESSES = {
    "bash",
    "sh",
    "dash",
    "zsh",
}

SCRIPTING_PROCESSES = {
    "python",
    "python3",
    "perl",
    "php",
    "ruby",
}

UNUSUAL_EXEC_PATHS = (
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


def analyze_network_connections(
    connections: List[Dict[str, Any]],
    processes: List[Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    """Analyze network connections and return suspicious findings."""
    findings = []

    process_lookup = _build_process_lookup(processes or [])

    for conn in connections:
        enriched_conn = _enrich_connection_with_process(conn, process_lookup)

        findings.extend(_check_network_tool_activity(enriched_conn))
        findings.extend(_check_shell_network_activity(enriched_conn))
        findings.extend(_check_external_connection_from_unusual_path(enriched_conn))
        findings.extend(_check_external_connection_from_scripting_process(enriched_conn))

    return findings


def _build_process_lookup(
    processes: List[Dict[str, Any]]
) -> Dict[int, Dict[str, Any]]:
    """Build a PID-to-process lookup table."""
    lookup = {}

    for proc in processes:
        pid = proc.get("pid")

        if pid is not None:
            lookup[pid] = proc

    return lookup


def _enrich_connection_with_process(
    conn: Dict[str, Any],
    process_lookup: Dict[int, Dict[str, Any]],
) -> Dict[str, Any]:
    """Add process metadata to a network connection when available."""
    enriched = dict(conn)

    pid = conn.get("pid")
    process = process_lookup.get(pid, {})

    enriched["process_exe"] = process.get("exe")
    enriched["process_cmdline"] = process.get("cmdline")
    enriched["process_username"] = process.get("username")

    return enriched


def _extract_ip(address: str) -> str:
    """Extract IP from ip:port style address."""
    if not address:
        return ""

    if address.startswith("["):
        return address.split("]")[0].lstrip("[")

    if ":" not in address:
        return ""

    return address.rsplit(":", 1)[0]


def _is_external_ip(ip: str) -> bool:
    """Return True if IP is public/external."""
    if not ip:
        return False

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return not (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def _has_external_remote(conn: Dict[str, Any]) -> bool:
    remote_address = conn.get("remote_address") or ""
    remote_ip = _extract_ip(remote_address)

    return _is_external_ip(remote_ip)


def _check_network_tool_activity(
    conn: Dict[str, Any]
) -> List[Dict[str, Any]]:
    findings = []

    process_name = (conn.get("process_name") or "").lower()
    status = conn.get("status")

    if status not in {"ESTABLISHED", "LISTEN"}:
        return findings

    if process_name in SUSPICIOUS_NETWORK_TOOLS:
        findings.append(
            {
                "finding_id": "NET-001",
                "title": "Network utility with active connection",
                "severity": "high",
                "category": "network",
                "mitre_technique": "T1105",
                "mitre_tactic": "Command and Control",
                "description": (
                    "A network utility commonly abused for reverse shells, "
                    "file transfer, or tunneling has active network activity."
                ),
                "evidence": conn,
                "recommendation": (
                    "Validate whether this network utility is expected. "
                    "Review parent process, command line, and remote destination."
                ),
            }
        )

    return findings


def _check_shell_network_activity(
    conn: Dict[str, Any]
) -> List[Dict[str, Any]]:
    findings = []

    process_name = (conn.get("process_name") or "").lower()
    cmdline = (conn.get("process_cmdline") or "").lower()
    status = conn.get("status")

    if status not in {"ESTABLISHED", "LISTEN"}:
        return findings

    if process_name in SHELL_PROCESSES or any(shell in cmdline for shell in SHELL_PROCESSES):
        if _has_external_remote(conn) or "/dev/tcp" in cmdline:
            findings.append(
                {
                    "finding_id": "NET-002",
                    "title": "Shell process with network activity",
                    "severity": "high",
                    "category": "network",
                    "mitre_technique": "T1059",
                    "mitre_tactic": "Execution",
                    "description": (
                        "A shell process appears to have network activity. "
                        "This may indicate reverse shell or hands-on-keyboard activity."
                    ),
                    "evidence": conn,
                    "recommendation": (
                        "Investigate immediately. Review command line, user context, "
                        "remote address, and process lineage."
                    ),
                }
            )

    return findings


def _check_external_connection_from_unusual_path(
    conn: Dict[str, Any]
) -> List[Dict[str, Any]]:
    findings = []

    exe = conn.get("process_exe") or ""
    status = conn.get("status")

    if status != "ESTABLISHED":
        return findings

    if not _has_external_remote(conn):
        return findings

    if exe.startswith(UNUSUAL_EXEC_PATHS):
        findings.append(
            {
                "finding_id": "NET-003",
                "title": "External connection from unusual executable path",
                "severity": "high",
                "category": "network",
                "mitre_technique": "T1071",
                "mitre_tactic": "Command and Control",
                "description": (
                    "A process executing from a temporary or memory-backed path "
                    "has an established external network connection."
                ),
                "evidence": conn,
                "recommendation": (
                    "Review the binary, hash the executable, inspect persistence, "
                    "and validate whether the remote destination is legitimate."
                ),
            }
        )

    return findings


def _check_external_connection_from_scripting_process(
    conn: Dict[str, Any]
) -> List[Dict[str, Any]]:
    findings = []

    process_name = (conn.get("process_name") or "").lower()
    status = conn.get("status")

    if status != "ESTABLISHED":
        return findings

    if not _has_external_remote(conn):
        return findings

    if process_name in SCRIPTING_PROCESSES:
        findings.append(
            {
                "finding_id": "NET-004",
                "title": "Scripting process with external connection",
                "severity": "medium",
                "category": "network",
                "mitre_technique": "T1059",
                "mitre_tactic": "Execution",
                "description": (
                    "A scripting interpreter has an established connection to "
                    "an external IP address. This may be legitimate, but it is "
                    "also commonly seen during payload execution or automation abuse."
                ),
                "evidence": conn,
                "recommendation": (
                    "Validate the script, user context, command line, and remote destination."
                ),
            }
        )

    return findings