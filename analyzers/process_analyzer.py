from typing import Any, Dict, List

SUSPICIOUS_TEMP_PATHS = [
    "/tmp/",
    "/vat/tmp/",
    "/dev/shm/",
]

SUSPICIOUS_COMMAND_PATTERNS = [
    "curl | bash",
    "curl|bash",
    "wget | sh",
    "wget|sh",
    "/dev/tcp",
    "base64 -d",
    "base64 --decode",
    "nc -e",
    "ncat -e",
    "socat",
]

SUSPICIOUS_TOOLS = [
    "nc",
    "ncat",
    "netcat",
    "socat",
    "curl",
    "wget",
    "python",
    "python3",
    "perl",
    "ruby",
    "php",
]

UNUSUAL_ROOT_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
    "/home/",
]

def analyze_processes(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze process data and return suspicious findings."""
    findings = []

    for proc in processes:
        findings.extend(_check_temp_path_execution(proc))
        findings.extend(_check_suspicious_command_patterns(proc))
        findings.extend(_check_suspicious_tools(proc))
        findings.extend(_check_shell_network_behavior(proc))
        findings.extend(_check_root_unusual_path(proc))

    return findings


def _check_temp_path_execution(proc: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    exe = proc.get("exe") or ""

    for path in SUSPICIOUS_TEMP_PATHS:
        if exe.startswith(path):
            findings.append(
                {
                    "finding_id": "PROC-001",
                    "title": "Process executing from temporary directory",
                    "severity": "high",
                    "category": "process",
                    "mitre_technique": "T1059",
                    "mitre_tactic": "Execution",
                    "description": (
                        "A running process is executing from a temporary directory. "
                        "Malware and post-exploitation tools commonly run from temporary paths."
                    ),
                    "evidence": {
                        "pid": proc.get("pid"),
                        "ppid": proc.get("ppid"),
                        "name": proc.get("name"),
                        "username": proc.get("username"),
                        "exe": proc.get("exe"),
                        "cmdline": proc.get("cmdline"),
                    },
                    "recommendation": (
                        "Review the process, parent process, executable hash, "
                        "and network activity. Consider isolating the host if malicious."
                    ),
                }
            )

    return findings


def _check_suspicious_command_patterns(proc: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    cmdline = (proc.get("cmdline") or "").lower()

    for pattern in SUSPICIOUS_COMMAND_PATTERNS:
        if pattern in cmdline:
            findings.append(
                {
                    "finding_id": "PROC-002",
                    "title": "Suspicious command-line pattern detected",
                    "severity": "medium",
                    "category": "process",
                    "mitre_technique": "T1059",
                    "mitre_tactic": "Execution",
                    "description": (
                        "A running process contains a command-line pattern commonly "
                        "associated with suspicious script execution or post-exploitation activity."
                    ),
                    "evidence": {
                        "pid": proc.get("pid"),
                        "ppid": proc.get("ppid"),
                        "name": proc.get("name"),
                        "username": proc.get("username"),
                        "exe": proc.get("exe"),
                        "cmdline": proc.get("cmdline"),
                        "matched_pattern": pattern,
                    },
                    "recommendation": (
                        "Review the command line, process lineage, user context, "
                        "and whether this activity was expected."
                    ),
                }
            )

    return findings

def _check_suspicious_tools(proc: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    name = (proc.get("name") or "").lower()
    cmdline = (proc.get("cmdline") or "").lower()

    for tool in SUSPICIOUS_TOOLS:
        if name == tool or f" {tool} " in f" {cmdline} ":
            findings.append(
                {
                    "finding_id": "PROC-003",
                    "title": "Suspicious tool detected in process list",
                    "severity": "low",
                    "category": "process",
                    "mitre_technique": "T1059",
                    "mitre_tactic": "Execution",
                    "description": "A process is using a tool commonly abused during post-exploitation.",
                    "evidence": {
                        "pid": proc.get("pid"),
                        "name": proc.get("name"),
                        "username": proc.get("username"),
                        "exe": proc.get("exe"),
                        "cmdline": proc.get("cmdline"),
                        "matched_tool": tool,
                    },
                    "recommendation": "Validate whether this tool usage is expected for this host and user.",
                }
            )

    return findings


def _check_shell_network_behavior(proc: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    cmdline = (proc.get("cmdline") or "").lower()

    shell_indicators = ["bash", "sh", "zsh"]
    network_indicators = ["/dev/tcp", "nc ", "ncat ", "socat"]

    if any(shell in cmdline for shell in shell_indicators) and any(
        net in cmdline for net in network_indicators
    ):
        findings.append(
            {
                "finding_id": "PROC-004",
                "title": "Shell process with network behavior",
                "severity": "high",
                "category": "process",
                "mitre_technique": "T1059",
                "mitre_tactic": "Execution",
                "description": "A shell process appears to include network-related behavior, which may indicate a reverse shell.",
                "evidence": {
                    "pid": proc.get("pid"),
                    "name": proc.get("name"),
                    "username": proc.get("username"),
                    "exe": proc.get("exe"),
                    "cmdline": proc.get("cmdline"),
                },
                "recommendation": "Investigate immediately. Review parent process, network connections, and user context.",
            }
        )

    return findings


def _check_root_unusual_path(proc: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    username = proc.get("username") or ""
    exe = proc.get("exe") or ""

    if username == "root":
        for path in UNUSUAL_ROOT_PATHS:
            if exe.startswith(path):
                findings.append(
                    {
                        "finding_id": "PROC-005",
                        "title": "Root process executing from unusual path",
                        "severity": "high",
                        "category": "process",
                        "mitre_technique": "T1059",
                        "mitre_tactic": "Execution",
                        "description": "A root-owned process is executing from a path commonly associated with temporary or user-controlled files.",
                        "evidence": {
                            "pid": proc.get("pid"),
                            "name": proc.get("name"),
                            "username": proc.get("username"),
                            "exe": proc.get("exe"),
                            "cmdline": proc.get("cmdline"),
                        },
                        "recommendation": "Review whether the binary is legitimate. Hash the executable and inspect related network activity.",
                    }
                )

    return findings