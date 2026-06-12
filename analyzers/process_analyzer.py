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

def analyze_processes(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Analyze process data and return suspicious findings."""
    findings = []

    for proc in processes:
        findings.extend(_check_temp_path_execution(proc))
        findings.extend(_check_suspicious_command_patterns(proc))

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