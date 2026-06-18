import re 
from collections import Counter
from typing import Any, Dict, List

FAILED_LOGIN_THRESHOLD = 5
SUDO_THRESHOLD = 20

def analyze_authentication(auth_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    findings.extend(
        _detect_failed_login_bursts(auth_data)
    )

    findings.extend(
        _detect_excessive_sudo_activity(auth_data)
    )

    return findings

def _detect_failed_login_bursts(
    auth_data: Dict[str, Any]
) -> List[Dict[str, Any]]:

    findings = []

    failure_counter = Counter()

    auth_logs = auth_data.get("auth_logs", [])

    for log in auth_logs:

        for line in log.get("lines", []):

            if "Failed password" not in line:
                continue

            match = re.search(
                r"from (\S+)",
                line
            )

            if match:
                ip = match.group(1)
                failure_counter[ip] += 1

    for ip, count in failure_counter.items():

        if count >= FAILED_LOGIN_THRESHOLD:

            findings.append(
                {
                    "finding_id": "AUTH-001",
                    "title": "Excessive Failed Login Attempts",
                    "severity": "high",
                    "category": "authentication",
                    "mitre_technique": "T1110",
                    "mitre_tactic": "Credential Access",
                    "description": (
                        f"{count} failed login attempts "
                        f"were observed from {ip}"
                    ),
                    "evidence": {
                        "source_ip": ip,
                        "failed_attempts": count,
                    },
                    "recommendation": (
                        "Investigate the source IP and "
                        "determine whether brute force "
                        "activity is occurring."
                    ),
                }
            )

    return findings

def _detect_excessive_sudo_activity(
    auth_data: Dict[str, Any]
) -> List[Dict[str, Any]]:

    findings = []

    sudo_counter = Counter()

    auth_logs = auth_data.get("auth_logs", [])

    for log in auth_logs:

        for line in log.get("lines", []):

            if "sudo:" not in line:
                continue

            match = re.search(
                r"sudo:\s+(\S+)",
                line
            )

            if match:
                user = match.group(1)
                sudo_counter[user] += 1

    for user, count in sudo_counter.items():

        if count >= SUDO_THRESHOLD:

            findings.append(
                {
                    "finding_id": "AUTH-002",
                    "title": "Excessive sudo Activity",
                    "severity": "medium",
                    "category": "authentication",
                    "mitre_technique": "T1548",
                    "mitre_tactic": "Privilege Escalation",
                    "description": (
                        f"User {user} executed sudo "
                        f"{count} times."
                    ),
                    "evidence": {
                        "user": user,
                        "sudo_count": count,
                    },
                    "recommendation": (
                        "Validate whether elevated "
                        "privilege usage is expected."
                    ),
                }
            )

    return findings