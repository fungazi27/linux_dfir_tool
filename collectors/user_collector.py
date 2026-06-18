from pathlib import Path
from typing import Any, Dict, List

PASSWD_FILE = ("/etc/passwd")
GROUP_FILE = ("/etc/group")

LOGIN_SHELLS = {
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/bin/dash",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/usr/bin/zsh",
}

def collect_users() -> Dict[str,Any]:
    """Collect Linux local user and group information."""
    users = _parse_passwd()
    groups = _parse_group()

    return {
        "users": users,
        "groups": groups,
        "uid_0_users": _find_uid_0_users(users),
        "sudo_group_members": _find_group_members(groups,"sudo"),
        "wheel_group_members": _find_group_members(groups, "wheel"),
    }

def _parse_passwd() -> List[Dict[str, Any]]:
    users = []

    if not PASSWD_FILE.exists():
        return users
    
    with PASSWD_FILE.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue
        
            parts = line.split(":")

            if len(parts) != 7:
                continue

            username, _, uid, gid, comment, home, shell = parts

            users.append(
                {
                    "username": username,
                    "uid": int(uid),
                    "gid": int(gid),
                    "comment": comment,
                    "home": home,
                    "shell": shell,
                }
            )
    
    return users

def _parse_group() -> List[Dict[str, Any]]:
    groups = []

    if not GROUP_FILE.exists():
        return groups

    with GROUP_FILE.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            parts = line.split(":")

            if len(parts) != 4:
                continue

            group_name, _, gid, members = parts

            groups.append(
                {
                    "group_name": group_name,
                    "gid": int(gid),
                    "members": [m for m in members.split(",") if m],
                }
            )

    return groups


def _find_uid_0_users(users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [user for user in users if user.get("uid") == 0]


def _find_login_shell_users(users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        user
        for user in users
        if user.get("shell") in LOGIN_SHELLS
    ]


def _find_group_members(
    groups: List[Dict[str, Any]],
    group_name: str,
) -> List[str]:
    for group in groups:
        if group.get("group_name") == group_name:
            return group.get("members", [])

    return []