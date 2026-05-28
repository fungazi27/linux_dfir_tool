# Linux Incident Response / Threat Hunting Toolkit

A Python-based Linux endpoint triage and forensic collection toolkit for SOC analysts, incident responders, and threat hunters.

## Features

- Process analysis
- Network connection analysis
- Persistence hunting
- User/account auditing
- Authentication log analysis
- Cron and systemd detection
- File system triage
- IOC scanning
- Timeline generation
- Suspicious behavior scoring
- MITRE ATT&CK mapping
- JSON, CSV, and HTML reports

## Supported Platforms

- Ubuntu
- Debian
- More Linux distributions planned

## Installation

```bash
git clone https://github.com/yourusername/linux-ir-toolkit.git
cd linux-ir-toolkit
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
