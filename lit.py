import argparse
import platform

from rich.console import Console

from utils.config_loader import load_config
from utils.file_utils import create_case_directory, write_json
from utils.logger import setup_logger
from utils.time_utils import utc_now_iso

from collectors.process_collector import collect_processes
from collectors.network_collector import collect_network_connections
from collectors.user_collector import collect_users
from collectors.auth_collector import collect_authentication_data

from analyzers.process_analyzer import analyze_processes
from analyzers.network_analyzer import analyze_network_connections
from analyzers.auth_analyzer import analyze_authentication


console = Console()


def collect_command(args):
    config = load_config()

    case_dir = create_case_directory(args.output)
    logger = setup_logger(
        case_dir / "logs", 
        config["logging"]["level"]
    )

    logger.info("Starting Linux IR collection")

    metadata = {
        "tool": config["tool"],
        "collection_started_utc": utc_now_iso(),
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "output_directory": str(case_dir),
    }

    metadata_path = case_dir / "raw" / "metadata.json"
    write_json(metadata_path, metadata)

    #------------------------------------
    # Process Collection
    #------------------------------------

    processes = collect_processes()

    processes_path = case_dir / "raw" / "processes.json"

    write_json(
        processes_path, 
        {"processes": processes}
    )
    
    logger.info(f"Collected {len(processes)} running processes")

    #------------------------------------
    # Network Collection
    #------------------------------------

    network_connections = collect_network_connections()

    network_path = (
        case_dir / "raw" / "network_connections.json"
    )

    write_json(
        network_path,
        {"connections": network_connections}
    )

    logger.info(
        f"Collected {len(network_connections)} network connections"
    )

    console.print(
        "[bold green]Collection initialized successfully.[/bold green]"
    )

    console.print(
        f"Output directory: {case_dir}"
    )

    #---------------------------------------
    # User Collection
    #---------------------------------------

    user_data = collect_users()

    users_path = (
        case_dir / "raw" / "users.json"
    )

    write_json(
        users_path,
        user_data
    )

    logger.info(
        f"Collected {len(user_data.get('users', []))} local users"
    )

    #---------------------------------------
    # Authentication Collection
    #---------------------------------------

    authentication_data = collect_authentication_data()

    authentication_path = (
        case_dir / "raw" / "authentication.json"
    )

    write_json(
        authentication_path,
        authentication_data
    )

    logger.info("Collected authentication artifacts")

    #---------------------------------------
    # Analysis
    #---------------------------------------

    findings = []
    
    findings.extend(
        analyze_network_connections(
            network_connections,
            processes
        )
    )

    findings.extend(
        analyze_authentication(
            authentication_data
        )
    )

    findings_path = (
        case_dir / "reports" / "findings.json"
    )

    write_json(
        findings_path,
        {"findings": findings}
    )

    logger.info(
        f"Generated {len(findings)} total findings"
    )

def build_parser():
    parser = argparse.ArgumentParser(
        description="Linux Incident Response / Threat Hunting Toolkit"
    )

    subparsers = parser.add_subparsers(dest="command")

    collect_parser = subparsers.add_parser(
        "collect",
        help="Collect Linux host artifacts"
    )

    collect_parser.add_argument(
        "--output",
        required=True,
        help="Output directory for case collection"
    )

    collect_parser.set_defaults(func=collect_command)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()