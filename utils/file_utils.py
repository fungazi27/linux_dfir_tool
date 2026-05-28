import json
from pathlib import Path
from typing import Any, Dict

def create_case_directory(output_path: str) -> Path:
    """Create and return the case output directory"""
    case_dir = Path(output_path)
    case_dir.mkdir(parents=True, exist_ok=True)

    (case_dir / "raw").mkdir(exist_ok=True)
    (case_dir / "reports").mkdir(exist_ok=True)
    (case_dir / "logs").mkdir(exist_ok=True)

    return case_dir

def write_json(file_path: Path, data:Dict[str, any]) -> None:
    """Write dictionary data to a JSON file"""
    with file_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)