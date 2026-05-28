import logging
from pathlib import Path


def setup_logger(log_dir: Path, level: str = "INFO") -> logging.Logger:
    """Set up application logger."""
    log_file = log_dir / "lit.log"

    logger = logging.getLogger("linux-ir-toolkit")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    logger.handlers.clear()

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger