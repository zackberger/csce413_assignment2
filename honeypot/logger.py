"""Logging helpers for the honeypot."""

import logging
import os
from logging.handlers import RotatingFileHandler

DEFAULT_LOG_PATH = "/app/logs/honeypot.log"


def create_logger(name: str = "Honeypot", log_path: str = DEFAULT_LOG_PATH) -> logging.Logger:
    """
    Create a logger that writes to both a rotating file and stdout.

    - Rotates at 1MB with 3 backups (prevents infinite growth).
    - Format includes timestamp, level, message.
    """
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.propagate = False  # avoid duplicate logs if root logger exists

    # Prevent duplicate handlers if create_logger is called twice
    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    file_handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3)
    file_handler.setFormatter(fmt)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

    return logger
