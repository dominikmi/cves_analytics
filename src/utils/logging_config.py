"""Centralized logging configuration."""

import logging


def get_logger(name: str) -> logging.Logger:
    """Return a logger by name.

    Args:
        name: Logger name (typically __name__).

    Returns:
        Configured logger instance.
    """
    return logging.getLogger(name)
