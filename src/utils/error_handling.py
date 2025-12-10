"""Standardized error handling for CVEs Analytics."""

import functools
import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class CVEsAnalyticsError(Exception):
    """Base exception for all CVEs Analytics errors."""

    pass


class DataValidationError(CVEsAnalyticsError):
    """Raised when data validation fails."""

    pass


class ConfigurationError(CVEsAnalyticsError):
    """Raised when configuration is invalid."""

    pass


def error_handler(default_return: Any = None, raise_on_error: bool = False):
    """
    Decorator for standardized error handling.

    Args:
        default_return: Value to return if an error occurs
        raise_on_error: Whether to re-raise the exception
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except CVEsAnalyticsError:
                # Re-raise our custom exceptions
                if raise_on_error:
                    raise
                logger.error(f"Known error in {func.__name__}", exc_info=True)
                return default_return
            except Exception as e:
                # Handle unexpected exceptions
                logger.error(f"Unexpected error in {func.__name__}: {e}", exc_info=True)
                if raise_on_error:
                    raise
                return default_return

        return wrapper

    return decorator
