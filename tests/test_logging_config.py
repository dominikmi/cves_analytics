"""Tests for logging configuration module."""

import logging
import tempfile
from pathlib import Path

from src.utils.logging_config import get_logger, setup_logger


class TestLoggingConfig:
    """Test cases for logging configuration."""

    def test_setup_logger_creates_logger(self):
        """Test that setup_logger creates a logger."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger("test_logger", log_dir=tmpdir)

            assert logger is not None
            assert logger.name == "test_logger"
            assert logger.level == logging.DEBUG

    def test_setup_logger_creates_log_directory(self):
        """Test that setup_logger creates log directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "logs"
            setup_logger("test_logger", log_dir=str(log_dir))

            assert log_dir.exists()

    def test_setup_logger_has_handlers(self):
        """Test that setup_logger adds handlers."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger("test_logger", log_dir=tmpdir)

            assert len(logger.handlers) > 0

    def test_get_logger_returns_logger(self):
        """Test that get_logger returns a logger."""
        logger = get_logger("test_logger")

        assert logger is not None
        assert isinstance(logger, logging.Logger)

    def test_get_logger_same_name_returns_same_logger(self):
        """Test that get_logger returns same logger for same name."""
        logger1 = get_logger("test_logger")
        logger2 = get_logger("test_logger")

        assert logger1 is logger2

    def test_logger_can_log(self):
        """Test that logger can log messages."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger("test_logger", log_dir=tmpdir)

            # Should not raise exception
            logger.info("Test message")
            logger.warning("Test warning")
            logger.error("Test error")

    def test_logger_with_custom_level(self):
        """Test logger with custom level."""
        with tempfile.TemporaryDirectory() as tmpdir:
            logger = setup_logger("test_logger", log_dir=tmpdir, level=logging.WARNING)

            assert logger.level == logging.WARNING
