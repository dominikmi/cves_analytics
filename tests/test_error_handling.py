"""Tests for error handling module."""

import unittest

from src.utils.error_handling import CVEsAnalyticsError, error_handler


class TestErrorHandler(unittest.TestCase):
    """Test cases for error_handler decorator."""

    def test_error_handler_successful_function(self):
        """Test error_handler with successful function."""

        @error_handler()
        def successful_function():
            return "success"

        result = successful_function()
        self.assertEqual(result, "success")

    def test_error_handler_with_exception_returns_default(self):
        """Test error_handler catches exceptions and returns default."""

        @error_handler(default_return="error_result")
        def failing_function():
            raise ValueError("Test error")

        result = failing_function()
        self.assertEqual(result, "error_result")

    def test_error_handler_with_default_return(self):
        """Test error_handler with default return value."""

        @error_handler(default_return="default")
        def failing_function():
            raise ValueError("Test error")

        result = failing_function()
        self.assertEqual(result, "default")

    def test_error_handler_preserves_function_name(self):
        """Test error_handler preserves function name."""

        @error_handler()
        def my_function():
            return "result"

        self.assertEqual(my_function.__name__, "my_function")

    def test_error_handler_with_arguments(self):
        """Test error_handler with function arguments."""

        @error_handler()
        def function_with_args(a, b):
            return a + b

        result = function_with_args(1, 2)
        self.assertEqual(result, 3)

    def test_error_handler_with_kwargs(self):
        """Test error_handler with keyword arguments."""

        @error_handler()
        def function_with_kwargs(a, b=10):
            return a + b

        result = function_with_kwargs(5, b=15)
        self.assertEqual(result, 20)

    def test_error_handler_with_none_default(self):
        """Test error_handler with None as default."""

        @error_handler(default_return=None)
        def failing_function():
            raise ValueError("Test error")

        result = failing_function()
        self.assertIsNone(result)

    def test_error_handler_custom_exception_not_raised_by_default(self):
        """Test error_handler with custom exception doesn't raise by default."""

        @error_handler(default_return="handled")
        def failing_function():
            raise CVEsAnalyticsError("Custom error")

        result = failing_function()
        self.assertEqual(result, "handled")

    def test_error_handler_can_raise_on_error(self):
        """Test error_handler can re-raise exceptions when configured."""

        @error_handler(raise_on_error=True)
        def failing_function():
            raise ValueError("Test error")

        with self.assertRaises(ValueError):
            failing_function()
