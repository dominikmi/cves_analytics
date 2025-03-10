import datetime
import traceback
import functools
import logging

# Configure logging with timestamps
logging.basicConfig(
    level=logging.ERROR, 
    format="%(asctime)s - %(levelname)s - %(message)s", 
    datefmt="%Y-%m-%d %H:%M:%S"
)

def error_handler(default_return=None):
    """
    A decorator to handle errors in functions, logging the issue and returning a sane error message.

    :param default_return: The value to return when an exception occurs.
                           If None specified, returns a standardized error response.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Capture current timestamp
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # function details
                func_name = func.__name__
                func_args = f"Args: {args}, Kwargs: {kwargs}"

                # Get me exact file and line where error happened
                error_trace = traceback.extract_tb(e.__traceback__)[-1]
                file_name, line_number, _, _ = error_trace

                # Log detailed error info with timestamp
                logging.error(f"[{timestamp}] Error in {func_name} at {file_name}, line {line_number}: {e}")
                logging.error(f"[{timestamp}] Function call details: {func_args}")

                # Friendly structured error message
                return default_return if default_return is not None else {
                    "error": f"Ooops, something's gone wrong in {func_name} at {file_name}, line {line_number}.",
                    "timestamp": timestamp,
                    "details": str(e)
                }
        return wrapper
    return decorator
