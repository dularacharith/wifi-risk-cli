import shutil
import subprocess
from typing import Any


def is_tool_available(tool_name: str) -> bool:
    """
    Check if an external tool is available in the system PATH.
    """
    return shutil.which(tool_name) is not None


def run_command_safe(args: list[str], timeout: int = 20) -> dict[str, Any]:
    """
    Safely execute an external CLI command with timeout and error handling.
    """
    tool_name = args[0] if args else ""
    if not is_tool_available(tool_name):
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"Tool '{tool_name}' is not installed or not in PATH.",
        }

    try:
        process = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return {
            "success": process.returncode == 0,
            "returncode": process.returncode,
            "stdout": process.stdout,
            "stderr": process.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout} seconds.",
        }
    except Exception as exc:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": f"Execution error: {exc}",
        }
