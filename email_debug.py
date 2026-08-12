"""Small helpers for retaining email-tool output when debugging is useful."""

from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path


def save_email_tool_debug_output(tool, target, stdout="", stderr=""):
    """
    Save the latest diagnostic output for a tool/target pair.

    The target is hashed so email addresses are not placed in filenames.  A
    failure to write diagnostics must never change the investigation result.
    """

    try:
        project_dir = Path(__file__).resolve().parent
        debug_dir = project_dir / "logs" / "email"
        debug_dir.mkdir(parents=True, exist_ok=True)

        target_hash = sha256(target.encode("utf-8")).hexdigest()[:12]
        path = debug_dir / f"{tool.lower()}_{target_hash}.txt"

        timestamp = datetime.now(timezone.utc).isoformat()
        content = (
            f"Captured: {timestamp}\n"
            f"Tool: {tool}\n\n"
            "===== STDOUT =====\n"
            f"{stdout or ''}\n\n"
            "===== STDERR =====\n"
            f"{stderr or ''}\n"
        )

        path.write_text(content, encoding="utf-8", errors="replace")
        return str(path)

    except OSError:
        return None
