import os
import platform
import sys
import traceback
from pathlib import Path

# Run from project root so imports and assets resolve regardless of CWD
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))
os.chdir(_PROJECT_ROOT)
os.environ.setdefault("RUN_TK_DESKTOP_DIR", str(_PROJECT_ROOT))


def _gui_excepthook(exc_type, exc_value, exc_tb):
    """Log unhandled exceptions and show a messagebox to avoid silent exit."""
    try:
        from services.structured_logger import get_logger
        logger = get_logger()
        logger.error(
            "Unhandled exception: %s\n%s",
            exc_value,
            "".join(traceback.format_exception(exc_type, exc_value, exc_tb)),
        )
    except Exception:
        traceback.print_exc()
    try:
        from tkinter import messagebox
        messagebox.showerror(
            "Unexpected Error",
            "An unexpected error occurred. See the log file for details.",
        )
    except Exception:
        pass


if __name__ == "__main__":
    sys.excepthook = _gui_excepthook
    if platform.system() == "Windows":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    from desktop_tkinter_app import main
    main()