import ctypes
import csv
import datetime
import json
import os
import platform
import secrets
import subprocess
import sys
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path

from services.app_paths import config_path, keys_dir
from tkinter import filedialog, messagebox, simpledialog, ttk

from services.api import VaultAPI
from services.crypto_utils import CryptoUtils
from services.extension_server import ExtensionServer
from services.platform_utils import open_folder as platform_open_folder
from services.local_key_manager import LocalKeyManager
from services.sync_service import SyncService
from services.structured_logger import get_logger
from services.session_security_service import (
    SessionSecurityService,
    verify_step_up_identity_app_password,
)
from services.security_alert_service import (
    SecurityAlertService,
    SEVERITY_CRITICAL,
    SEVERITY_INFO,
    SEVERITY_WARNING,
)
from services.status_bus import get_bus, StatusContext
from config.design_tokens import THEMES, STRENGTH_COLOURS, STRENGTH_LABELS, get_theme


class VaultTkApp:
    # Constants for magic numbers
    DEFAULT_CLIPBOARD_CLEAR_SECONDS = 20
    DEFAULT_IDLE_TIMEOUT_MINUTES = 5
    DEFAULT_IDLE_TIMEOUT_MS = DEFAULT_IDLE_TIMEOUT_MINUTES * 60 * 1000
    DEFAULT_UNDO_TIMEOUT_MS = 10_000
    MIN_CLIPBOARD_CLEAR_SECONDS = 1
    MIN_IDLE_TIMEOUT_MINUTES = 1
    HEALTH_CACHE_TTL_SECONDS = 45
    BACKUP_CRED_PROMPT_DELAY_MS = 30_000  # Prompt for backup credentials 30s after login/unlock
    
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Secure Vault Desktop")
        
        # Set window icon if available (prevents icon issues on some systems)
        try:
            # Try to set a default icon (this will fail gracefully if no icon file exists)
            pass  # Icon can be added later if needed
        except Exception:
            pass
        
        self.palette = get_theme("dark") # Temporary default until config loads
        self.root.configure(bg=self.palette["bg"])
        self.root.configure(highlightthickness=0)  # Prevent red focus border after unlock (Windows)
        
        # Ensure window is properly initialized before setting geometry
        self.root.update_idletasks()

        self.api = VaultAPI()
        self.security_alert_service = SecurityAlertService(
            audit=self.api.audit,
            publish_alert_to_ui=None,
            throttle_seconds=20,
        )
        self.api.security_alert_service = self.security_alert_service
        self.sync_service = SyncService(config_path=str(config_path("sync_config.json")))
        # Phase 6.5: on_request_denied_ui runs on main thread via after(); debounced; now routed through security_alert_service
        self._extension_denied_toast_last = {}  # reason -> timestamp
        self._EXTENSION_DENIED_DEBOUNCE_SEC = 60
        ext_host = os.environ.get("SECURECRYPT_EXTENSION_HOST", "127.0.0.1")
        self.extension_server = ExtensionServer(
            self.api,
            self._get_extension_session,
            host=ext_host,
            on_request_denied_ui=lambda reason: self.root.after(0, lambda r=reason: self._show_extension_denied_toast(r)),
        )

        self.current_user = None
        self.session = None
        self._current_session_id = None
        self.logger = get_logger()

        self.search_var = tk.StringVar()
        # Map table header names to database columns (matching table headers exactly)
        self.sort_column_map = {
            "Service": "service_name",
            "Username": "username_email",
            "Url": "url",
            "Created": "created_at"
        }
        self.sort_column_var = tk.StringVar(value="Service")
        self.sort_direction_var = tk.StringVar(value="ASC")
        self._sort_dropdown_window = None  # Custom dropdown window
        self.status_var = tk.StringVar(value="Ready")
        self.health_cache = {"timestamp": 0.0, "data": None}
        self.health_loading = False

        self.import_rows = []
        self.import_show_passwords = False

        # Security UX controls
        self.clipboard_clear_seconds = self.DEFAULT_CLIPBOARD_CLEAR_SECONDS
        self.clipboard_clear_enabled = True
        self._clipboard_clear_job = None
        self._clipboard_nonce = None

        self.idle_timeout_ms = self.DEFAULT_IDLE_TIMEOUT_MS
        self._idle_job = None
        self._unfocused_lock_job = None  # lock after app unfocused for idle_timeout
        self._backup_timer = None
        self._backup_cred_prompt_job = None
        self._last_activity_ts = 0.0
        self._password_reveal_timer = None  # auto-mask after revealing passwords in vault table
        self._password_revealed_iids = set()  # iids currently showing password in vault column

        # Undo buffer for destructive actions
        self._undo_buffer = None  # {"action": str, "data": dict, "job_id": after_id}
        self._undo_timeout_ms = self.DEFAULT_UNDO_TIMEOUT_MS

        # Theme management
        self._current_theme_name = "dark"

        # Toast notification
        self._toast_widget = None

        self._load_config()  # Load persisted settings

        # Phase 4: Non-blocking KDF benchmark – avoid frozen GUI on first run
        LocalKeyManager._kdf_non_blocking = True
        _profile_existed = LocalKeyManager.KDF_PROFILE_PATH.exists()
        LocalKeyManager.get_kdf_profile(non_blocking=True)
        self._kdf_calibration_pending = not _profile_existed and not LocalKeyManager.KDF_PROFILE_PATH.exists()

        # Session security (Phase 6.1): central state and policy; idle -> LOCK model
        policy = getattr(self, "_session_security_policy", None) or {}
        self.session_security = SessionSecurityService(policy=policy)
        self.session_security.ensure_app_instance_id()
        self.session_security.register_clear_callback(self._on_session_lock_clear)
        # Use validated idle timeout from service (clamped range)
        self.idle_timeout_ms = self.session_security.get_policy()["idle_lock_minutes"] * 60 * 1000
        self.api.set_session_security(self.session_security)  # for localhost API lock checks (Phase 6.x)

        self._setup_style()
        
        # Initialize the persistent status terminal dock (visible across all views)
        self._build_status_terminal_dock()
        self._start_status_poller()
        
        self._set_auth_window()
        self._build_login_view()

        if getattr(self, "_kdf_calibration_pending", False):
            self._set_status("Initial security calibration is running in the background. Performance will improve after it completes.")
            self._kdf_calibration_pending = False

        # Lock when app is unfocused for the set time (same as "lock after no use" minutes)
        self._install_focus_watchers()
        # Keyboard + activity hooks
        self.root.bind("<Control-k>", self._open_command_palette)
        self.root.bind("<Alt-l>", lambda e: self._do_manual_lock())
        self._install_activity_watchers()
        self._install_sleep_detection()

    # ---------------------- style ----------------------
    def _setup_style(self):
        style = ttk.Style(self.root)

        # Keep a fully themeable ttk baseline to avoid low-contrast states on hover/focus.
        # Native Windows themes may ignore style foreground/background for some states.
        try:
            style.theme_use("clam")
        except Exception:
            pass

        tokens = get_theme(self._current_theme_name)
        # Map tokens to internal palette names
        self.palette = {
            "bg": tokens.get("bg"),
            "panel": tokens.get("bg_secondary"),
            "text": tokens.get("fg"),
            "muted": tokens.get("fg_muted"),
            "topbar": tokens.get("nav_bg"),
            "topbar_text": tokens.get("nav_fg"),
            "success": tokens.get("success"),
            "danger": tokens.get("danger"),
            "danger_hover": tokens.get("danger_hover"),
            "accent": tokens.get("accent"),
            "accent_fg": tokens.get("accent_fg", "white"),
            "accent_soft": tokens.get("nav_active_bg"),
            "accent_soft_hover": tokens.get("nav_hover_bg"),
            "accent_active": tokens.get("accent_active"),
            "accent_hover": tokens.get("accent_hover"),
            "card_soft": tokens.get("bg_tertiary"),
            "hero": tokens.get("accent"),
            "border": tokens.get("border"),
            "topbar_hover": tokens.get("nav_hover_bg"),
            "topbar_active": tokens.get("nav_active_bg"),
            "topbar_active_hover": tokens.get("accent_hover"),
            "topbar_active_text": tokens.get("nav_active_fg") or "#ffffff",  # Fallback for visibility on blue bg
            "input_bg": tokens.get("input_bg"),
            "input_fg": tokens.get("input_fg"),
            "table_row_hover": tokens.get("table_row_hover"),
            "table_row_alt": tokens.get("table_row_alt"),
            "table_header_bg": tokens.get("table_header_bg", tokens.get("bg_tertiary")),
        }

        self.root.configure(bg=self.palette["bg"])

        try:
            self.ui_scale = float(self.root.tk.call("tk", "scaling"))
        except Exception:
            self.ui_scale = 1.0

        self.base_size = int(round(13 * self.ui_scale))
        self.small_size = int(round(11.5 * self.ui_scale))
        self.title_size = int(round(22 * self.ui_scale))
        self.card_title_size = int(round(12.5 * self.ui_scale))
        self.card_value_size = int(round(24 * self.ui_scale))
        self.hero_title_size = int(round(24 * self.ui_scale))
        self.auth_title_size = int(round(17 * self.ui_scale))

        families = {f.lower(): f for f in tkfont.families()}
        ui_family = None
        for cand in ["Inter", "SF Pro Text", "Segoe UI", "Helvetica Neue", "Arial"]:
            if cand.lower() in families:
                ui_family = families[cand.lower()]
                break
        if not ui_family:
            ui_family = "TkDefaultFont"

        mono_family = None
        for cand in ["JetBrains Mono", "Fira Code", "Consolas", "Courier New"]:
            if cand.lower() in families:
                mono_family = families[cand.lower()]
                break
        if not mono_family:
            mono_family = "TkFixedFont"

        emoji_family = families.get("segoe ui emoji", ui_family)

        self.font_base = tkfont.Font(family=ui_family, size=self.base_size)
        self.font_small = tkfont.Font(family=ui_family, size=self.small_size)
        self.font_title = tkfont.Font(family=ui_family, size=self.title_size, weight="bold")
        self.font_entry = tkfont.Font(family=ui_family, size=self.base_size)
        self.font_button = tkfont.Font(family=ui_family, size=self.base_size, weight="bold")
        self.font_mono = tkfont.Font(family=mono_family, size=max(11, self.base_size - 1))
        self.font_nav = tkfont.Font(family=ui_family, size=max(11, self.base_size - 1), weight="bold")
        self.font_brand = tkfont.Font(family=ui_family, size=18, weight="bold")
        self.font_eye = tkfont.Font(family=emoji_family, size=max(11, self.base_size))
        self.font_auth_title = tkfont.Font(family=ui_family, size=self.auth_title_size, weight="bold")
        self.font_hero_title = tkfont.Font(family=ui_family, size=self.hero_title_size, weight="bold")
        self.font_card_title = tkfont.Font(family=ui_family, size=self.card_title_size, weight="bold")
        self.font_card_value = tkfont.Font(family=ui_family, size=self.card_value_size, weight="bold")
        # Large font so checkbox box and label are bigger (min 20pt for visibility)
        self.font_checkbox = tkfont.Font(family=ui_family, size=max(20, self.base_size + 8))
        # Toolbar / filter controls: ensure readable size (min 11pt) for dropdowns and buttons
        self.font_toolbar = tkfont.Font(family=ui_family, size=max(11, self.base_size))

        style.configure("TFrame", background=self.palette["bg"])
        style.configure("Panel.TFrame", background=self.palette["panel"])
        style.configure("Soft.TFrame", background=self.palette["card_soft"])
        # Activity Log and other sections: dark card with themed label
        style.configure(
            "TLabelframe",
            background=self.palette["panel"],
            borderwidth=1,
            relief="solid",
        )
        style.configure(
            "TLabelframe.Label",
            background=self.palette["panel"],
            foreground=self.palette["text"],
            font=self.font_card_title,
        )
        style.map("TLabelframe", background=[("active", self.palette["panel"])])
        style.map("TLabelframe.Label", background=[("active", self.palette["panel"])])

        style.configure("TLabel", background=self.palette["bg"], foreground=self.palette["text"], font=self.font_base)
        style.configure("Title.TLabel", background=self.palette["bg"], foreground=self.palette["text"], font=self.font_title)
        style.configure("Sub.TLabel", background=self.palette["bg"], foreground=self.palette["muted"], font=self.font_small)
        style.configure("CardTitle.TLabel", background=self.palette["panel"], foreground=self.palette["muted"], font=self.font_card_title)
        style.configure("CardValue.TLabel", background=self.palette["panel"], foreground=self.palette["text"], font=self.font_card_value)
        style.configure("Header.TLabel", background=self.palette["bg"], foreground=self.palette["text"], font=self.font_title)
        style.configure("Toolbar.TLabel", background=self.palette["bg"], foreground=self.palette["text"], font=self.font_toolbar)
        # Activity Log: larger text to match theme and readability
        style.configure("ActivityLog.TLabel", background=self.palette["bg"], foreground=self.palette["text"], font=self.font_base)
        style.configure(
            "ActivityLog.TCombobox",
            font=self.font_base,
            padding=(8, 6),
            background=self.palette.get("input_bg", self.palette["panel"]),
            foreground=self.palette["text"],
            borderwidth=1,
            relief="solid",
            fieldbackground=self.palette.get("input_bg", self.palette["panel"]),
            arrowcolor=self.palette["text"],
        )
        style.map(
            "ActivityLog.TCombobox",
            background=[
                ("disabled", self.palette["border"]),
                ("readonly", self.palette.get("input_bg", self.palette["panel"])),
                ("active", self.palette.get("input_bg", self.palette["panel"])),
                ("!disabled", self.palette.get("input_bg", self.palette["panel"])),
            ],
            foreground=[
                ("disabled", self.palette["muted"]),
                ("active", self.palette["text"]),
                ("!disabled", self.palette["text"]),
            ],
            fieldbackground=[
                ("readonly", self.palette.get("input_bg", self.palette["panel"])),
                ("!readonly", self.palette.get("input_bg", self.palette["panel"])),
            ],
            arrowcolor=[
                ("disabled", self.palette["muted"]),
                ("!disabled", self.palette["text"]),
            ],
        )

        # FIXED: Hero section colors adapt to theme for visibility
        hero_bg = self.palette["hero"]
        if self._current_theme_name == "light":
            hero_fg = "#ffffff"  # White text on colored background in light mode
            hero_sub_fg = "#f0f0f0"  # Slightly lighter for subtext
        else:
            hero_fg = "#ffffff"  # White text on dark background
            hero_sub_fg = "#eaf2ff"  # Light blue for dark mode
        
        style.configure("Hero.TFrame", background=hero_bg)
        style.configure("HeroTitle.TLabel", background=hero_bg, foreground=hero_fg, font=self.font_hero_title)
        style.configure("HeroSub.TLabel", background=hero_bg, foreground=hero_sub_fg, font=self.font_base)
        style.configure("Bullet.TLabel", background=hero_bg, foreground=hero_sub_fg, font=self.font_small)

        style.configure("AuthCard.TFrame", background=self.palette["panel"])
        style.configure("AuthTitle.TLabel", background=self.palette["panel"], foreground=self.palette["text"], font=self.font_auth_title)
        style.configure("AuthSub.TLabel", background=self.palette["panel"], foreground=self.palette["muted"], font=self.font_base)

        style.configure(
            "TButton",
            font=self.font_button,
            padding=(12, 8),
            background=self.palette["card_soft"],
            foreground=self.palette["text"],
            borderwidth=1,
            relief="solid",
            focusthickness=0,
        )
        style.map(
            "TButton",
            background=[
                ("disabled", self.palette["border"]),
                ("pressed", self.palette["accent_soft"]),
                ("active", "#eef2ff"),  # FIXED: Use light background on hover for visibility
                ("!disabled", self.palette["card_soft"]),
            ],
            foreground=[
                ("disabled", self.palette["muted"]),
                ("pressed", self.palette["text"]),
                ("active", "#000000"),  # FIXED: Always black text on light hover background
                ("!disabled", self.palette["text"]),
            ],
        )

        style.configure(
            "Secondary.TButton",
            font=self.font_toolbar,
            padding=(10, 8),
            background=self.palette["card_soft"],
            foreground=self.palette["text"],
            borderwidth=1,
            relief="solid",
            focusthickness=0,
        )
        style.map(
            "Secondary.TButton",
            background=[
                ("disabled", "#e2e8f0"),
                ("pressed", "#dde7ff"),
                ("active", "#eef2ff"),  # Light background on hover
                ("!disabled", self.palette["card_soft"]),
            ],
            foreground=[
                ("disabled", "#94a3b8"),
                ("pressed", self.palette["text"]),
                ("active", "#000000"),  # FIXED: Always black text on light hover background (#eef2ff)
                ("!disabled", self.palette["text"]),
            ],
        )

        style.configure(
            "Accent.TButton",
            font=self.font_button,
            padding=(12, 9),
            background=self.palette["accent"],
            foreground="white",  # Always white text on accent background
            borderwidth=0,
            relief="flat",
            focusthickness=0,
        )
        style.map(
            "Accent.TButton",
            background=[
                ("disabled", self.palette["border"]),
                ("pressed", self.palette["accent_active"]),
                ("active", self.palette["accent_hover"]),  # Hover: lighter accent color
                ("!disabled", self.palette["accent"]),
            ],
            foreground=[
                ("disabled", self.palette["muted"]),
                ("pressed", "white"),  # Always white text when pressed
                ("active", "white"),   # Always white text on hover (FIXED: was using accent_fg which might be wrong)
                ("!disabled", "white"),  # Always white text normally
            ],
        )

        # Link.TButton style for secondary actions like "Forgot passphrase?"
        style.configure(
            "Link.TButton",
            background=self.palette["panel"],
            foreground=self.palette["accent"],
            borderwidth=0,
            padding=(4, 2),
            font=self.font_small,
        )
        style.map(
            "Link.TButton",
            background=[("active", self.palette["card_soft"])],
            foreground=[("active", self.palette["accent"])],
        )

        style.configure("TNotebook", background=self.palette["panel"], borderwidth=0)
        style.configure("TPanedwindow", background=self.palette["panel"])
        style.configure("Sash", background=self.palette.get("border", self.palette["panel"]))
        style.configure("TSeparator", background=self.palette.get("border", self.palette["panel"]))
        style.configure("TNotebook.Tab", padding=(18, 10), font=self.font_button)
        style.map(
            "TNotebook.Tab",
            background=[
                ("selected", self.palette["accent_soft"]),
                ("active", self.palette["accent_soft_hover"]),
                ("!selected", self.palette["card_soft"]),
            ],
            foreground=[
                ("selected", self.palette["accent_fg"]),
                ("active", self.palette["accent_fg"]),
                ("!selected", self.palette["text"]),
            ],
        )

        style.configure(
            "Treeview",
            font=self.font_base,
            rowheight=int(round(34 * self.ui_scale)),
            background=self.palette["panel"],
            fieldbackground=self.palette["panel"],
            foreground=self.palette["text"],
        )
        style.configure("Treeview.Heading", font=self.font_button, background=self.palette.get("table_header_bg", self.palette["bg"]), foreground=self.palette["text"])
        th_bg = self.palette.get("table_header_bg", self.palette["bg"])
        style.map(
            "Treeview.Heading",
            background=[
                ("active", "#eef2ff"),  # Light background on hover
                ("!active", th_bg),
            ],
            foreground=[
                ("active", "#000000"),  # Black text on hover for visibility
                ("!active", self.palette["text"]),
            ],
        )
        
        # Style Combobox: use toolbar font so dropdown and field text are readable
        style.configure(
            "TCombobox",
            font=self.font_toolbar,
            padding=(10, 8),
            background=self.palette["card_soft"],
            foreground=self.palette["text"],
            borderwidth=1,
            relief="solid",
            fieldbackground=self.palette["card_soft"],
            arrowcolor=self.palette["text"],
        )
        style.map(
            "TCombobox",
            background=[
                ("disabled", self.palette["border"]),
                ("readonly", self.palette["card_soft"]),
                ("active", "#eef2ff"),  # Light background on hover
                ("!disabled", self.palette["card_soft"]),
            ],
            foreground=[
                ("disabled", self.palette["muted"]),
                ("active", "#000000"),  # Black text on hover
                ("!disabled", self.palette["text"]),
            ],
            fieldbackground=[
                ("readonly", self.palette["card_soft"]),
                ("!readonly", self.palette["card_soft"]),
            ],
            arrowcolor=[
                ("disabled", self.palette["muted"]),
                ("!disabled", self.palette["text"]),
            ],
        )

        # TSpinbox: match theme (dark panel + light text in dark mode)
        try:
            style.configure(
                "TSpinbox",
                font=self.font_base,
                padding=(6, 5),
                background=self.palette["panel"],
                foreground=self.palette["text"],
                borderwidth=1,
                relief="solid",
                fieldbackground=self.palette.get("input_bg", self.palette["panel"]),
                arrowcolor=self.palette["text"],
            )
            style.map(
                "TSpinbox",
                background=[("disabled", self.palette["border"]), ("!disabled", self.palette["panel"])],
                foreground=[("disabled", self.palette["muted"]), ("!disabled", self.palette["text"])],
                fieldbackground=[("readonly", self.palette.get("input_bg", self.palette["panel"])), ("!readonly", self.palette.get("input_bg", self.palette["panel"]))],
                arrowcolor=[("disabled", self.palette["muted"]), ("!disabled", self.palette["text"])],
            )
        except Exception:
            pass

        # TCheckbutton: match theme, larger label + padding, dark indicator (same as spinboxes/entries)
        try:
            style.configure(
                "TCheckbutton",
                font=self.font_toolbar,
                background=self.palette["panel"],
                foreground=self.palette["text"],
                padding=(8, 12),
                indicatorbackground=self.palette.get("input_bg", self.palette["border"]),
                indicatorforeground=self.palette["text"],
            )
            style.configure(
                "Toolbar.TCheckbutton",
                font=self.font_toolbar,
                background=self.palette["bg"],
                foreground=self.palette["text"],
                padding=(6, 8),
            )
            style.map("Toolbar.TCheckbutton", background=[("active", self.palette["bg"])], foreground=[("active", self.palette["text"])])
            # Larger indicator box if theme supports it (clam/alt)
            try:
                style.configure("TCheckbutton", indicatordiameter=20, indicatormargin=(4, 4, 4, 4))
            except Exception:
                pass
            style.map(
                "TCheckbutton",
                background=[("active", self.palette["panel"]), ("!active", self.palette["panel"])],
                foreground=[("active", self.palette["text"]), ("!active", self.palette["text"]), ("disabled", self.palette["muted"])],
                indicatorbackground=[
                    ("active", self.palette.get("input_bg", self.palette["border"])),
                    ("selected", self.palette.get("accent", self.palette["border"])),
                    ("!selected", self.palette.get("input_bg", self.palette["border"])),
                ],
                indicatorforeground=[("selected", self.palette["text"]), ("!selected", self.palette["text"])],
            )
        except Exception:
            pass

        style.map(
            "Treeview",
            background=[("selected", self.palette["accent_soft"])],
            foreground=[("selected", self.palette["text"])],
        )

        # Only configure table tags if widgets exist (they are destroyed by _clear_root before unlock rebuild)
        if hasattr(self, "vault_table") and self.vault_table.winfo_exists():
            self.vault_table.tag_configure("odd", background=self.palette["panel"], foreground=self.palette["text"])
            self.vault_table.tag_configure("even", background=self.palette.get("table_row_alt", self.palette["panel"]), foreground=self.palette["text"])
        if hasattr(self, "audit_log_table") and self.audit_log_table.winfo_exists():
            self.audit_log_table.tag_configure("odd", background=self.palette["panel"], foreground=self.palette["text"])
            self.audit_log_table.tag_configure("even", background=self.palette.get("table_row_alt", self.palette["panel"]), foreground=self.palette["text"])

    def _bind_table_header_hover(self, treeview: ttk.Treeview):
        """Add hover effects to Treeview headers - black text on light background."""
        style = ttk.Style()
        normal_bg = self.palette.get("table_header_bg", self.palette["bg"])
        normal_fg = self.palette["text"]
        hover_bg = "#eef2ff"  # Light background on hover
        hover_fg = "#000000"  # Black text on hover
        
        def on_enter(event):
            # Change style to hover state
            style.configure("Treeview.Heading", background=hover_bg, foreground=hover_fg)
        
        def on_leave(event):
            # Restore normal style
            style.configure("Treeview.Heading", background=normal_bg, foreground=normal_fg)
        
        # Bind to the treeview widget - headers are part of it
        # Use a threshold to detect when mouse is over header area (top ~30 pixels)
        def on_motion(event):
            if event.y < 30:  # Header area
                on_enter(event)
            else:
                on_leave(event)
        
        treeview.bind("<Motion>", on_motion)
        treeview.bind("<Leave>", on_leave)

    # ---------------------- helpers ----------------------
    def _clear_root(self):
        for child in self.root.winfo_children():
            # Preserve the status terminal dock and show bar (persistent across all views)
            if child == getattr(self, "_status_terminal_frame", None):
                continue
            if child == getattr(self, "_show_terminal_bar", None):
                continue
            child.destroy()

    # ---------------------- Status Terminal Dock (Persistent) ----------------------
    def _build_status_terminal_dock(self):
        """
        Build the persistent status terminal dock at the bottom of root.
        This dock remains visible across all views (login, register, main).
        Features: resize, pin, hide/show, collapse/expand.
        """
        # Configuration
        self._status_terminal_height = 160
        self._status_terminal_min_height = 80
        self._status_terminal_max_height = 400
        self._status_terminal_collapsed = False
        self._status_terminal_hidden = False
        self._status_terminal_pinned = True
        self._status_terminal_autoscroll = True
        self._status_terminal_max_lines = 400
        self._resize_dragging = False
        
        # Main container frame
        self._status_terminal_frame = tk.Frame(self.root, bg=self.palette.get("panel", "#1e1e1e"))
        self._status_terminal_frame.pack(side="bottom", fill="x")
        
        # Resize handle at top (drag to resize)
        self._resize_handle = tk.Frame(
            self._status_terminal_frame,
            bg=self.palette.get("muted", "#444444"),
            height=4,
            cursor="sb_v_double_arrow",
        )
        self._resize_handle.pack(side="top", fill="x")
        self._resize_handle.bind("<Button-1>", self._start_resize)
        self._resize_handle.bind("<B1-Motion>", self._do_resize)
        self._resize_handle.bind("<ButtonRelease-1>", self._stop_resize)
        
        # Header row with controls
        header = tk.Frame(self._status_terminal_frame, bg=self.palette.get("panel", "#1e1e1e"))
        header.pack(side="top", fill="x", padx=8, pady=(4, 0))
        
        # Title
        title_lbl = tk.Label(
            header,
            text="Process Monitor",
            font=self.font_nav,
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("text", "#ffffff"),
        )
        title_lbl.pack(side="left", padx=(4, 12))
        
        # View Full Report button
        details_btn = tk.Button(
            header,
            text="View Report",
            relief="flat",
            bg=self.palette.get("accent", "#3b82f6"),
            fg=self.palette.get("accent_fg", "white"),
            font=self.font_small,
            padx=8,
            pady=2,
            cursor="hand2",
            command=self._show_process_viewer,
        )
        details_btn.pack(side="right", padx=4)
        
        # Hide button (minimize to tiny bar)
        self._hide_btn = tk.Button(
            header,
            text="Hide",
            relief="flat",
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("muted", "#888888"),
            font=self.font_small,
            padx=6,
            cursor="hand2",
            command=self._hide_status_terminal,
        )
        self._hide_btn.pack(side="right", padx=2)
        
        # Pin toggle (keep always visible)
        self._pin_btn = tk.Button(
            header,
            text="📌",
            relief="flat",
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("success", "#22c55e"),
            font=self.font_small,
            width=3,
            cursor="hand2",
            command=self._toggle_pin_terminal,
        )
        self._pin_btn.pack(side="right", padx=2)
        
        # Collapse/Expand toggle
        self._status_collapse_btn = tk.Button(
            header,
            text="▼",
            relief="flat",
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("muted", "#888888"),
            font=self.font_small,
            width=3,
            cursor="hand2",
            command=self._toggle_status_terminal,
        )
        self._status_collapse_btn.pack(side="right", padx=2)
        
        # Auto-scroll toggle
        self._autoscroll_btn = tk.Button(
            header,
            text="Auto ✓",
            relief="flat",
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("success", "#22c55e"),
            font=self.font_small,
            padx=6,
            cursor="hand2",
            command=self._toggle_autoscroll,
        )
        self._autoscroll_btn.pack(side="right", padx=2)
        
        # Clear button
        clear_btn = tk.Button(
            header,
            text="Clear",
            relief="flat",
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("muted", "#888888"),
            font=self.font_small,
            padx=6,
            cursor="hand2",
            command=self._clear_status_terminal,
        )
        clear_btn.pack(side="right", padx=2)
        
        # Size indicator label
        self._size_label = tk.Label(
            header,
            text=f"{self._status_terminal_height}px",
            font=self.font_small,
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("muted", "#666666"),
        )
        self._size_label.pack(side="right", padx=(0, 8))
        
        # Body frame (collapsible, resizable)
        self._status_body_frame = tk.Frame(
            self._status_terminal_frame,
            bg=self.palette.get("bg", "#121212"),
            height=self._status_terminal_height,
        )
        self._status_body_frame.pack(side="top", fill="x", padx=8, pady=(4, 8))
        self._status_body_frame.pack_propagate(False)
        
        # Text widget (read-only, monospace)
        self._status_text = tk.Text(
            self._status_body_frame,
            wrap="none",
            font=self.font_mono,
            bg=self.palette.get("bg", "#121212"),
            fg=self.palette.get("text", "#ffffff"),
            insertbackground=self.palette.get("text", "#ffffff"),
            selectbackground=self.palette.get("accent", "#3b82f6"),
            relief="flat",
            padx=8,
            pady=4,
            state="disabled",
            cursor="arrow",
        )
        self._status_text.pack(side="left", fill="both", expand=True)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(
            self._status_body_frame,
            command=self._status_text.yview,
            bg=self.palette.get("panel", "#1e1e1e"),
        )
        scrollbar.pack(side="right", fill="y")
        self._status_text.config(yscrollcommand=scrollbar.set)
        
        # Configure text tags for colors
        self._status_text.tag_config("INFO", foreground=self.palette.get("text", "#ffffff"))
        self._status_text.tag_config("OK", foreground=self.palette.get("success", "#22c55e"))
        self._status_text.tag_config("WARN", foreground="#f59e0b")
        self._status_text.tag_config("ERROR", foreground=self.palette.get("danger", "#ef4444"))
        self._status_text.tag_config("TIMESTAMP", foreground=self.palette.get("muted", "#888888"))
        
        # Hidden state show bar (appears when terminal is hidden)
        self._show_terminal_bar = tk.Frame(self.root, bg=self.palette.get("panel", "#1e1e1e"))
        # Don't pack initially - only shown when terminal is hidden
        
        self._show_terminal_btn = tk.Button(
            self._show_terminal_bar,
            text="▲ Show Process Monitor",
            relief="flat",
            bg=self.palette.get("accent", "#3b82f6"),
            fg="white",
            font=self.font_small,
            padx=16,
            pady=4,
            cursor="hand2",
            command=self._show_status_terminal,
        )
        self._show_terminal_btn.pack(side="left", padx=8, pady=4)
        
        # Add a status indicator to the show bar
        self._hidden_status_label = tk.Label(
            self._show_terminal_bar,
            text="Terminal hidden",
            font=self.font_small,
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("muted", "#888888"),
        )
        self._hidden_status_label.pack(side="left", padx=8)
    
    def _toggle_status_terminal(self):
        """Toggle collapse/expand of status terminal body."""
        if self._status_terminal_collapsed:
            self._status_body_frame.pack(side="top", fill="x", padx=8, pady=(4, 8))
            self._status_collapse_btn.config(text="▼")
            self._status_terminal_collapsed = False
        else:
            self._status_body_frame.pack_forget()
            self._status_collapse_btn.config(text="▲")
            self._status_terminal_collapsed = True
    
    def _toggle_autoscroll(self):
        """Toggle auto-scroll behavior."""
        self._status_terminal_autoscroll = not self._status_terminal_autoscroll
        if self._status_terminal_autoscroll:
            self._autoscroll_btn.config(text="Auto ✓", fg=self.palette.get("success", "#22c55e"))
        else:
            self._autoscroll_btn.config(text="Auto", fg=self.palette.get("muted", "#888888"))
    
    def _clear_status_terminal(self):
        """Clear the status terminal text and session."""
        self._status_text.config(state="normal")
        self._status_text.delete("1.0", "end")
        self._status_text.config(state="disabled")
        get_bus().clear_session()
    
    def _toggle_pin_terminal(self):
        """Toggle pin state - pinned terminal stays visible during page switches."""
        self._status_terminal_pinned = not self._status_terminal_pinned
        if self._status_terminal_pinned:
            self._pin_btn.config(fg=self.palette.get("success", "#22c55e"))
        else:
            self._pin_btn.config(fg=self.palette.get("muted", "#888888"))
    
    def _hide_status_terminal(self):
        """Hide the status terminal (minimize to show bar)."""
        self._status_terminal_hidden = True
        self._status_terminal_frame.pack_forget()
        self._show_terminal_bar.pack(side="bottom", fill="x")
    
    def _show_status_terminal(self):
        """Show the status terminal (restore from hidden)."""
        self._status_terminal_hidden = False
        self._show_terminal_bar.pack_forget()
        self._status_terminal_frame.pack(side="bottom", fill="x")
    
    def _start_resize(self, event):
        """Start resizing the terminal."""
        self._resize_dragging = True
        self._resize_start_y = event.y_root
        self._resize_start_height = self._status_terminal_height
    
    def _do_resize(self, event):
        """Handle resize drag - adjust terminal height."""
        if not self._resize_dragging:
            return
        
        # Calculate new height (dragging up increases height)
        delta = self._resize_start_y - event.y_root
        new_height = self._resize_start_height + delta
        
        # Clamp to min/max
        new_height = max(self._status_terminal_min_height, min(self._status_terminal_max_height, new_height))
        
        # Apply new height
        self._status_terminal_height = new_height
        self._status_body_frame.config(height=new_height)
        self._size_label.config(text=f"{new_height}px")
    
    def _stop_resize(self, event):
        """Stop resizing the terminal."""
        self._resize_dragging = False
    
    def _start_status_poller(self):
        """Start the status bus poller using root.after()."""
        self._poll_status_bus()
    
    def _poll_status_bus(self):
        """Drain StatusBus queue and append formatted lines to terminal. Thread-safe."""
        try:
            events = get_bus().drain()
            for event in events:
                self._append_status_line(event)
        except Exception:
            pass
        # Re-schedule (100ms interval)
        self.root.after(100, self._poll_status_bus)
    
    def _append_status_line(self, event):
        """Append a formatted status line to the terminal with professional formatting."""
        self._status_text.config(state="normal")
        
        # Determine visual indicator based on level
        if event.level == "OK":
            icon = "✓"
            level_display = "[OK]  "
        elif event.level == "ERROR":
            icon = "✗"
            level_display = "[FAIL]"
        elif event.level == "WARN":
            icon = "!"
            level_display = "[WARN]"
        else:
            icon = "→"
            level_display = "[INFO]"
        
        # Format: [HH:MM:SS] [ICON] [LEVEL] Operation (Step): message
        timestamp_str = f"[{event.timestamp}]"
        
        if event.step:
            line = f"{timestamp_str} {icon} {level_display} {event.operation} | {event.step}: {event.message}\n"
        else:
            line = f"{timestamp_str} {icon} {level_display} {event.operation}: {event.message}\n"
        
        # Insert with tag for coloring
        start_idx = self._status_text.index("end-1c")
        self._status_text.insert("end", line)
        
        # Apply color tag to the line
        end_idx = self._status_text.index("end-1c")
        self._status_text.tag_add(event.level, start_idx, end_idx)
        
        # Trim if too many lines
        line_count = int(self._status_text.index("end-1c").split(".")[0])
        if line_count > self._status_terminal_max_lines:
            excess = line_count - self._status_terminal_max_lines
            self._status_text.delete("1.0", f"{excess + 1}.0")
        
        self._status_text.config(state="disabled")
        
        # Auto-scroll if enabled
        if self._status_terminal_autoscroll:
            self._status_text.see("end")
    
    def _show_process_viewer(self):
        """Open pop-out Process Viewer window with full session transcript."""
        viewer = tk.Toplevel(self.root)
        viewer.title("Process Viewer - Session Transcript")
        viewer.configure(bg=self.palette.get("bg", "#121212"))
        viewer.geometry("900x600")
        viewer.minsize(700, 400)
        
        # Header frame
        header = tk.Frame(viewer, bg=self.palette.get("panel", "#1e1e1e"))
        header.pack(side="top", fill="x", padx=0, pady=0)
        
        title_lbl = tk.Label(
            header,
            text="Session Transcript",
            font=self.font_brand,
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("text", "#ffffff"),
        )
        title_lbl.pack(side="left", padx=16, pady=12)
        
        # Close button
        close_btn = tk.Button(
            header,
            text="Close",
            relief="flat",
            bg=self.palette.get("danger", "#ef4444"),
            fg="white",
            font=self.font_small,
            padx=12,
            pady=4,
            cursor="hand2",
            command=viewer.destroy,
        )
        close_btn.pack(side="right", padx=8, pady=8)
        
        # Clear Session button
        def _clear_and_refresh():
            get_bus().clear_session()
            self._clear_status_terminal()
            _refresh_text()
        
        clear_btn = tk.Button(
            header,
            text="Clear Session",
            relief="flat",
            bg=self.palette.get("panel", "#1e1e1e"),
            fg=self.palette.get("muted", "#888888"),
            font=self.font_small,
            padx=8,
            pady=4,
            cursor="hand2",
            command=_clear_and_refresh,
        )
        clear_btn.pack(side="right", padx=4, pady=8)
        
        # Copy to Clipboard button
        def _copy_transcript():
            session = get_bus().get_current_session()
            
            # Generate professional text-based report for clipboard
            lines = []
            lines.append("=" * 80)
            lines.append("                         REAL-TIME PROCESS LOG")
            lines.append("=" * 80)
            lines.append("")
            
            # Group events by operation
            operations = {}
            for event in session:
                op_key = event.operation
                if op_key not in operations:
                    operations[op_key] = []
                operations[op_key].append(event)
            
            step_num = 0
            for op_name, events in operations.items():
                step_num += 1
                lines.append(f"Step {step_num}: {op_name}")
                lines.append("-" * 60)
                
                for event in events:
                    if event.level == "OK":
                        icon = "[OK]   "
                    elif event.level == "ERROR":
                        icon = "[FAIL] "
                    elif event.level == "WARN":
                        icon = "[WARN] "
                    else:
                        icon = "[INFO] "
                    
                    if event.step:
                        lines.append(f"  {icon}{event.step}: {event.message}")
                    else:
                        lines.append(f"  {icon}{event.message}")
                
                # Final status
                final_event = events[-1]
                if final_event.level == "OK":
                    lines.append("  Status: COMPLETED SUCCESSFULLY")
                elif final_event.level == "ERROR":
                    lines.append("  Status: FAILED")
                lines.append("")
            
            # Footer
            from datetime import datetime
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            lines.append("-" * 80)
            lines.append(f"Generated: {now}")
            lines.append(f"Total Operations: {len(operations)}")
            lines.append(f"Total Events: {len(session)}")
            
            transcript = "\n".join(lines)
            self.root.clipboard_clear()
            self.root.clipboard_append(transcript)
            copy_btn.config(text="Copied!")
            viewer.after(1500, lambda: copy_btn.config(text="Copy Transcript"))
        
        copy_btn = tk.Button(
            header,
            text="Copy Transcript",
            relief="flat",
            bg=self.palette.get("accent", "#3b82f6"),
            fg=self.palette.get("accent_fg", "white"),
            font=self.font_small,
            padx=8,
            pady=4,
            cursor="hand2",
            command=_copy_transcript,
        )
        copy_btn.pack(side="right", padx=4, pady=8)
        
        # Export Report button
        def _export_report():
            from tkinter import filedialog
            from datetime import datetime
            
            session = get_bus().get_current_session()
            if not session:
                return
            
            # Generate professional text-based report
            lines = []
            lines.append("=" * 80)
            lines.append("                    SECURECRYPT VAULT - PROCESS REPORT")
            lines.append("=" * 80)
            lines.append("")
            
            # Group events by operation
            operations = {}
            for event in session:
                op_key = event.operation
                if op_key not in operations:
                    operations[op_key] = []
                operations[op_key].append(event)
            
            step_num = 0
            for op_name, events in operations.items():
                step_num += 1
                lines.append(f"STEP {step_num}: {op_name.upper()}")
                lines.append("-" * 70)
                
                for event in events:
                    if event.level == "OK":
                        icon = "[OK]   "
                    elif event.level == "ERROR":
                        icon = "[FAIL] "
                    elif event.level == "WARN":
                        icon = "[WARN] "
                    else:
                        icon = "[INFO] "
                    
                    if event.step:
                        lines.append(f"    {icon}{event.step}: {event.message}")
                    else:
                        lines.append(f"    {icon}{event.message}")
                
                # Final status
                final_event = events[-1]
                if final_event.level == "OK":
                    lines.append("")
                    lines.append("    >>> Status: COMPLETED SUCCESSFULLY")
                elif final_event.level == "ERROR":
                    lines.append("")
                    lines.append("    >>> Status: FAILED")
                lines.append("")
            
            # Footer
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            lines.append("=" * 80)
            lines.append(f"Report Generated: {now}")
            lines.append(f"Total Operations: {len(operations)}")
            lines.append(f"Total Events: {len(session)}")
            lines.append("=" * 80)
            
            report_content = "\n".join(lines)
            
            # Ask user where to save
            filename = filedialog.asksaveasfilename(
                title="Export Process Report",
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                initialfile=f"process_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            
            if filename:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(report_content)
                export_btn.config(text="Exported!")
                viewer.after(1500, lambda: export_btn.config(text="Export Report"))
        
        export_btn = tk.Button(
            header,
            text="Export Report",
            relief="flat",
            bg=self.palette.get("success", "#22c55e"),
            fg="white",
            font=self.font_small,
            padx=8,
            pady=4,
            cursor="hand2",
            command=_export_report,
        )
        export_btn.pack(side="right", padx=4, pady=8)
        
        # Text area
        text_frame = tk.Frame(viewer, bg=self.palette.get("bg", "#121212"))
        text_frame.pack(side="top", fill="both", expand=True, padx=16, pady=(8, 16))
        
        text_widget = tk.Text(
            text_frame,
            wrap="none",
            font=self.font_mono,
            bg=self.palette.get("bg", "#121212"),
            fg=self.palette.get("text", "#ffffff"),
            insertbackground=self.palette.get("text", "#ffffff"),
            selectbackground=self.palette.get("accent", "#3b82f6"),
            relief="flat",
            padx=12,
            pady=8,
            state="disabled",
        )
        text_widget.pack(side="left", fill="both", expand=True)
        
        scrollbar = tk.Scrollbar(text_frame, command=text_widget.yview)
        scrollbar.pack(side="right", fill="y")
        text_widget.config(yscrollcommand=scrollbar.set)
        
        # Configure tags
        text_widget.tag_config("INFO", foreground=self.palette.get("text", "#ffffff"))
        text_widget.tag_config("OK", foreground=self.palette.get("success", "#22c55e"))
        text_widget.tag_config("WARN", foreground="#f59e0b")
        text_widget.tag_config("ERROR", foreground=self.palette.get("danger", "#ef4444"))
        text_widget.tag_config("HEADER", foreground=self.palette.get("accent", "#3b82f6"), font=self.font_nav)
        
        # Additional tags for professional formatting
        text_widget.tag_config("BORDER", foreground="#4ade80")
        text_widget.tag_config("SECTION", foreground="#22d3ee", font=self.font_nav)
        text_widget.tag_config("STEP", foreground="#60a5fa")
        text_widget.tag_config("CHECK", foreground="#22c55e")
        text_widget.tag_config("CROSS", foreground="#ef4444")
        text_widget.tag_config("LABEL", foreground="#a1a1aa")
        text_widget.tag_config("VALUE", foreground="#ffffff")
        
        def _format_professional_report(session):
            """Format session events into professional report-grade output."""
            lines = []
            
            # Group events by operation
            operations = {}
            for event in session:
                op_key = event.operation
                if op_key not in operations:
                    operations[op_key] = []
                operations[op_key].append(event)
            
            # Build report
            lines.append(("╔" + "═" * 78 + "╗\n", "BORDER"))
            lines.append(("║" + " " * 25 + "REAL-TIME PROCESS LOG" + " " * 32 + "║\n", "BORDER"))
            lines.append(("╚" + "═" * 78 + "╝\n\n", "BORDER"))
            
            step_num = 0
            for op_name, events in operations.items():
                step_num += 1
                
                # Section header
                lines.append((f"┌─ Step {step_num}: {op_name} ", "SECTION"))
                lines.append(("─" * (60 - len(op_name)) + "┐\n", "SECTION"))
                lines.append(("│\n", "BORDER"))
                
                for event in events:
                    # Determine icon based on level
                    if event.level == "OK":
                        icon = "✓"
                        icon_tag = "CHECK"
                    elif event.level == "ERROR":
                        icon = "✗"
                        icon_tag = "CROSS"
                    elif event.level == "WARN":
                        icon = "!"
                        icon_tag = "WARN"
                    else:
                        icon = "→"
                        icon_tag = "INFO"
                    
                    # Format the line
                    lines.append(("│  ", "BORDER"))
                    lines.append((f"{icon} ", icon_tag))
                    
                    if event.step:
                        lines.append((f"{event.step}: ", "LABEL"))
                    
                    lines.append((f"{event.message}", event.level))
                    lines.append(("\n", "INFO"))
                
                lines.append(("│\n", "BORDER"))
                
                # Show final status for operation
                final_event = events[-1]
                if final_event.level == "OK":
                    lines.append(("│  ", "BORDER"))
                    lines.append(("Status: ", "LABEL"))
                    lines.append(("COMPLETED SUCCESSFULLY\n", "CHECK"))
                elif final_event.level == "ERROR":
                    lines.append(("│  ", "BORDER"))
                    lines.append(("Status: ", "LABEL"))
                    lines.append(("FAILED\n", "CROSS"))
                
                lines.append(("└" + "─" * 78 + "┘\n\n", "SECTION"))
            
            # Footer with timestamp
            from datetime import datetime
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            lines.append(("─" * 80 + "\n", "LABEL"))
            lines.append(("Generated: ", "LABEL"))
            lines.append((f"{now}\n", "VALUE"))
            lines.append(("Total Operations: ", "LABEL"))
            lines.append((f"{len(operations)}\n", "VALUE"))
            lines.append(("Total Events: ", "LABEL"))
            lines.append((f"{len(session)}\n", "VALUE"))
            
            return lines
        
        def _refresh_text():
            text_widget.config(state="normal")
            text_widget.delete("1.0", "end")
            
            session = get_bus().get_current_session()
            if not session:
                text_widget.insert("end", "No status events in current session.\n", "INFO")
            else:
                # Generate professional report
                formatted_lines = _format_professional_report(session)
                for text, tag in formatted_lines:
                    text_widget.insert("end", text, tag)
            
            text_widget.config(state="disabled")
        
        _refresh_text()
        
        # Focus the viewer
        viewer.focus_force()
        viewer.grab_set()

    def _center_window(self, w: int, h: int, min_w=None, min_h=None):
        """Center window on screen with smart sizing."""
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()

        # IMPROVED: Better size constraints
        min_width = min_w or 700
        min_height = min_h or 520

        # Ensure window fits on screen
        w = max(min_width, min(w, sw - 40))
        h = max(min_height, min(h, sh - 60))

        # Center window
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.minsize(min_width, min_height)
        self.root.resizable(True, True)  # Allow resizing

    def _set_auth_window(self, target=None):
        """Set window size for authentication/login view with smart auto-fitting."""
        win = target if target else self.root
        try:
            win.update_idletasks()  # Ensure window is ready
            sw = win.winfo_screenwidth()
            sh = win.winfo_screenheight()
            
            # IMPROVED: Large window size for better visibility
            # Use more screen space for a bigger window - ensure it's always large
            ideal_w = min(1600, int(sw * 0.92))  # Use 92% width, max 1600px
            ideal_h = min(1000, int(sh * 0.92))   # Use 92% height, max 1000px
        
            # Ensure minimum usable size (larger minimums)
            min_w = 1400
            min_h = 900
            w = max(min_w, ideal_w)
            h = max(min_h, ideal_h)
            
            # Ensure window fits on screen with margins
            margin_x = 40
            margin_y = 60
            w = min(w, sw - margin_x)
            h = min(h, sh - margin_y)
            
            # Center window on screen
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            
            win.geometry(f"{w}x{h}+{x}+{y}")
            if not target:  # Only set minsize for main window
                win.minsize(min_w, min_h)
                # Allow resizing for better UX
                win.resizable(True, True)
        except Exception as e:
            # Fallback to large defaults if geometry fails
            self.logger.error("Error setting auth window geometry: %s", e)
            if not target:
                win.geometry("1500x950")
                win.minsize(1400, 900)
                win.resizable(True, True)

    def _set_main_window(self):
        """Set window size and position for main application view with smart auto-fitting."""
        try:
            self.root.update_idletasks()  # Ensure window is ready
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
            
            # IMPROVED: Large window size for main view - use more screen space
            # Use 95% of screen but ensure minimum usable size
            ideal_w = min(1800, int(sw * 0.95))  # Use 95% width, max 1800px
            ideal_h = min(1100, int(sh * 0.93))   # Use 93% height, max 1100px
            
            # Minimum sizes for main view (large minimums)
            min_w = 1600
            min_h = 950
            w = max(min_w, ideal_w)
            h = max(min_h, ideal_h)
            
            # Ensure window fits on screen with small margins
            margin_x = 20
            margin_y = 40
            w = min(w, sw - margin_x)
            h = min(h, sh - margin_y)
            
            # Center window
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            
            self.root.geometry(f"{w}x{h}+{x}+{y}")
            self.root.minsize(min_w, min_h)
            self.root.resizable(True, True)  # Allow user to resize
            
            # Ensure all content is visible
            self.root.update_idletasks()
        except Exception as e:
            # Fallback to large defaults
            self.logger.error("Error setting main window geometry: %s", e)
            self.root.geometry("1700x1000")
            self.root.minsize(1600, 950)
            self.root.resizable(True, True)

    @staticmethod
    def _safe_username(username: str) -> bool:
        ok, _ = CryptoUtils.validate_input(username, "username")
        return ok

    def _safe_key_path(self, username: str, purpose: str) -> Path:
        if not self._safe_username(username):
            raise ValueError("Invalid username format")

        base = keys_dir().resolve()
        user_dir = (base / username).resolve()
        try:
            user_dir.relative_to(base)
        except Exception:
            raise ValueError("Unsafe username path")

        return user_dir / f"{purpose}_key.pem"

    @staticmethod
    def _secure_write_json(path: Path, payload: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass

    def _set_status(self, text: str):
        self.status_var.set(text)

    def _show_extension_denied_toast(self, reason: str):
        """Phase 6.5: Non-intrusive desktop notification when extension request is blocked (debounced)."""
        now = time.time()
        last = self._extension_denied_toast_last.get(reason, 0)
        if now - last < self._EXTENSION_DENIED_DEBOUNCE_SEC:
            return
        self._extension_denied_toast_last[reason] = now
        msg = {
            "APP_LOCKED": "Unlock the app to continue autofill.",
            "SESSION_EXPIRED": "Session expired — sign in again.",
            "REAUTH_REQUIRED": "Re-auth required for autofill.",
            "AUTH_REQUIRED": "Sign in to the app to use autofill.",
        }.get(reason, "Autofill was blocked. Check the app.")
        self._show_toast(msg, "warning")

    def _install_focus_watchers(self):
        """Lock app after it has been unfocused for the configured 'lock after no use' time."""
        def _on_focus_out(_event=None):
            if not self.session or self.session_security.is_locked():
                return
            if not self.session_security.get_policy().get("idle_lock_enabled", True):
                return
            self._clear_idle_lock()
            try:
                self._unfocused_lock_job = self.root.after(
                    self.idle_timeout_ms, self._force_idle_lock
                )
            except Exception:
                self._unfocused_lock_job = None

        def _on_focus_in(_event=None):
            self._clear_unfocused_lock()
            self._on_user_activity()

        self.root.bind("<FocusOut>", _on_focus_out)
        self.root.bind("<FocusIn>", _on_focus_in)

    def _install_activity_watchers(self):
        events = ("<Any-KeyPress>", "<Any-ButtonPress>", "<Motion>")
        for ev in events:
            self.root.bind_all(ev, self._on_user_activity, add="+")

    def _on_user_activity(self, _event=None):
        # Throttle (debounce) and only track when session is active and unlocked (Phase 6.2).
        now = time.time()
        if now - self._last_activity_ts < 0.8:
            return
        self._last_activity_ts = now
        if not self.session or self.session_security.is_locked():
            return
        # Phase 6.1/6.4: update session security activity; enforce hard expiry
        err = self.session_security.mark_user_activity()
        if err == "expired":
            self._handle_hard_expiry()
            return
        # Phase 6.2: arm idle timer only when idle lock is enabled
        if self.session_security.get_policy().get("idle_lock_enabled", True):
            self._arm_idle_lock()

    def _arm_idle_lock(self):
        """Schedule idle lock; no-op if already locked or idle lock disabled (Phase 6.2)."""
        if self.session_security.is_locked():
            return
        if not self.session_security.get_policy().get("idle_lock_enabled", True):
            return
        self._clear_idle_lock()
        try:
            self._idle_job = self.root.after(self.idle_timeout_ms, self._force_idle_lock)
        except Exception:
            self._idle_job = None

    def _do_manual_lock(self):
        """Phase 6.2: User chose to lock the app; same path as idle lock. Backup timer continues in background."""
        if not self.session or self.session_security.is_locked():
            return
        get_bus().info("Lock", "Locking session...")
        self._clear_idle_lock()
        self._locked_from_page = getattr(self, "active_nav_key", None) or "dashboard"
        try:
            uid = int(self.session["user_id"]) if self.session else None
            self.security_alert_service.notify_security_alert("session_locked_manual", user_id=uid)
        except Exception:
            pass
        self.session_security.lock_session("manual")
        self.logger.info("Session locked (manual)")
        get_bus().ok("Lock", "Session locked")
        self._transition_to_locked_ui(reason="manual")

    def _clear_unfocused_lock(self):
        """Cancel the 'lock when app unfocused' timer."""
        if self._unfocused_lock_job:
            try:
                self.root.after_cancel(self._unfocused_lock_job)
            except Exception:
                pass
            self._unfocused_lock_job = None

    def _clear_idle_lock(self):
        if self._idle_job:
            try:
                self.root.after_cancel(self._idle_job)
            except Exception:
                pass
            self._idle_job = None
        self._clear_unfocused_lock()

    def _handle_hard_expiry(self):
        """Phase 6.4: Hard expiry transition – full login required, not unlock. Clear callbacks already run in mark_user_activity."""
        try:
            uid = int(self.session["user_id"]) if self.session else None
            self.security_alert_service.notify_security_alert("session_hard_expired", user_id=uid)
        except Exception:
            pass
        if self.session:
            self.session.clear()
        self.session = None
        self.current_user = None
        self._current_session_id = None
        self._clear_idle_lock()
        self._clear_hard_expiry_check()
        if self._backup_timer:
            try:
                self.root.after_cancel(self._backup_timer)
            except Exception:
                pass
            self._backup_timer = None
        if self._backup_cred_prompt_job:
            try:
                self.root.after_cancel(self._backup_cred_prompt_job)
            except Exception:
                pass
            self._backup_cred_prompt_job = None
        self.extension_server.stop()
        self._build_login_view()
        self._set_status("Session expired. Please sign in again.")

    def _check_hard_expiry(self):
        """Phase 6.4: Periodic hard expiry check (catches expiry when no user activity)."""
        self._hard_expiry_check_job = None
        if not self.session:
            self._schedule_hard_expiry_check()
            return
        if self.session_security.is_hard_expired():
            self.session_security.mark_user_activity()  # sets EXPIRED_HARD, runs clear callbacks
            self._handle_hard_expiry()
            return
        self._schedule_hard_expiry_check()

    _HARD_EXPIRY_CHECK_INTERVAL_MS = 60000  # 1 minute

    def _schedule_hard_expiry_check(self):
        """Schedule next periodic hard expiry check (Phase 6.4)."""
        if getattr(self, "_hard_expiry_check_job", None):
            try:
                self.root.after_cancel(self._hard_expiry_check_job)
            except Exception:
                pass
        if self.session and self.session_security.get_policy().get("hard_session_expiry_enabled", True):
            try:
                self._hard_expiry_check_job = self.root.after(self._HARD_EXPIRY_CHECK_INTERVAL_MS, self._check_hard_expiry)
            except Exception:
                self._hard_expiry_check_job = None

    def _clear_hard_expiry_check(self):
        if getattr(self, "_hard_expiry_check_job", None):
            try:
                self.root.after_cancel(self._hard_expiry_check_job)
            except Exception:
                pass
            self._hard_expiry_check_job = None

    def _on_session_lock_clear(self):
        """Centralized sensitive cache clearing (Phase 6.1/6.6): password vars, clipboard. Keep enc_priv, backup key so backup timer can continue while locked."""
        try:
            self._clear_password_fields()
            if self._clipboard_clear_job:
                try:
                    self.root.after_cancel(self._clipboard_clear_job)
                except Exception:
                    pass
                self._clipboard_clear_job = None
            try:
                self._clear_clipboard_windows()
            except Exception:
                pass
        except Exception:
            pass

    def _force_idle_lock(self):
        """Phase 6.2: Idle timeout → lock (not logout); show lock screen. Backup timer continues in background."""
        if not self.session or self.session_security.is_locked():
            return
        self._clear_idle_lock()
        self._locked_from_page = getattr(self, "active_nav_key", None) or "dashboard"
        try:
            uid = int(self.session["user_id"]) if self.session else None
            self.security_alert_service.notify_security_alert("session_locked_idle", user_id=uid)
        except Exception:
            pass
        self.session_security.lock_session("idle")
        self.logger.info("Session locked (idle)")
        self._transition_to_locked_ui(reason="idle")

    def _transition_to_locked_ui(self, reason: str = "manual"):
        """Switch UI to lock screen; vault content is already hidden by clearing root.
        
        Note: Backup timer continues running while locked. The backup credentials
        (cached in backup_service) and enc_priv (in session) are preserved.
        Extension server also continues to allow autofill when locked.
        """
        if reason == "idle":
            msg = "App locked due to inactivity. Unlock to continue."
        else:
            msg = "App locked."
        self._set_status(msg)
        self._show_toast(msg, "warning")
        self._build_lock_screen(reason=reason)
        # Ensure backup timer continues running while locked
        if not self._backup_timer and self.session:
            self._schedule_backup_tick()

    def _build_lock_screen(self, reason: str = "manual"):
        """Phase 6.2: Lock screen – no vault content; unlock passphrase + Logout."""
        self._clear_root()
        self._set_auth_window()

        shell = ttk.Frame(self.root, padding=22)
        shell.pack(fill="both", expand=True)

        card = ttk.Frame(shell, style="AuthCard.TFrame", padding=32)
        card.pack(expand=True)
        card.columnconfigure(0, weight=1)

        ttk.Label(card, text="App locked", style="AuthTitle.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        reason_text = "App locked due to inactivity. Unlock to continue." if reason == "idle" else "App locked."
        ttk.Label(card, text=reason_text, style="AuthSub.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 4))
        username = (self.session or {}).get("username") or (self.current_user or {}).get("username") or "—"
        ttk.Label(card, text=f"Account: {username}", style="AuthSub.TLabel").grid(row=2, column=0, sticky="w", pady=(0, 20))
        ttk.Label(card, text="Unlock to continue", style="AuthSub.TLabel").grid(row=3, column=0, sticky="w", pady=(0, 12))

        self.unlock_pass = tk.StringVar()
        self._make_password_row(card, "Your login password", self.unlock_pass, row=4)
        btn_row = ttk.Frame(card, style="AuthCard.TFrame")
        btn_row.grid(row=6, column=0, sticky="w", pady=(0, 12))
        self.unlock_btn = ttk.Button(btn_row, text="Unlock", command=self._unlock, style="Accent.TButton")
        self.unlock_btn.pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Logout", command=self._logout_from_lock_screen).pack(side="left")

        self.root.bind("<Return>", lambda e: self._unlock())

    def _full_clear_for_logout(self):
        """Wipe all sensitive data on logout (enc_priv, backup key). Lock only clears UI caches."""
        if self.session:
            try:
                self.api.clear_auto_backup_key_for_user(int(self.session["user_id"]))
            except Exception:
                pass
            enc_priv = self.session.get("enc_priv")
            if isinstance(enc_priv, (bytearray, memoryview)):
                CryptoUtils.wipe_sensitive_data(enc_priv)
            sign_priv = self.session.get("sign_priv")
            if isinstance(sign_priv, (bytearray, memoryview)):
                CryptoUtils.wipe_sensitive_data(sign_priv)
            self.session["enc_priv"] = None
            self.session["sign_priv"] = None

    def _logout_from_lock_screen(self):
        """Full logout from lock screen; clears session and shows login view."""
        self._clear_hard_expiry_check()
        self._full_clear_for_logout()
        self.session_security.on_logout()
        if self.session:
            self.session.clear()
        self.session = None
        self.current_user = None
        self._current_session_id = None
        self._clear_idle_lock()
        if self._backup_timer:
            try:
                self.root.after_cancel(self._backup_timer)
            except Exception:
                pass
            self._backup_timer = None
        if self._backup_cred_prompt_job:
            try:
                self.root.after_cancel(self._backup_cred_prompt_job)
            except Exception:
                pass
            self._backup_cred_prompt_job = None
        self.extension_server.stop()
        self._build_login_view()
        self._set_status("Logged out")

    def _unlock(self):
        """Validate passphrase, re-derive keys, unlock session, return to main view."""
        bus = get_bus()
        bus.info("Unlock", "Verifying passphrase...")
        
        if getattr(self, "unlock_btn", None):
            try:
                self.unlock_btn.config(state="disabled")
            except Exception:
                pass
        passphrase = (self.unlock_pass.get() or "").strip()
        if not passphrase:
            bus.error("Unlock", "Missing passphrase")
            self._show_toast("Enter your login password.", "warning")
            if getattr(self, "unlock_btn", None):
                try:
                    self.unlock_btn.config(state="normal")
                except Exception:
                    pass
            return
        if not self.session or not self.current_user:
            self._show_toast("Session lost. Please log in again.", "error")
            if getattr(self, "unlock_btn", None):
                try:
                    self.unlock_btn.config(state="normal")
                except Exception:
                    pass
            self._logout_from_lock_screen()
            return
        username = self.session.get("username") or self.current_user.get("username")
        if not username:
            self._show_toast("Session invalid. Please log in again.", "error")
            if getattr(self, "unlock_btn", None):
                try:
                    self.unlock_btn.config(state="normal")
                except Exception:
                    pass
            self._logout_from_lock_screen()
            return
        try:
            enc_path = self._safe_key_path(username, "encryption")
            sign_path = self._safe_key_path(username, "signing")
        except Exception:
            self.unlock_pass.set("")
            self._show_toast("Could not find key files. Log in again.", "error")
            if getattr(self, "unlock_btn", None):
                try:
                    self.unlock_btn.config(state="normal")
                except Exception:
                    pass
            return
        if not enc_path.exists():
            self.unlock_pass.set("")
            self._show_toast("Encryption key not found. Log in again.", "error")
            if getattr(self, "unlock_btn", None):
                try:
                    self.unlock_btn.config(state="normal")
                except Exception:
                    pass
            return
        try:
            enc_bundle = json.loads(enc_path.read_text(encoding="utf-8"))
            enc_priv_bytes = LocalKeyManager.unlock_key_from_bundle(enc_bundle, passphrase)
            if not enc_priv_bytes:
                self.unlock_pass.set("")
                try:
                    self.api.record_unlock_failure(username)
                    must_wait, _ = self.api.check_unlock_backoff(username)
                    uid = int(self.session["user_id"]) if self.session else None
                    if must_wait:
                        self.security_alert_service.notify_security_alert(
                            "unlock_failed_repeated_threshold", user_id=uid
                        )
                    else:
                        self.security_alert_service.notify_security_alert(
                            "unlock_failed", user_id=uid
                        )
                except Exception:
                    pass
                if getattr(self, "unlock_btn", None):
                    try:
                        self.unlock_btn.config(state="normal")
                    except Exception:
                        pass
                return
            enc_priv = bytearray(enc_priv_bytes) if isinstance(enc_priv_bytes, bytes) else enc_priv_bytes
        except Exception:
            self.unlock_pass.set("")
            try:
                self.api.record_unlock_failure(username)
                must_wait, _ = self.api.check_unlock_backoff(username)
                uid = int(self.session["user_id"]) if self.session else None
                if must_wait:
                    self.security_alert_service.notify_security_alert(
                        "unlock_failed_repeated_threshold", user_id=uid
                    )
                else:
                    self.security_alert_service.notify_security_alert(
                        "unlock_failed", user_id=uid
                    )
            except Exception:
                pass
            if getattr(self, "unlock_btn", None):
                try:
                    self.unlock_btn.config(state="normal")
                except Exception:
                    pass
            return
        sign_priv = None
        if sign_path.exists():
            try:
                sign_bundle = json.loads(sign_path.read_text(encoding="utf-8"))
                sign_priv_bytes = LocalKeyManager.unlock_key_from_bundle(sign_bundle, passphrase)
                if sign_priv_bytes:
                    sign_priv = bytearray(sign_priv_bytes) if isinstance(sign_priv_bytes, bytes) else sign_priv_bytes
            except Exception:
                pass
        self.unlock_pass.set("")
        self.session["enc_priv"] = enc_priv
        self.session["sign_priv"] = sign_priv
        try:
            self.api.reset_unlock_backoff(username)
        except Exception:
            pass
        self.session_security.unlock_session()
        self._clear_idle_lock()
        self._arm_idle_lock()
        bus.ok("Unlock", "Session resumed")
        ok_ext, _ = self.extension_server.start()
        self._build_main_view()
        self.show_page(getattr(self, "_locked_from_page", "dashboard"))
        self.root.update_idletasks()  # Ensure content is painted after unlock
        self._schedule_backup_tick()
        self._schedule_hard_expiry_check()  # Phase 6.4
        self._set_status(f"Unlocked. Logged in as {username}" + (" · Extension API running" if ok_ext else ""))
        self._show_toast("Unlocked successfully.", "success")

    # ── Sleep / resume detection (Windows) ─────────────────────────────

    def _install_sleep_detection(self):
        """Listen for OS sleep/resume events. On resume → force idle lock."""
        if platform.system() != "Windows":
            return
        try:
            import ctypes
            import ctypes.wintypes

            WM_POWERBROADCAST = 0x0218
            PBT_APMRESUMEAUTOMATIC = 0x12
            PBT_APMRESUMESUSPEND = 0x07
            PBT_APMSUSPEND = 0x04

            # Tkinter on Windows receives WM_POWERBROADCAST through its event loop.
            # We poll the message queue indirectly via root.after + a lightweight check.
            def _monitor_resume():
                # On Windows, when the OS resumes the system thread sleeps too.
                # The simplest cross-compatible approach: check if the elapsed wall-clock
                # time since last tick exceeds the idle timeout (meaning we slept).
                now = time.time()
                if hasattr(self, '_sleep_check_ts') and self.session:
                    elapsed = now - self._sleep_check_ts
                    if elapsed > (self.idle_timeout_ms / 1000):
                        self._force_idle_lock()
                        return
                self._sleep_check_ts = now
                self.root.after(5000, _monitor_resume)  # check every 5 sec

            self._sleep_check_ts = time.time()
            self.root.after(5000, _monitor_resume)
        except Exception:
            pass  # graceful no-op on unsupported systems

    # ── Toast notification system (non-blocking) ───────────────────────

    def _show_toast(self, message: str, level: str = "info", duration_ms: int = 3500):
        """Show a non-blocking toast notification at the top of the window."""
        if self._toast_widget:
            try:
                self._toast_widget.destroy()
            except Exception:
                pass

        bg_map = {"info": self.palette.get("accent"), "success": self.palette.get("success"), "warning": self.palette.get("warning"), "error": self.palette.get("danger")}
        bg = bg_map.get(level, bg_map["info"])
        # FIXED: Use appropriate text color based on theme
        # For colored backgrounds (accent, success, danger), always use white text for contrast
        fg = "#ffffff"  # White text on colored backgrounds for visibility

        toast = tk.Frame(self.root, bg=bg, padx=16, pady=8)
        toast.place(relx=0.5, y=10, anchor="n")
        _font = (self.font_base.actual()["family"], 10, "bold") if getattr(self, "font_base", None) else ("TkDefaultFont", 10, "bold")
        tk.Label(toast, text=message, bg=bg, fg=fg, font=_font).pack()
        self._toast_widget = toast

        def _fade():
            try:
                toast.destroy()
            except Exception:
                pass
            if self._toast_widget is toast:
                self._toast_widget = None

        self.root.after(duration_ms, _fade)

    # ── Security alert banner (in-app, severity-based) ─────────────────

    def _hide_security_alert_banner(self):
        """Hide the security alert banner and cancel any autohide job."""
        if self._alert_banner_autohide_job:
            try:
                self.root.after_cancel(self._alert_banner_autohide_job)
            except Exception:
                pass
            self._alert_banner_autohide_job = None
        frame = getattr(self, "_alert_banner_frame", None)
        if not frame:
            return
        try:
            if not frame.winfo_exists():
                return
            for w in frame.winfo_children():
                try:
                    w.destroy()
                except Exception:
                    pass
            frame.configure(height=0)
        except tk.TclError:
            pass

    def _show_security_alert_banner(
        self, severity: str, message: str, event_code: str, context: None
    ):
        """Show in-app alert banner. Info/Warning auto-hide; Critical stays until dismiss."""
        if not getattr(self, "security_alerts_banner_enabled", True):
            return
        self._hide_security_alert_banner()
        frame = getattr(self, "_alert_banner_frame", None)
        if not frame:
            return
        try:
            if not frame.winfo_exists():
                return
        except tk.TclError:
            return
        color_map = {
            SEVERITY_INFO: self.palette.get("accent"),
            SEVERITY_WARNING: self.palette.get("warning"),
            SEVERITY_CRITICAL: self.palette.get("danger"),
        }
        bg = color_map.get(severity, self.palette.get("accent"))
        fg = "#ffffff"
        frame.configure(bg=bg, height=44)
        inner = tk.Frame(frame, bg=bg, padx=16, pady=8)
        inner.pack(fill="x", expand=True)
        _font = (self.font_base.actual()["family"], 10, "bold") if getattr(self, "font_base", None) else ("TkDefaultFont", 10, "bold")
        tk.Label(
            inner,
            text=message,
            bg=bg,
            fg=fg,
            font=_font,
            wraplength=800,
            anchor="w",
        ).pack(side="left", fill="x", expand=True, anchor="w")
        if severity == SEVERITY_CRITICAL:
            def _dismiss():
                self._hide_security_alert_banner()
            _btn_font = (self.font_base.actual()["family"], 9, "bold") if getattr(self, "font_base", None) else ("TkDefaultFont", 9, "bold")
            tk.Button(
                inner,
                text="Dismiss",
                bg=bg,
                fg=fg,
                activebackground=self.palette.get("danger_hover", bg),
                activeforeground=fg,
                font=_btn_font,
                relief="flat",
                bd=0,
                padx=12,
                pady=4,
                cursor="hand2",
                command=_dismiss,
            ).pack(side="right", padx=(8, 0))
        else:
            autohide_sec = max(3, min(30, getattr(self, "security_alerts_banner_autohide_seconds", 6)))
            self._alert_banner_autohide_job = self.root.after(
                int(autohide_sec) * 1000, self._hide_security_alert_banner
            )

    def _show_security_alert_windows_toast(
        self, severity: str, message: str, event_code: str, context
    ):
        """Show a native Windows toast notification for the security alert (Windows only)."""
        if platform.system() != "Windows":
            return
        if not getattr(self, "security_alerts_windows_toast_enabled", True):
            return
        try:
            from winotify import Notification
        except ImportError:
            return
        try:
            toast = Notification(
                app_id="Secure Vault",
                title="Secure Vault – Security",
                msg=message or "Security alert",
            )
            toast.show()
        except Exception:
            pass

    def _clear_clipboard_windows(self):
        """Clear clipboard on Windows aggressively, attempting to clear clipboard history."""
        try:
            if platform.system() == "Windows":
                # Use Windows API for more aggressive clearing
                try:
                    import ctypes
                    from ctypes import wintypes
                    
                    user32 = ctypes.windll.user32
                    kernel32 = ctypes.windll.kernel32
                    
                    # Try multiple times to ensure clipboard is cleared
                    for attempt in range(3):
                        if user32.OpenClipboard(None):
                            try:
                                # Empty clipboard completely
                                user32.EmptyClipboard()
                                
                                # Try to set an empty string to overwrite any remaining data
                                # This helps clear clipboard history entries
                                CF_TEXT = 1
                                CF_UNICODETEXT = 13
                                
                                # Set empty text data
                                empty_str = ""
                                empty_bytes = empty_str.encode('utf-16le')
                                
                                # Allocate memory for empty string
                                mem = kernel32.GlobalAlloc(0x2000, len(empty_bytes) + 2)  # GMEM_MOVEABLE
                                if mem:
                                    try:
                                        mem_ptr = kernel32.GlobalLock(mem)
                                        if mem_ptr:
                                            ctypes.memmove(mem_ptr, empty_bytes, len(empty_bytes))
                                            kernel32.GlobalUnlock(mem)
                                            user32.SetClipboardData(CF_UNICODETEXT, mem)
                                    except Exception:
                                        if mem:
                                            kernel32.GlobalFree(mem)
                                
                                user32.CloseClipboard()
                                break  # Success, exit loop
                            except Exception:
                                try:
                                    user32.CloseClipboard()
                                except Exception:
                                    pass
                        # Small delay between attempts
                        time.sleep(0.05)
                except Exception:
                    pass
            
            # Also use Tkinter's clipboard clear as fallback
            try:
                self.root.clipboard_clear()
                # Set empty string to overwrite any clipboard history
                self.root.clipboard_append("")
                # Clear again to ensure it's empty
                self.root.clipboard_clear()
            except Exception:
                pass
        except Exception:
            pass

    def _copy_to_clipboard(self, value: str, label: str = "Value"):
        # CRITICAL SECURITY FIX: Improved clipboard nonce handling to prevent race conditions
        # Cancel any existing clipboard clear job first
        if self._clipboard_clear_job:
            try:
                self.root.after_cancel(self._clipboard_clear_job)
            except Exception:
                pass
            self._clipboard_clear_job = None

        # Generate new nonce before clearing clipboard
        nonce = secrets.token_hex(8)
        self._clipboard_nonce = nonce

        # Clear and set clipboard
        self._clear_clipboard_windows()
        # Small delay to ensure clipboard is cleared before setting new value
        self.root.update_idletasks()
        self.root.clipboard_append(value)
        self._set_status(f"{label} copied to clipboard")
        
        # Status terminal update (never show the value itself)
        get_bus().ok("Clipboard", f"{label} copied to clipboard")

        # Auto-clear clipboard after configured timeout (only when enabled)
        if getattr(self, "clipboard_clear_enabled", True):
            def clear_if_same():
                try:
                    if hasattr(self, '_clipboard_nonce') and self._clipboard_nonce == nonce:
                        self._clear_clipboard_windows()
                        self._set_status("Clipboard cleared automatically")
                        self._clipboard_nonce = None
                except Exception:
                    pass
                finally:
                    self._clipboard_clear_job = None

            self._clipboard_clear_job = self.root.after(int(self.clipboard_clear_seconds * 1000), clear_if_same)

    @staticmethod
    def _hex_to_rgb(h: str):
        h = h.lstrip("#")
        return tuple(int(h[i : i + 2], 16) for i in (0, 2, 4))

    @staticmethod
    def _rgb_to_hex(rgb):
        return "#%02x%02x%02x" % tuple(max(0, min(255, int(v))) for v in rgb)

    def _animate_button(self, button: tk.Button, target_bg: str, target_fg: str, steps: int = 6, duration_ms: int = 140):
        try:
            start_bg = button.cget("bg")
            start_fg = button.cget("fg")
        except Exception:
            button.configure(bg=target_bg, fg=target_fg)
            return

        try:
            sb = self._hex_to_rgb(start_bg)
            sf = self._hex_to_rgb(start_fg)
            tb = self._hex_to_rgb(target_bg)
            tf = self._hex_to_rgb(target_fg)
        except Exception:
            button.configure(bg=target_bg, fg=target_fg)
            return

        prev_job = getattr(button, "_anim_job", None)
        if prev_job:
            try:
                self.root.after_cancel(prev_job)
            except Exception:
                pass

        step_delay = max(10, duration_ms // max(1, steps))

        def tick(i=1):
            t = i / float(steps)
            cb = tuple(sb[k] + (tb[k] - sb[k]) * t for k in range(3))
            cf = tuple(sf[k] + (tf[k] - sf[k]) * t for k in range(3))
            button.configure(
                bg=self._rgb_to_hex(cb),
                fg=self._rgb_to_hex(cf),
                activebackground=target_bg,
                activeforeground=target_fg,
            )
            if i < steps:
                button._anim_job = self.root.after(step_delay, lambda: tick(i + 1))

        tick(1)

    def _bind_hover_button(self, button: tk.Button, normal_bg: str, hover_bg: str, normal_fg: str, hover_fg: str):
        """Add explicit hover colors so text/background never lose contrast."""
        # IMPROVED: Ensure high contrast text colors for visibility
        # Calculate if we need to adjust text color for better visibility
        if self._current_theme_name == "light":
            # For light theme, ensure dark text on hover
            if hover_fg == normal_fg or hover_fg in ["#ffffff", "white"]:
                hover_fg = "#000000"
        else:
            # For dark theme, ensure light text on hover
            if hover_fg == normal_fg or hover_fg in ["#000000", "black"]:
                hover_fg = "#ffffff"
        
        button.configure(
            bg=normal_bg,
            fg=normal_fg,
            activebackground=hover_bg,
            activeforeground=hover_fg,
            highlightthickness=0,
            bd=0,
            relief="flat",
            takefocus=0,
        )

        def on_enter(_e):
            self._animate_button(button, hover_bg, hover_fg)

        def on_leave(_e):
            self._animate_button(button, normal_bg, normal_fg)

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)

    def _apply_nav_btn_style(self, key: str):
        btn = self.nav_buttons.get(key)
        if not btn:
            return
        hovered = bool(getattr(btn, "_is_hovered", False))
        active = key == getattr(self, "active_nav_key", None)

        if active and hovered:
            bg, fg = self.palette["topbar_active_hover"], self.palette["topbar_active_text"]
        elif active:
            bg, fg = self.palette["topbar_active"], self.palette["topbar_active_text"]
            # Ensure visible text on blue: Windows can lose fg; use explicit high-contrast
            fg = fg or "#ffffff"
        elif hovered:
            # IMPROVED: Ensure text is always visible on hover
            bg = self.palette["topbar_hover"]
            # Use high contrast text color for hover state
            if self._current_theme_name == "light":
                fg = "#212529"  # Dark text on light hover background
            else:
                fg = "#ffffff"  # White text on dark hover background
        else:
            bg, fg = self.palette["topbar"], self.palette["topbar_text"]

        if active:
            # Direct configure for active tab (no animation) - avoids Windows fg loss with stepped animation
            try:
                btn.configure(bg=bg, fg=fg, activebackground=bg, activeforeground=fg)
            except Exception:
                self._animate_button(btn, bg, fg)
        else:
            self._animate_button(btn, bg, fg)

    def _set_nav_hover(self, key: str, is_hovered: bool):
        btn = self.nav_buttons.get(key)
        if not btn:
            return
        btn._is_hovered = bool(is_hovered)
        self._apply_nav_btn_style(key)

    def _make_checkbutton(self, parent, text: str, variable: tk.BooleanVar, background=None, command=None, **kwargs):
        """Theme-styled checkbox: custom large box (24x24) + label, theme colors."""
        bg = background if background is not None else self.palette["card_soft"]
        fg = self.palette["text"]
        accent = self.palette["accent"]
        border = self.palette.get("border", bg)
        font = getattr(self, "font_checkbox", self.font_base)
        box_size = 24

        frame = tk.Frame(parent, bg=bg)
        canvas = tk.Canvas(
            frame,
            width=box_size,
            height=box_size,
            bg=bg,
            highlightthickness=0,
            bd=0,
        )
        canvas.pack(side="left", padx=(0, 8))

        def _draw():
            if not canvas.winfo_exists():
                return
            canvas.delete("all")
            checked = variable.get()
            # outer rect
            pad = 2
            canvas.create_rectangle(
                pad, pad, box_size - pad, box_size - pad,
                outline=border, width=2, fill=accent if checked else self.palette.get("input_bg", bg),
            )
            if checked:
                # checkmark
                m = box_size // 2
                canvas.create_line(m - 5, m, m - 1, m + 5, fill=fg, width=2, capstyle="round", joinstyle="round")
                canvas.create_line(m - 1, m + 5, m + 6, m - 5, fill=fg, width=2, capstyle="round", joinstyle="round")

        def _toggle(event=None):
            variable.set(not variable.get())
            _draw()
            if command:
                command()

        canvas.bind("<Button-1>", _toggle)
        _draw()
        variable.trace_add("write", lambda *a: _draw())

        label = tk.Label(
            frame,
            text=text,
            font=font,
            bg=bg,
            fg=fg,
            cursor="hand2",
        )
        label.pack(side="left", anchor="w")
        label.bind("<Button-1>", _toggle)
        frame._checkbutton_canvas = canvas
        return frame

    def _make_entry(self, parent, textvariable: tk.StringVar, show: str = ""):
        e = tk.Entry(
            parent,
            textvariable=textvariable,
            show=show,
            font=self.font_entry,
            bg=self.palette.get("input_bg", self.palette.get("panel", "#ffffff")),
            fg=self.palette.get("input_fg", self.palette["text"]),
            relief="solid",
            bd=1,
            insertbackground=self.palette.get("input_fg", self.palette["text"]),
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            highlightcolor=self.palette.get("border_focus", self.palette["accent"]),
        )
        return e

    def _make_password_entry_with_eye(
        self,
        parent,
        var: tk.StringVar,
        mask: str = "•",
        require_step_up_for_reveal: bool = False,
        step_up_action_name: str = "",
        step_up_action_text: str = "",
    ):
        """Return a frame with entry + eye toggle. Caller packs or grids the frame.
        If require_step_up_for_reveal is True, user must enter login phrase before revealing."""
        row = ttk.Frame(parent)
        row.columnconfigure(0, weight=1)
        ent = self._make_entry(row, var, show=mask)
        ent.grid(row=0, column=0, sticky="ew")

        def _on_eye_click():
            if ent.cget("show") != "":
                if require_step_up_for_reveal and step_up_action_name and step_up_action_text:
                    if not self._require_step_up_or_phrase(step_up_action_name, step_up_action_text):
                        return
            self._toggle_password_entry(ent, eye, mask)

        eye = tk.Button(
            row,
            text="👁",
            font=self.font_eye,
            width=3,
            relief="flat",
            bg=self.palette.get("card_soft", self.palette["panel"]),
            fg=self.palette["text"],
            activebackground=self.palette.get("accent_soft", self.palette["border"]),
            command=_on_eye_click,
        )
        eye.grid(row=0, column=1, padx=(6, 0))
        self._bind_hover_button(
            eye,
            self.palette.get("card_soft", self.palette["panel"]),
            self.palette.get("accent_soft", self.palette["border"]),
            self.palette["text"],
            self.palette["text"],
        )
        return row

    def _make_spinbox(self, parent, textvariable: tk.StringVar, from_: int, to: int, width: int = 8):
        """Themed tk.Spinbox matching dark/light theme (input_bg, input_fg) and readable size."""
        sp = tk.Spinbox(
            parent,
            from_=from_,
            to=to,
            textvariable=textvariable,
            width=width,
            font=self.font_entry,
            bg=self.palette.get("input_bg", self.palette.get("panel", "#ffffff")),
            fg=self.palette.get("input_fg", self.palette["text"]),
            buttonbackground=self.palette.get("card_soft", self.palette["border"]),
            relief="solid",
            bd=1,
            insertbackground=self.palette.get("input_fg", self.palette["text"]),
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            highlightcolor=self.palette.get("border_focus", self.palette["accent"]),
        )
        return sp

    def _make_password_row(self, parent, label_text: str, var: tk.StringVar, row: int):
        ttk.Label(parent, text=label_text, style="AuthSub.TLabel").grid(row=row, column=0, sticky="w")
        wrap = ttk.Frame(parent, style="AuthCard.TFrame")
        wrap.grid(row=row + 1, column=0, sticky="ew", pady=(0, 10))
        wrap.columnconfigure(0, weight=1)

        ent = self._make_entry(wrap, var, show="*")
        ent.grid(row=0, column=0, sticky="ew")

        eye = tk.Button(
            wrap,
            text="👁",
            font=self.font_eye,
            width=3,
            relief="flat",
            bg=self.palette["card_soft"],
            fg=self.palette["text"],
            activebackground=self.palette["accent_soft"],
            command=lambda: self._toggle_password_entry(ent, eye),
        )
        eye.grid(row=0, column=1, padx=(6, 0))
        self._bind_hover_button(eye, self.palette["card_soft"], self.palette["accent_soft"], self.palette["text"], self.palette["text"])
        return ent

    def _toggle_password_entry(self, entry: tk.Entry, button: tk.Button = None, mask: str = "*"):
        current = entry.cget("show")
        if current == "":
            entry.configure(show=mask)
            if button:
                button.configure(text="👁")
        else:
            entry.configure(show="")
            if button:
                button.configure(text="🙈")

    def _get_selected_entry_id(self):
        """Return the first selected entry id, or None if none selected (single-entry compatibility)."""
        ids = self._get_selected_entry_ids()
        return ids[0] if ids else None

    def _get_selected_entry_ids(self):
        """Return list of all selected vault row ids (iids)."""
        if not getattr(self, "vault_table", None):
            return []
        selected = self.vault_table.selection()
        out = []
        for rid in selected:
            try:
                out.append(int(rid))
            except (ValueError, TypeError):
                pass
        return out

    def _get_selected_values(self):
        """Return metadata for the first selected row, or None. Values: service, username, url, created, password (masked)."""
        selected = self.vault_table.selection()
        if not selected:
            return None
        rid = selected[0]
        vals = self.vault_table.item(rid, "values")
        if not vals:
            return None
        # iid = entry id; values are service, username, url, created, password (5 cols)
        return {
            "id": int(rid),
            "service": vals[0] if len(vals) > 0 else "",
            "username": vals[1] if len(vals) > 1 else "",
            "url": vals[2] if len(vals) > 2 else "",
            "created": vals[3] if len(vals) > 3 else "",
        }

    def _vault_select_all(self):
        """Select all rows in the vault table."""
        if not getattr(self, "vault_table", None):
            return
        children = self.vault_table.get_children()
        if not children:
            self._on_select_vault()
            return
        self.vault_table.unbind("<<TreeviewSelect>>")
        try:
            self.vault_table.selection_set(children)
        finally:
            self.vault_table.bind("<<TreeviewSelect>>", self._on_select_vault)
        self._on_select_vault()

    def _vault_clear_selection(self):
        """Clear selection in the vault table."""
        if not getattr(self, "vault_table", None):
            return
        self.vault_table.selection_remove(self.vault_table.get_children())
        self._on_select_vault()

    VAULT_PASSWORD_REVEAL_SECONDS = 45
    VAULT_PASSWORD_DISPLAY_MAX_LEN = 20

    def _reveal_passwords_for_selected(self):
        """Reveal passwords in the vault table for selected rows (one step-up). Auto-mask after 45s."""
        if not self.session or not getattr(self, "vault_table", None):
            return
        ids = self._get_selected_entry_ids()
        if not ids:
            messagebox.showinfo("Show passwords", "Select one or more entries.")
            return
        if not self._require_step_up_or_phrase("reveal_password", "reveal passwords for selected entries"):
            return
        enc_priv = self.session.get("enc_priv")
        if not enc_priv:
            messagebox.showerror("Error", "Session not available.")
            return
        enc_priv_bytes = bytes(enc_priv) if isinstance(enc_priv, bytearray) else enc_priv
        if self._password_reveal_timer:
            try:
                self.root.after_cancel(self._password_reveal_timer)
            except Exception:
                pass
            self._password_reveal_timer = None
        revealed = {}
        for entry_id in ids:
            res, msg = self.api.decrypt_secret(self.session["user_id"], entry_id, enc_priv_bytes)
            if msg != "Success" or res is None:
                messagebox.showerror("Decrypt failed", msg or "Could not decrypt one or more entries.")
                return
            pwd = res.get("password", "") if isinstance(res, dict) else ""
            if isinstance(pwd, str) and len(pwd) > self.VAULT_PASSWORD_DISPLAY_MAX_LEN:
                pwd = pwd[: self.VAULT_PASSWORD_DISPLAY_MAX_LEN] + "…"
            revealed[str(entry_id)] = pwd or "—"
        for iid, pwd_display in revealed.items():
            try:
                vals = list(self.vault_table.item(iid, "values"))
                if len(vals) >= 5:
                    vals[4] = pwd_display
                    self.vault_table.item(iid, values=tuple(vals))
            except Exception:
                pass
        self._password_revealed_iids = set(revealed.keys())
        self._password_reveal_timer = self.root.after(
            self.VAULT_PASSWORD_REVEAL_SECONDS * 1000,
            self._mask_passwords_in_vault,
        )

    def _mask_passwords_in_vault(self):
        """Set password column back to masked for all previously revealed rows."""
        self._password_reveal_timer = None
        if not getattr(self, "vault_table", None):
            self._password_revealed_iids = set()
            return
        for iid in list(self._password_revealed_iids):
            try:
                vals = list(self.vault_table.item(iid, "values"))
                if len(vals) >= 5:
                    vals[4] = "••••••"
                    self.vault_table.item(iid, values=tuple(vals))
            except Exception:
                pass
        self._password_revealed_iids = set()

    def _hide_passwords_in_vault(self):
        """Immediately re-mask passwords in the vault table and cancel auto-mask timer."""
        if self._password_reveal_timer:
            try:
                self.root.after_cancel(self._password_reveal_timer)
            except Exception:
                pass
            self._password_reveal_timer = None
        self._mask_passwords_in_vault()

    def _get_active_encryption_cert(self):
        if not self.session:
            return None
        return self.api.get_active_certificate(self.session["user_id"], "encryption")

    def _clear_password_fields(self):
        """CRITICAL SECURITY: Securely clear all password StringVars to remove sensitive data from memory."""
        try:
            if hasattr(self, 'login_pass'):
                self.login_pass.set("")
            if hasattr(self, 'reg_login_pass'):
                self.reg_login_pass.set("")
            if hasattr(self, 'reg_recovery_pass'):
                self.reg_recovery_pass.set("")
            if hasattr(self, 'password_var'):
                self.password_var.set("")
            if hasattr(self, 'backup_import_pass_var'):
                self.backup_import_pass_var.set("")
        except Exception:
            pass

    def _require_phrase(self, action_text: str) -> bool:
        """Legacy: prompt for login password and verify (no step-up TTL)."""
        if not self.session:
            return False

        phrase = simpledialog.askstring(
            "Security phrase required",
            f"Enter your login password to {action_text}.",
            show="*",
            parent=self.root,
        )
        if phrase is None:
            return False

        username = self.session.get("username", "")
        try:
            auth_path = self._safe_key_path(username, "auth")
            if not auth_path.exists():
                messagebox.showerror("Security check", "Auth key not found on this device.")
                return False

            bundle = json.loads(auth_path.read_text(encoding="utf-8"))
            unlocked = LocalKeyManager.unlock_key_from_bundle(bundle, phrase)
            if not unlocked:
                messagebox.showerror("Security check", "Invalid login phrase.")
                return False
            return True
        except Exception as e:
            messagebox.showerror("Security check", "Verification failed. Try again.")
            return False

    def _show_step_up_reauth_dialog(self, action_name: str, reason_text: str) -> bool:
        """Phase 6.3/6.6: Reusable step-up re-auth dialog. Returns True if user verified successfully."""
        if not self.session:
            return False
        username = self.session.get("username", "")
        try:
            auth_path = self._safe_key_path(username, "auth")
        except Exception:
            messagebox.showerror("Re-authentication", "Could not find your account key.")
            return False
        if not auth_path.exists():
            messagebox.showerror("Re-authentication", "Auth key not found on this device.")
            return False
        try:
            uid = int(self.session["user_id"])
            self.api.audit.log_event("step_up_reauth_prompted", {"action": action_name}, user_id=uid)
        except Exception:
            pass

        dialog = tk.Toplevel(self.root)
        dialog.title("Confirm your password")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.palette["bg"])
        dialog.resizable(False, False)
        result = {"ok": False, "done": False}

        f = ttk.Frame(dialog, style="Panel.TFrame", padding=20)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Please confirm your password to continue this action.", style="Sub.TLabel", wraplength=400).pack(anchor="w", pady=(0, 12))
        pass_var = tk.StringVar()
        pass_row = self._make_password_entry_with_eye(f, pass_var, mask="•")
        pass_row.pack(fill="x", pady=(0, 8))
        pass_entry = pass_row.winfo_children()[0]
        err_var = tk.StringVar()
        ttk.Label(f, textvariable=err_var, style="Sub.TLabel", foreground=self.palette.get("danger", "#c00")).pack(anchor="w", pady=(0, 8))

        def on_confirm():
            if result["done"]:
                return
            phrase = (pass_var.get() or "").strip()
            if not phrase:
                err_var.set("Enter your password.")
                return
            result["done"] = True
            confirm_btn.config(state="disabled")
            ok, err_msg = verify_step_up_identity_app_password(username, phrase, auth_path)
            pass_var.set("")
            if ok:
                result["ok"] = True
                try:
                    uid = int(self.session["user_id"]) if self.session else None
                    self.api.audit.log_event("step_up_reauth_success", {"action": action_name}, user_id=uid)
                except Exception:
                    pass
                try:
                    dialog.destroy()
                except Exception:
                    pass
            else:
                try:
                    uid = int(self.session["user_id"]) if self.session else None
                    self.security_alert_service.notify_security_alert(
                        "step_up_reauth_failed", {"action": action_name}, user_id=uid
                    )
                except Exception:
                    pass
                result["done"] = False
                confirm_btn.config(state="normal")
                err_var.set(err_msg or "Invalid password. Try again.")

        def on_cancel():
            result["done"] = True
            try:
                dialog.destroy()
            except Exception:
                pass

        btn_row = ttk.Frame(f, style="Panel.TFrame")
        btn_row.pack(anchor="w", pady=(8, 0))
        confirm_btn = ttk.Button(btn_row, text="Confirm", command=on_confirm, style="Accent.TButton")
        confirm_btn.pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Cancel", command=on_cancel).pack(side="left")
        pass_entry.focus_set()
        dialog.bind("<Return>", lambda e: on_confirm())
        dialog.protocol("WM_DELETE_WINDOW", on_cancel)
        dialog.wait_window()
        return result.get("ok", False)

    def _require_step_up_or_phrase(self, action_name: str, action_text: str) -> bool:
        """Phase 6.3: If step-up required and not valid, show re-auth dialog; else use legacy phrase prompt."""
        if not self.session:
            return False
        if self.session_security.is_locked():
            self._show_toast("App is locked. Unlock first.", "warning")
            return False
        policy = self.session_security.get_policy()
        if not policy.get("step_up_reauth_enabled", True):
            return self._require_phrase(action_text)
        action_policy = self.session_security._get_action_policy(action_name)
        if not action_policy.get("requires_step_up_reauth", True):
            return self._require_phrase(action_text)
        if self.session_security.is_step_up_valid(action_name):
            return True
        if self._show_step_up_reauth_dialog(action_name, action_text):
            self.session_security.complete_step_up_reauth_success(action_name)
            return True
        return False

    # ---------------------- login/register ----------------------
    def _build_login_view(self):
        self._clear_root()
        self._set_auth_window()

        shell = ttk.Frame(self.root, padding=22)
        shell.pack(fill="both", expand=True)

        container = ttk.Frame(shell, style="Panel.TFrame")
        container.pack(fill="both", expand=True)
        container.columnconfigure(0, weight=56)
        container.columnconfigure(1, weight=44)
        container.rowconfigure(0, weight=1)

        hero = ttk.Frame(container, style="Hero.TFrame", padding=30)
        hero.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        ttk.Label(hero, text="Welcome to Secure Vault", style="HeroTitle.TLabel").pack(anchor="w")
        ttk.Label(
            hero,
            text="Save your passwords in one safe place. Only you can see them.",
            style="HeroSub.TLabel",
        ).pack(anchor="w", pady=(10, 18))

        intro_points = [
            "• Your passwords stay on your device (we don't see them)",
            "• Add passwords by typing or bring them from your browser",
            "• Use the extension to fill passwords in websites",
        ]
        for p in intro_points:
            ttk.Label(hero, text=p, style="Bullet.TLabel").pack(anchor="w", pady=4)

        # Important notice about passphrases - black text in all themes
        notice_frame = ttk.Frame(hero, style="Hero.TFrame")
        notice_frame.pack(anchor="w", pady=(20, 0), fill="x")
        tk.Label(
            notice_frame,
            text="🔑 Remember these two passwords",
            bg=self.palette["hero"],
            fg="#000000",  # Black text in all themes
            font=self.font_button,
        ).pack(anchor="w", pady=(0, 4))
        tk.Label(
            notice_frame,
            text="• Login password: You type this every time you open the app. Keep it secret.",
            bg=self.palette["hero"],
            fg="#000000",  # Black text in all themes
            font=self.font_base,
        ).pack(anchor="w", pady=2)
        tk.Label(
            notice_frame,
            text="• Recovery passphrase: If you forget your login passphrase, this one lets you set a new one. Write it down and keep it safe!",
            bg=self.palette["hero"],
            fg="#000000",  # Black text in all themes
            font=self.font_base,
        ).pack(anchor="w", pady=2)
        tk.Label(
            notice_frame,
            text="• Use different passphrases for each. Both must be at least 12 characters (3 of: lowercase, uppercase, digit, symbol).",
            bg=self.palette["hero"],
            fg="#000000",  # Black text in all themes
            font=self.font_base,
        ).pack(anchor="w", pady=2)

        card = ttk.Frame(container, style="AuthCard.TFrame", padding=24)
        card.grid(row=0, column=1, sticky="nsew")
        ttk.Label(card, text="Open your vault", style="AuthTitle.TLabel").pack(anchor="w")
        ttk.Label(card, text="Sign in or create a new account", style="AuthSub.TLabel").pack(anchor="w", pady=(4, 14))

        notebook = ttk.Notebook(card)
        notebook.pack(fill="both", expand=True)

        self.login_tab = ttk.Frame(notebook, style="AuthCard.TFrame", padding=(8, 10, 8, 8))
        self.register_tab = ttk.Frame(notebook, style="AuthCard.TFrame", padding=(8, 10, 8, 8))
        notebook.add(self.login_tab, text="I have an account")
        notebook.add(self.register_tab, text="Create account")

        self.login_username = tk.StringVar()
        self.login_pass = tk.StringVar()

        ttk.Label(self.login_tab, text="Your name (username)", style="AuthSub.TLabel").grid(row=0, column=0, sticky="w")
        self.login_user_entry = self._make_entry(self.login_tab, self.login_username)
        self.login_user_entry.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        self.login_pass_entry = self._make_password_row(self.login_tab, "Your login passphrase", self.login_pass, row=2)
        self.login_tab.columnconfigure(0, weight=1)

        login_btn_row = ttk.Frame(self.login_tab, style="AuthCard.TFrame")
        login_btn_row.grid(row=4, column=0, sticky="ew", pady=(2, 0))
        self.login_btn = ttk.Button(login_btn_row, text="Login", command=self._login, style="Accent.TButton")
        self.login_btn.pack(side="left")
        
        # Forgot passphrase link
        forgot_frame = ttk.Frame(self.login_tab, style="AuthCard.TFrame")
        forgot_frame.grid(row=5, column=0, sticky="w", pady=(8, 0))
        ttk.Button(
            forgot_frame,
            text="Forgot login passphrase?",
            command=self._open_forgot_passphrase_dialog,
            style="Link.TButton"
        ).pack(side="left")

        # Phase 4: Forgot both phrases — restore from backup
        ttk.Button(
            self.login_tab,
            text="Forgot both? Restore from a backup file",
            command=self._open_restore_from_backup_wizard,
            style="Link.TButton",
        ).grid(row=6, column=0, sticky="w", pady=(4, 0))

        self.reg_username = tk.StringVar()
        self.reg_email = tk.StringVar()
        self.reg_login_pass = tk.StringVar()
        self.reg_recovery_pass = tk.StringVar()

        ttk.Label(self.register_tab, text="Choose a username (your name for this app)", style="AuthSub.TLabel").grid(row=0, column=0, sticky="w")
        self.reg_user_entry = self._make_entry(self.register_tab, self.reg_username)
        self.reg_user_entry.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        ttk.Label(self.register_tab, text="Email", style="AuthSub.TLabel").grid(row=2, column=0, sticky="w")
        self.reg_email_entry = self._make_entry(self.register_tab, self.reg_email)
        self.reg_email_entry.grid(row=3, column=0, sticky="ew", pady=(0, 8))

        self.reg_login_entry = self._make_password_row(self.register_tab, "Login passphrase (≥12 chars, 3 of: lower, upper, digit, symbol)", self.reg_login_pass, row=4)
        self.reg_recover_entry = self._make_password_row(self.register_tab, "Recovery passphrase (≥12 chars – write it down!)", self.reg_recovery_pass, row=6)

        self.register_tab.columnconfigure(0, weight=1)
        ttk.Button(self.register_tab, text="Create account", command=self._register, style="Accent.TButton").grid(row=8, column=0, sticky="w", pady=(4, 0))

        def on_enter(_e=None):
            try:
                current = notebook.select()
                if current == str(self.register_tab):
                    self._register()
                else:
                    self._login()
            except Exception:
                self._login()

        self.root.bind("<Return>", on_enter)

    def _open_forgot_passphrase_dialog(self):
        """Open modal dialog for passphrase recovery."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Reset your login password")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.palette["bg"])
        
        # Center dialog
        dialog.update_idletasks()
        w = 500
        h = 450
        x = (dialog.winfo_screenwidth() // 2) - (w // 2)
        y = (dialog.winfo_screenheight() // 2) - (h // 2)
        dialog.geometry(f"{w}x{h}+{x}+{y}")
        dialog.resizable(True, True)  # Allow resizing
        dialog.minsize(450, 400)  # Set minimum size to prevent too small
        
        # Container frame styled like AuthCard
        container = ttk.Frame(dialog, style="AuthCard.TFrame", padding=24)
        container.pack(fill="both", expand=True)
        
        ttk.Label(container, text="Set a new login password", style="AuthTitle.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Label(
            container,
            text="Type your recovery password (the one you wrote down). Then choose a new login password.",
            style="AuthSub.TLabel"
        ).pack(anchor="w", pady=(0, 8))
        
        notice_frame = ttk.Frame(container, style="AuthCard.TFrame")
        notice_frame.pack(fill="x", pady=(0, 20))
        tk.Label(
            notice_frame,
            text="You need your recovery password to do this. Keep it written down somewhere safe!",
            bg=self.palette["card_soft"],
            fg="#000000",  # Black text in all themes
            font=self.font_base,
            wraplength=450,
            justify="left",
        ).pack(anchor="w", padx=8, pady=8)
        
        # Local StringVars (do NOT reuse self.login_pass or other session vars)
        username_var = tk.StringVar(value=self.login_username.get().strip())
        recovery_var = tk.StringVar()
        new_login_var = tk.StringVar()
        confirm_var = tk.StringVar()
        
        ttk.Label(container, text="Your username", style="AuthSub.TLabel").pack(anchor="w")
        username_entry = self._make_entry(container, username_var)
        username_entry.pack(fill="x", pady=(0, 10))
        
        # Recovery passphrase - use pack layout instead of grid
        ttk.Label(container, text="Your recovery password", style="AuthSub.TLabel").pack(anchor="w", pady=(0, 0))
        recovery_wrap = ttk.Frame(container, style="AuthCard.TFrame")
        recovery_wrap.pack(fill="x", pady=(0, 10))
        recovery_wrap.columnconfigure(0, weight=1)
        recovery_entry = self._make_entry(recovery_wrap, recovery_var, show="*")
        recovery_entry.grid(row=0, column=0, sticky="ew")
        
        # New login passphrase
        ttk.Label(container, text="New login password (at least 12 characters)", style="AuthSub.TLabel").pack(anchor="w", pady=(0, 0))
        new_login_wrap = ttk.Frame(container, style="AuthCard.TFrame")
        new_login_wrap.pack(fill="x", pady=(0, 10))
        new_login_wrap.columnconfigure(0, weight=1)
        new_login_entry = self._make_entry(new_login_wrap, new_login_var, show="*")
        new_login_entry.grid(row=0, column=0, sticky="ew")
        
        # Confirm new login passphrase
        ttk.Label(container, text="Type the new login password again", style="AuthSub.TLabel").pack(anchor="w", pady=(0, 0))
        confirm_wrap = ttk.Frame(container, style="AuthCard.TFrame")
        confirm_wrap.pack(fill="x", pady=(0, 10))
        confirm_wrap.columnconfigure(0, weight=1)
        confirm_entry = self._make_entry(confirm_wrap, confirm_var, show="*")
        confirm_entry.grid(row=0, column=0, sticky="ew")
        
        # Buttons
        btn_frame = ttk.Frame(container, style="AuthCard.TFrame")
        btn_frame.pack(fill="x", pady=(20, 0))
        
        def on_reset():
            self._do_passphrase_reset(dialog, username_var, recovery_var, new_login_var, confirm_var)
        
        def on_cancel():
            # Clear sensitive fields
            recovery_var.set("")
            new_login_var.set("")
            confirm_var.set("")
            dialog.destroy()
        
        ttk.Button(btn_frame, text="Set new login password", command=on_reset, style="Accent.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(btn_frame, text="Cancel", command=on_cancel, style="Secondary.TButton").pack(side="left")
        
        # Keyboard bindings
        def on_enter_key(_e=None):
            on_reset()
        
        def on_esc_key(_e=None):
            on_cancel()
        
        dialog.bind("<Return>", on_enter_key)
        dialog.bind("<Escape>", on_esc_key)
        
        # Focus on username field
        username_entry.focus_set()

    def _open_restore_from_backup_wizard(self):
        """Phase 4: Wizard for reset + restore from local backup when user forgot both phrases."""
        dialog = tk.Toplevel(self.root)
        dialog.title("Restore from a backup file")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.palette["bg"])
        dialog.minsize(600, 540)
        w, h = 660, 580
        x = (dialog.winfo_screenwidth() // 2) - (w // 2)
        y = (dialog.winfo_screenheight() // 2) - (h // 2)
        dialog.geometry(f"{w}x{h}+{x}+{y}")

        state = {"step": 1, "username": "", "file_path": "", "recovery_key": "", "preview_meta": None, "enc_priv_pem": None}
        dialog._restore_state = state

        container = ttk.Frame(dialog, style="AuthCard.TFrame", padding=20)
        container.pack(fill="both", expand=True)

        def clear_step():
            for w in container.winfo_children():
                w.destroy()

        def step1():
            clear_step()
            ttk.Label(container, text="Step 1: Reset this account", style="AuthTitle.TLabel").pack(anchor="w", pady=(0, 8))
            ttk.Label(
                container,
                text="You forgot both your login and recovery passwords. We'll clear this account, then you'll restore from a backup file and set new passwords. Your backup file is not deleted.",
                style="Sub.TLabel",
                wraplength=500,
            ).pack(anchor="w", pady=(0, 12))
            ttk.Label(container, text="Username of the account to reset:", style="Sub.TLabel").pack(anchor="w", pady=(4, 2))
            username_var = tk.StringVar(value=state.get("username", ""))
            un_entry = self._make_entry(container, username_var)
            un_entry.pack(fill="x", pady=(0, 12))
            ttk.Label(
                container,
                text='Type "DELETE MY VAULT" below to confirm reset. This clears vault, sessions, and keys for this account.',
                style="Sub.TLabel",
                wraplength=500,
            ).pack(anchor="w", pady=(0, 4))
            confirm_var = tk.StringVar()
            conf_entry = self._make_entry(container, confirm_var)
            conf_entry.pack(fill="x", pady=(0, 12))

            def do_reset():
                username = username_var.get().strip()
                if not username:
                    messagebox.showwarning("Restore", "Enter username.", parent=dialog)
                    return
                if confirm_var.get().strip() != "DELETE MY VAULT":
                    messagebox.showwarning("Restore", 'You must type "DELETE MY VAULT" to confirm.', parent=dialog)
                    return
                btn_reset.config(state="disabled")
                ok, msg = self.api.reset_account_data_loss(username)
                if not ok:
                    messagebox.showerror("Reset failed", msg, parent=dialog)
                    btn_reset.config(state="normal")
                    return
                state["username"] = username
                state["step"] = 2
                step2()

            btn_row = ttk.Frame(container, style="AuthCard.TFrame")
            btn_row.pack(anchor="w", pady=(8, 0))
            btn_reset = ttk.Button(btn_row, text="Reset account", command=do_reset, style="Accent.TButton")
            btn_reset.pack(side="left", padx=(0, 8))
            ttk.Button(btn_row, text="Cancel", command=dialog.destroy, style="Secondary.TButton").pack(side="left")

        def step2():
            clear_step()
            ttk.Label(container, text="Step 2: Pick your backup file and enter its password", style="AuthTitle.TLabel").pack(anchor="w", pady=(0, 8))
            ttk.Label(container, text="Backup file:", style="Sub.TLabel").pack(anchor="w", pady=(4, 2))
            path_var = tk.StringVar(value=state.get("file_path", ""))
            path_row = ttk.Frame(container, style="AuthCard.TFrame")
            path_row.pack(fill="x")
            self._make_entry(path_row, path_var).pack(side="left", fill="x", expand=True, padx=(0, 8))

            def pick_file():
                p = filedialog.askopenfilename(
                    title="Select encrypted backup",
                    filetypes=[("Backup files", "*.enc *.json"), ("All files", "*.*")],
                )
                if p:
                    path_var.set(p)

            ttk.Button(path_row, text="Browse", command=pick_file).pack(side="left")
            ttk.Label(container, text="Enter your backup recovery key or backup password:", style="Sub.TLabel").pack(anchor="w", pady=(8, 2))
            key_var = tk.StringVar(value=state.get("recovery_key", ""))
            self._make_password_entry_with_eye(container, key_var, mask="•").pack(fill="x", pady=(0, 8))

            preview_text = tk.Text(container, height=6, wrap="word", font=self.font_small, state="disabled")
            preview_text.pack(fill="x", pady=(8, 0))

            def do_validate():
                path = path_var.get().strip()
                if not path:
                    messagebox.showwarning("Restore", "Select a backup file.", parent=dialog)
                    return
                if not Path(path).exists():
                    messagebox.showerror("Restore", "File not found.", parent=dialog)
                    return
                key = key_var.get().strip()
                if not key:
                    messagebox.showwarning("Restore", "Enter your backup recovery key or password.", parent=dialog)
                    return
                ok, msg = self.api.validate_backup_package_auto(path, key)
                if not ok:
                    messagebox.showerror("Validation failed", msg, parent=dialog)
                    return
                ok_preview, msg_preview, meta = self.api.preview_backup_metadata(path)
                if not ok_preview:
                    return
                state["file_path"] = path
                state["recovery_key"] = key
                state["preview_meta"] = meta
                preview_text.configure(state="normal")
                preview_text.delete("1.0", "end")
                preview_text.insert("end", f"Backup ID: {meta.get('backup_id', '')}\n")
                preview_text.insert("end", f"Created: {meta.get('created_at', '')}\n")
                preview_text.insert("end", f"Entries: {meta.get('entry_count', 0)}\n")
                preview_text.insert("end", f"User ID in backup: {meta.get('user_id', '')}\n")
                preview_text.configure(state="disabled")

            def do_restore():
                path = path_var.get().strip()
                key = key_var.get().strip()
                if not path or not key:
                    messagebox.showwarning("Restore", "Select file and enter recovery key/password.", parent=dialog)
                    return
                username = state.get("username")
                if not username:
                    messagebox.showerror("Restore", "Missing username.", parent=dialog)
                    return
                btn_restore.config(state="disabled")
                ok, msg, enc_priv = self.api.restore_backup_from_local_file(username, path, key, mode=None)
                if not ok:
                    try:
                        self.security_alert_service.notify_security_alert(
                            "backup_restore_failed", {"reason": msg}
                        )
                    except Exception:
                        pass
                    messagebox.showerror("Restore failed", msg, parent=dialog)
                    btn_restore.config(state="normal")
                    return
                state["enc_priv_pem"] = enc_priv
                state["step"] = 3
                step3()

            btn_row = ttk.Frame(container, style="AuthCard.TFrame")
            btn_row.pack(anchor="w", pady=(12, 0))
            ttk.Button(btn_row, text="Validate backup", command=do_validate, style="Secondary.TButton").pack(side="left", padx=(0, 8))
            btn_restore = ttk.Button(btn_row, text="Restore", command=do_restore, style="Accent.TButton")
            btn_restore.pack(side="left", padx=(0, 8))
            ttk.Button(btn_row, text="Cancel", command=dialog.destroy, style="Secondary.TButton").pack(side="left")

        def step3():
            clear_step()
            ttk.Label(container, text="Step 3: Choose new passwords", style="AuthTitle.TLabel").pack(anchor="w", pady=(0, 8))
            ttk.Label(
                container,
                text="Pick a new login password and a new recovery password. You'll use the login password to open the app next time.",
                style="Sub.TLabel",
                wraplength=500,
            ).pack(anchor="w", pady=(0, 12))
            ttk.Label(container, text="New login password (at least 12 characters):", style="Sub.TLabel").pack(anchor="w", pady=(4, 2))
            new_login_var = tk.StringVar()
            self._make_password_entry_with_eye(container, new_login_var, mask="•").pack(fill="x", pady=(0, 4))
            ttk.Label(container, text="Type it again:", style="Sub.TLabel").pack(anchor="w", pady=(4, 2))
            new_login_confirm_var = tk.StringVar()
            self._make_password_entry_with_eye(container, new_login_confirm_var, mask="•").pack(fill="x", pady=(0, 8))
            ttk.Label(container, text="New recovery password (at least 12 characters – write it down!):", style="Sub.TLabel").pack(anchor="w", pady=(4, 2))
            new_recovery_var = tk.StringVar()
            self._make_password_entry_with_eye(container, new_recovery_var, mask="•").pack(fill="x", pady=(0, 4))
            ttk.Label(container, text="Type it again:", style="Sub.TLabel").pack(anchor="w", pady=(4, 2))
            new_recovery_confirm_var = tk.StringVar()
            self._make_password_entry_with_eye(container, new_recovery_confirm_var, mask="•").pack(fill="x", pady=(0, 12))

            def do_rekey():
                login = new_login_var.get()
                login_confirm = new_login_confirm_var.get()
                rec = new_recovery_var.get()
                rec_confirm = new_recovery_confirm_var.get()
                ok_l, msg_l = self.api.validate_passphrase(login)
                if not ok_l:
                    messagebox.showwarning("Validation", f"New login passphrase: {msg_l}", parent=dialog)
                    return
                if login != login_confirm:
                    messagebox.showwarning("Validation", "Login passphrase and confirmation do not match.", parent=dialog)
                    return
                ok_r, msg_r = self.api.validate_passphrase(rec)
                if not ok_r:
                    messagebox.showwarning("Validation", f"New recovery passphrase: {msg_r}", parent=dialog)
                    return
                if rec != rec_confirm:
                    messagebox.showwarning("Validation", "Recovery passphrase and confirmation do not match.", parent=dialog)
                    return
                username = state.get("username")
                enc = state.get("enc_priv_pem")
                if not username or not enc:
                    messagebox.showerror("Error", "Restore state lost. Please start over.", parent=dialog)
                    dialog.destroy()
                    return
                ok, msg = self.api.finalize_post_restore_rekey(username, login, rec, enc)
                state["enc_priv_pem"] = None  # clear sensitive state
                if not ok:
                    try:
                        self.security_alert_service.notify_security_alert(
                            "post_restore_rekey_failed", {"reason": msg}
                        )
                    except Exception:
                        pass
                    messagebox.showerror("Rekey failed", msg, parent=dialog)
                    return
                state["step"] = 4
                step4()

            btn_row = ttk.Frame(container, style="AuthCard.TFrame")
            btn_row.pack(anchor="w", pady=(8, 0))
            ttk.Button(btn_row, text="Save and finish", command=do_rekey, style="Accent.TButton").pack(side="left", padx=(0, 8))
            ttk.Button(btn_row, text="Cancel", command=dialog.destroy, style="Secondary.TButton").pack(side="left")

        def step4():
            clear_step()
            ttk.Label(container, text="All done!", style="AuthTitle.TLabel").pack(anchor="w", pady=(0, 8))
            ttk.Label(
                container,
                text="Your passwords are back. Close this window and sign in with your new login password.",
                style="Sub.TLabel",
                wraplength=500,
            ).pack(anchor="w", pady=(0, 12))
            ttk.Button(container, text="Close", command=dialog.destroy, style="Accent.TButton").pack(anchor="w")

        step1()

    def _do_passphrase_reset(self, dialog, username_var, recovery_var, new_login_var, confirm_var):
        """Perform passphrase reset using recovery passphrase."""
        username = username_var.get().strip()
        recovery_pass = recovery_var.get()
        new_login = new_login_var.get()
        confirm_login = confirm_var.get()
        
        # Clear sensitive fields on any exit path
        def clear_and_close():
            recovery_var.set("")
            new_login_var.set("")
            confirm_var.set("")
            dialog.destroy()
        
        # Validate username
        ok_u, msg_u = CryptoUtils.validate_input(username, "username")
        if not ok_u:
            messagebox.showerror("Validation", msg_u, parent=dialog)
            clear_and_close()
            return
        
        # Check lockout
        try:
            is_locked, lock_msg, remaining = self.api.check_lockout(username, "recovery", client_fingerprint="tk-desktop")
            if is_locked:
                messagebox.showerror("Account Locked", lock_msg, parent=dialog)
                clear_and_close()
                return
        except Exception as e:
            messagebox.showerror("Error", f"Failed to check lockout: {e}", parent=dialog)
            clear_and_close()
            return
        
        # Validate new login passphrase
        ok_phrase, msg_phrase = self.api.validate_passphrase(new_login)
        if not ok_phrase:
            messagebox.showerror("Validation", f"New login passphrase: {msg_phrase}", parent=dialog)
            recovery_var.set("")
            new_login_var.set("")
            confirm_var.set("")
            return
        
        if new_login != confirm_login:
            messagebox.showerror("Validation", "New login passphrase and confirmation do not match.", parent=dialog)
            recovery_var.set("")
            new_login_var.set("")
            confirm_var.set("")
            return
        
        if new_login == recovery_pass:
            messagebox.showerror("Validation", "New login passphrase must be different from recovery passphrase.", parent=dialog)
            recovery_var.set("")
            new_login_var.set("")
            confirm_var.set("")
            return
        
        # Check if identity exists locally
        purposes = ["auth", "signing", "encryption"]
        bundle_paths = {}
        for purpose in purposes:
            try:
                path = self._safe_key_path(username, purpose)
                if not path.exists():
                    messagebox.showerror("Identity Not Found", "Identity not found on this device.", parent=dialog)
                    # Only record attempt if we've already validated inputs
                    try:
                        self.api.record_attempt(username, "recovery", False, client_fingerprint="tk-desktop")
                    except Exception:
                        pass
                    clear_and_close()
                    return
                bundle_paths[purpose] = path
            except Exception as e:
                messagebox.showerror("Error", f"Failed to access key files: {e}", parent=dialog)
                clear_and_close()
                return
        
        # Load bundles and recover private keys
        recovered_keys = {}
        for purpose in purposes:
            try:
                bundle = json.loads(bundle_paths[purpose].read_text(encoding="utf-8"))
                private_key_bytes = LocalKeyManager.unlock_with_recovery(bundle, recovery_pass)
                if not private_key_bytes:
                    # Generic error - don't reveal which key failed
                    self.api.record_attempt(username, "recovery", False, client_fingerprint="tk-desktop")
                    messagebox.showerror("Recovery Failed", "Invalid recovery passphrase.", parent=dialog)
                    recovery_var.set("")
                    new_login_var.set("")
                    confirm_var.set("")
                    return
                recovered_keys[purpose] = private_key_bytes
            except Exception as e:
                # Generic error
                self.api.record_attempt(username, "recovery", False, client_fingerprint="tk-desktop")
                messagebox.showerror("Recovery Failed", "Invalid recovery passphrase.", parent=dialog)
                recovery_var.set("")
                new_login_var.set("")
                confirm_var.set("")
                return
        
        # All keys recovered successfully
        try:
            self.api.record_attempt(username, "recovery", True, client_fingerprint="tk-desktop")
        except Exception:
            pass
        
        # Re-protect all bundles with new login passphrase
        try:
            for purpose in purposes:
                new_bundle = LocalKeyManager.protect_key_bundle(recovered_keys[purpose], new_login, recovery_pass)
                self._secure_write_json(bundle_paths[purpose], new_bundle)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save new passphrase: {e}", parent=dialog)
            recovery_var.set("")
            new_login_var.set("")
            confirm_var.set("")
            return
        
        # Audit log (attribute to user if found)
        try:
            user = self.api.user_service.get_user_by_username(username)
            uid = int(user["id"]) if user and user.get("id") is not None else None
            self.api.audit.log_event("LOGIN_PASSPHRASE_RESET", {"username": username, "client_fingerprint": "tk-desktop"}, user_id=uid)
        except Exception:
            pass  # Non-critical
        
        # Success
        messagebox.showinfo(
            "Success",
            "Login passphrase reset successfully. You can now sign in with the new passphrase.",
            parent=dialog
        )
        
        # Prefill username and clear login passphrase field
        self.login_username.set(username)
        self.login_pass.set("")
        
        clear_and_close()

    def _register(self):
        bus = get_bus()
        bus.info("Register", "Validating registration data...")
        
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        login_pass = self.reg_login_pass.get()
        recovery_pass = self.reg_recovery_pass.get()

        ok_lp, msg_lp = self.api.validate_passphrase(login_pass)
        if not ok_lp:
            bus.error("Register", "Passphrase validation failed")
            return messagebox.showerror("Validation", f"Login passphrase: {msg_lp}")
        ok_rp, msg_rp = self.api.validate_passphrase(recovery_pass)
        if not ok_rp:
            bus.error("Register", "Recovery passphrase validation failed")
            return messagebox.showerror("Validation", f"Recovery passphrase: {msg_rp}")
        if login_pass == recovery_pass:
            bus.error("Register", "Passphrase validation failed")
            return messagebox.showerror("Validation", "Recovery passphrase must be different.")

        ok_u, msg_u = CryptoUtils.validate_input(username, "username")
        if not ok_u:
            bus.error("Register", "Username validation failed")
            return messagebox.showerror("Validation", msg_u)

        ok_e, msg_e = CryptoUtils.validate_input(email, "email")
        if not ok_e:
            bus.error("Register", "Email validation failed")
            return messagebox.showerror("Validation", msg_e)

        try:
            bus.info("Register", "Generating RSA key pairs...", step="Key Gen")
            api_bundle = {}
            for purpose in ["auth", "signing", "encryption"]:
                priv = CryptoUtils.generate_rsa_key_pair(3072)
                priv_pem = CryptoUtils.serialize_private_key(priv)
                pub_pem = CryptoUtils.serialize_public_key(priv.public_key()).decode()

                bus.info("Register", f"Protecting {purpose} key...", step="Key Protect")
                protected = LocalKeyManager.protect_key_bundle(priv_pem, login_pass, recovery_pass)
                self._secure_write_json(self._safe_key_path(username, purpose), protected)
                api_bundle[purpose] = {"pub_pem": pub_pem}

            bus.info("Register", "Creating user account...", step="API Call")
            ok, msg = self.api.register_user(username, email, api_bundle)
            if ok:
                self.reg_username.set("")
                self.reg_email.set("")
                self.reg_login_pass.set("")
                self.reg_recovery_pass.set("")
                bus.ok("Register", "Registration complete")
                messagebox.showinfo("Success", msg)
                self._set_status("Account created successfully")
            else:
                bus.error("Register", "Registration failed")
                messagebox.showerror("Registration failed", msg)
        except Exception as e:
            bus.error("Register", "Registration failed")
            messagebox.showerror("Registration failed", str(e))

    def _login(self):
        bus = get_bus()
        bus.info("Login", "Validating credentials...")
        
        def _reenable_login_btn():
            if getattr(self, "login_btn", None):
                try:
                    self.login_btn.config(state="normal")
                except Exception:
                    pass

        if getattr(self, "login_btn", None):
            try:
                self.login_btn.config(state="disabled")
            except Exception:
                pass

        username = self.login_username.get().strip()
        passphrase = self.login_pass.get()

        ok_u, msg_u = CryptoUtils.validate_input(username, "username")
        if not ok_u:
            bus.error("Login", "Validation failed")
            _reenable_login_btn()
            return messagebox.showerror("Validation", msg_u)

        if not passphrase:
            bus.error("Login", "Missing passphrase")
            _reenable_login_btn()
            return messagebox.showerror("Validation", "Enter your login passphrase.")

        # Progressive backoff: block rapid wrong-attempt retries
        must_wait, wait_seconds = self.api.check_unlock_backoff(username)
        if must_wait and wait_seconds > 0:
            try:
                from services.structured_logger import get_logger
                get_logger().info("Login blocked: backoff_active, username=%s, wait=%ds", username, wait_seconds)
            except Exception:
                pass
            messagebox.showwarning(
                "Too many attempts",
                f"Too many failed attempts. Try again in {wait_seconds} seconds.",
            )
            if getattr(self, "login_btn", None):
                self.root.after(wait_seconds * 1000, _reenable_login_btn)
            return

        try:
            auth_path = self._safe_key_path(username, "auth")
            enc_path = self._safe_key_path(username, "encryption")
            sign_path = self._safe_key_path(username, "signing")
        except Exception as e:
            bus.error("Login", "Key path error")
            _reenable_login_btn()
            return messagebox.showerror("Login", str(e))

        if not auth_path.exists():
            bus.error("Login", "Identity not found on this device")
            _reenable_login_btn()
            return messagebox.showerror("Login", "Identity not found on this device.")

        try:
            bus.info("Login", "Deriving encryption key...", step="Key Derive")
            auth_bundle = json.loads(auth_path.read_text(encoding="utf-8"))
            auth_priv = LocalKeyManager.unlock_key_from_bundle(auth_bundle, passphrase)
            if not auth_priv:
                bus.error("Login", "Invalid passphrase")
                self.api.record_unlock_failure(username)
                self.login_pass.set("")
                _reenable_login_btn()
                return messagebox.showerror("Login", "Invalid passphrase.")

            bus.info("Login", "Authenticating with server...", step="Auth")
            ok, user, _, msg = self.api.login_user(
                username,
                priv_key_data=auth_priv,
                client_fingerprint="tk-desktop",
            )
            if not ok:
                bus.error("Login", "Authentication failed")
                self.login_pass.set("")
                _reenable_login_btn()
                return messagebox.showerror("Login failed", msg)

            enc_priv = None
            sign_priv = None

            if enc_path.exists():
                enc_bundle = json.loads(enc_path.read_text(encoding="utf-8"))
                enc_priv_bytes = LocalKeyManager.unlock_key_from_bundle(enc_bundle, passphrase)
                if enc_priv_bytes:
                    enc_priv = bytearray(enc_priv_bytes) if isinstance(enc_priv_bytes, bytes) else enc_priv_bytes
            if sign_path.exists():
                sign_bundle = json.loads(sign_path.read_text(encoding="utf-8"))
                sign_priv_bytes = LocalKeyManager.unlock_key_from_bundle(sign_bundle, passphrase)
                if sign_priv_bytes:
                    sign_priv = bytearray(sign_priv_bytes) if isinstance(sign_priv_bytes, bytes) else sign_priv_bytes

            if not enc_priv:
                self.login_pass.set("")
                _reenable_login_btn()
                return messagebox.showerror(
                    "Login failed",
                    "Could not unlock encryption key with this phrase. Check local key files.",
                )

            self.login_pass.set("")

            bus.info("Login", "Creating session...", step="Session")
            self.current_user = dict(user)
            self.session = {
                "user_id": int(user["id"]),
                "username": username,
                "enc_priv": enc_priv,
                "sign_priv": sign_priv,
            }

            self.api.reset_unlock_backoff(username)
            self.session_security.on_login(int(user["id"]))
            self._arm_idle_lock()
            ok_ext, msg_ext = self.extension_server.start()

            bus.ok("Login", "Login successful")
            self._build_main_view()

            try:
                self.root.state('zoomed')
            except Exception:
                try:
                    self.root.attributes('-zoomed', True)
                except Exception:
                    try:
                        self.root.state('normal')
                        sw = self.root.winfo_screenwidth()
                        sh = self.root.winfo_screenheight()
                        self.root.geometry(f"{sw}x{sh}+0+0")
                    except Exception:
                        pass
            
            if ok_ext:
                self._set_status(f"Logged in as {username} · Extension API running on http://127.0.0.1:5005")
            else:
                self._set_status(f"Logged in as {username} · Extension API error: {msg_ext}")
        except Exception as e:
            try:
                self.login_pass.set("")
            except Exception:
                pass
            _reenable_login_btn()
            messagebox.showerror("Login failed", str(e))

    # ---------------------- main layout ----------------------
    def _build_main_view(self):
        self._clear_root()
        # Unbind root Return so Enter in main view doesn't trigger login or unlock
        try:
            self.root.unbind("<Return>")
        except Exception:
            pass
        self._setup_style()  # Re-apply ttk styles (fixes disappearing text after unlock on Windows)
        self._set_main_window()
        # IMPROVED: Ensure content is visible after building
        self.root.update_idletasks()

        self.main = ttk.Frame(self.root)
        self.main.pack(fill="both", expand=True)

        # Top bar
        self.topbar = tk.Frame(self.main, bg=self.palette["topbar"], height=68, bd=0, highlightthickness=0)
        self.topbar.pack(side="top", fill="x")
        self.topbar.pack_propagate(False)
        self.active_nav_key = None

        # Brand frame - clean design without border
        brand = tk.Frame(
            self.topbar, 
            bg=self.palette["topbar"]
        )
        brand.pack(side="left", padx=14, pady=8)

        # Determine text color - ensure maximum contrast
        if self._current_theme_name == "light":
            brand_fg = "#000000"  # Pure black for light theme
        else:
            brand_fg = "#ffffff"  # Pure white for dark/high contrast
        
        # Create "Secure Vault" title label - ensure it's visible
        brand_title = tk.Label(
            brand,
            text="Secure Vault",
            bg=self.palette["topbar"],
            fg=brand_fg,
            font=self.font_brand,
            anchor="w"
        )
        brand_title.pack(anchor="w", padx=10, pady=(6, 2))
        
        # Create username label - ensure it's visible
        username_text = f"User: {self.session['username']}"
        username_label = tk.Label(
            brand,
            text=username_text,
            bg=self.palette["topbar"],
            fg=brand_fg,
            font=self.font_small,
            anchor="w"
        )
        username_label.pack(anchor="w", padx=10, pady=(0, 6))
        
        # Force update and set frame width to ensure visibility
        self.root.update_idletasks()
        try:
            # Get actual required widths
            title_w = brand_title.winfo_reqwidth() or 150
            user_w = username_label.winfo_reqwidth() or 200
            needed_width = max(title_w, user_w) + 30
            brand.config(width=max(250, needed_width))
        except Exception:
            # Fallback: use safe default
            brand.config(width=250)
        
        # Prevent frame from shrinking below content size
        brand.pack_propagate(False)

        nav_holder = tk.Frame(self.topbar, bg=self.palette["topbar"])
        nav_holder.pack(side="left", padx=20)

        self.nav_buttons = {}
        nav_items = [
            ("Overview", "dashboard"),
            ("My passwords", "vault"),
            ("Import", "import"),
            ("Backup", "backup"),
            ("Activity Log", "activity_log"),
            ("Settings", "settings"),
            ("Extension", "extension"),
        ]

        for text, key in nav_items:
            b = tk.Button(
                nav_holder,
                text=text,
                relief="flat",
                bd=0,
                bg=self.palette["topbar"],
                fg=self.palette["topbar_text"],
                activebackground=self.palette.get("topbar_hover"),
                activeforeground=self.palette.get("topbar_text"),  # FIXED: Use theme text color for visibility
                font=self.font_nav,
                padx=14,
                pady=8,
                cursor="hand2",
                highlightthickness=0,
                takefocus=0,
                command=lambda k=key: self.show_page(k),
            )
            b.pack(side="left", padx=3)
            b.bind("<Enter>", lambda _e, k=key: self._set_nav_hover(k, True))
            b.bind("<Leave>", lambda _e, k=key: self._set_nav_hover(k, False))
            self.nav_buttons[key] = b

        self.lock_btn = tk.Button(
            self.topbar,
            text="Lock (Alt+L)",
            relief="flat",
            bg=self.palette.get("topbar"),
            fg=self.palette.get("topbar_text"),
            activebackground=self.palette.get("topbar_hover"),
            activeforeground=self.palette.get("topbar_text"),
            font=self.font_nav,
            padx=14,
            pady=8,
            cursor="hand2",
            highlightthickness=0,
            bd=0,
            takefocus=0,
            command=self._do_manual_lock,
        )
        self.lock_btn.pack(side="right", padx=(12, 4), pady=8)
        self._bind_hover_button(self.lock_btn, self.palette.get("topbar"), self.palette.get("topbar_hover"), self.palette.get("topbar_text"), self.palette.get("topbar_text"))

        self.logout_btn = tk.Button(
            self.topbar,
            text="Logout",
            relief="flat",
            bg=self.palette.get("danger"),
            fg="white",
            activebackground=self.palette.get("danger_hover"),
            activeforeground="white",
            font=self.font_nav,
            padx=14,
            pady=8,
            cursor="hand2",
            highlightthickness=0,
            bd=0,
            takefocus=0,
            command=self._logout,
        )
        self.logout_btn.pack(side="right", padx=4, pady=8)
        self._bind_hover_button(self.logout_btn, self.palette.get("danger"), self.palette.get("danger_hover"), "white", "white")

        # Content area - IMPROVED: Ensure proper expansion
        self.content_shell = ttk.Frame(self.main)
        self.content_shell.pack(side="top", fill="both", expand=True)
        self.content_shell.columnconfigure(0, weight=1)
        self.content_shell.rowconfigure(0, weight=1)

        # Security alert banner (above content; shown on publish_alert_to_ui)
        self._alert_banner_frame = tk.Frame(self.content_shell, height=0, bg=self.palette["bg"])
        self._alert_banner_frame.pack(fill="x", side="top")
        self._alert_banner_frame.pack_propagate(False)
        self._alert_banner_autohide_job = None

        self.content = ttk.Frame(self.content_shell, padding=16)
        self.content.pack(fill="both", expand=True)
        self.content.columnconfigure(0, weight=1)
        self.content.rowconfigure(0, weight=1)

        status = ttk.Frame(self.content_shell, style="Panel.TFrame", padding=(12, 6))
        status.pack(fill="x", side="bottom")
        ttk.Label(status, textvariable=self.status_var, style="Sub.TLabel").pack(anchor="w")
        
        # IMPROVED: Bind resize event to ensure content stays visible
        def on_resize(event=None):
            self.root.update_idletasks()
            # Ensure minimum size is maintained (large minimums)
            w, h = self.root.winfo_width(), self.root.winfo_height()
            if w < 1400 or h < 900:
                self.root.minsize(1400, 900)
        
        self.root.bind("<Configure>", on_resize)

        self.frames = {
            "dashboard": self._build_dashboard_page(),
            "vault": self._build_vault_page(),
            "import": self._build_import_page(),
            "backup": self._build_backup_page(),
            "activity_log": self._build_activity_log_page(),
            "sync": self._build_sync_page(),
            "settings": self._build_settings_page(),
            "extension": self._build_extension_page(),
        }

        # Security alert service: UI callback runs on main thread (banner + Windows toast)
        def _on_security_alert(sev, msg, ec, ctx):
            self._show_security_alert_banner(sev, msg, ec, ctx)
            self._show_security_alert_windows_toast(sev, msg, ec, ctx)
        self.security_alert_service.set_publish_alert_to_ui(
            lambda sev, msg, ec, ctx: self.root.after(0, lambda: _on_security_alert(sev, msg, ec, ctx))
        )

        self.show_page("dashboard")
        self._schedule_backup_tick()
        self._schedule_hard_expiry_check()  # Phase 6.4

    def _schedule_backup_cred_prompt(self):
        """Schedule a popup after login/unlock asking for backup credentials if auto backup is enabled."""
        if self._backup_cred_prompt_job:
            try:
                self.root.after_cancel(self._backup_cred_prompt_job)
            except Exception:
                pass
            self._backup_cred_prompt_job = None
        self._backup_cred_prompt_job = self.root.after(
            self.BACKUP_CRED_PROMPT_DELAY_MS,
            self._maybe_prompt_backup_credentials
        )

    def _maybe_prompt_backup_credentials(self):
        """Show popup asking for backup credentials if auto backup is enabled but cache may be empty."""
        self._backup_cred_prompt_job = None
        if not self.session or self.session_security.is_locked():
            return
        try:
            uid = int(self.session["user_id"])
            status = self.api.get_backup_status(uid)
            if not status.get("enabled"):
                return
            if not status.get("backup_on_change_enabled") and not status.get("backup_auto_enabled"):
                return
        except Exception:
            return

        dialog = tk.Toplevel(self.root)
        dialog.title("Auto backup needs credentials")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.palette["bg"])
        dialog.minsize(420, 200)
        f = ttk.Frame(dialog, style="AuthCard.TFrame", padding=24)
        f.pack(fill="both", expand=True)
        f.columnconfigure(0, weight=1)
        ttk.Label(f, text="Auto backup needs your backup credentials", style="AuthTitle.TLabel").pack(anchor="w", pady=(0, 8))
        ttk.Label(
            f,
            text="To run automatic backups (on schedule or when you add/change passwords), enter your backup key or password below and click Save. You can also enter them in the Backup tab.",
            style="Sub.TLabel",
            wraplength=480,
        ).pack(anchor="w", pady=(0, 12))
        cred_var = tk.StringVar()
        cred_row = self._make_password_entry_with_eye(f, cred_var, mask="•")
        cred_row.pack(fill="x", pady=(0, 12))

        def do_save():
            key = (cred_var.get() or "").strip()
            if not key:
                messagebox.showwarning("Backup", "Enter your backup key or password.", parent=dialog)
                return
            ok_resolve, mode, err = self.api.resolve_recovery_factor(uid, key)
            if not ok_resolve:
                messagebox.showwarning("Backup", err or "Invalid backup key or password.", parent=dialog)
                return
            ok, msg = self.api.set_auto_backup_key_for_session(uid, key, mode)
            if not ok:
                messagebox.showwarning("Backup", msg, parent=dialog)
                return
            self._show_toast("Credentials saved for auto backup", "success")
            cred_var.set("")
            dialog.destroy()

        def do_skip():
            dialog.destroy()

        btn_row = ttk.Frame(f, style="AuthCard.TFrame")
        btn_row.pack(anchor="w", pady=(8, 0))
        ttk.Button(btn_row, text="Save", command=do_save, style="Accent.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Skip", command=do_skip, style="Secondary.TButton").pack(side="left")
        dialog.geometry(f"+{self.root.winfo_rootx() + 80}+{self.root.winfo_rooty() + 80}")

    def _schedule_backup_tick(self):
        """Schedule next backup job check (60s)."""
        if self._backup_timer:
            try:
                self.root.after_cancel(self._backup_timer)
            except Exception:
                pass
        self._backup_timer = self.root.after(60000, self._tick_backup_jobs)

    def _tick_backup_jobs(self):
        """Run pending backup jobs (scheduled/change-triggered) without blocking UI.
        
        This runs even when the app is locked - backup credentials are cached in
        backup_service and enc_priv is preserved during lock (only cleared on logout).
        """
        self._backup_timer = None
        if not self.session:
            return
        try:
            enc_priv = self.session.get("enc_priv")
            if not enc_priv:
                self._schedule_backup_tick()
                return
            enc_priv_bytes = bytes(enc_priv) if isinstance(enc_priv, bytearray) else enc_priv
            did_run, msg = self.api.process_pending_backup_jobs(int(self.session["user_id"]), enc_priv_bytes)
            # Only refresh UI if not locked and page exists
            if did_run and hasattr(self, "backup_phase2_status_var") and not self.session_security.is_locked():
                try:
                    self.refresh_backup_page()
                except Exception as re:
                    self.logger.debug("Refresh backup page after auto backup: %s", re)
        except Exception:
            pass
        self._schedule_backup_tick()

    def set_theme(self, theme_name: str):
        self._current_theme_name = theme_name
        tokens = get_theme(theme_name)
        self.palette.update(tokens)
        self._setup_style()
        self._save_config()
        self._build_main_view() # Rebuild to apply colors
        self._show_toast(f"Theme changed to {theme_name}", "success")

    def _build_settings_page(self):
        # Scrollable container so Settings content is never clipped (e.g. on small/DPI screens)
        outer = ttk.Frame(self.content)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)
        canvas = tk.Canvas(
            outer,
            bg=self.palette["bg"],
            highlightthickness=0,
        )
        scrollbar = ttk.Scrollbar(outer)
        inner = ttk.Frame(canvas)
        inner_window = canvas.create_window(0, 0, window=inner, anchor="nw")

        def _on_frame_configure(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(event):
            w = event.width
            canvas.itemconfig(inner_window, width=max(w, inner.winfo_reqwidth()))

        inner.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.configure(command=canvas.yview)

        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        def _scroll_settings(delta_units: int):
            canvas.yview_scroll(-delta_units, "units")

        def _on_mousewheel(event):
            if getattr(event, "delta", None) is not None:
                _scroll_settings(int(event.delta / 120))
            return "break"

        def _on_linux_scroll_up(event):
            _scroll_settings(3)
            return "break"

        def _on_linux_scroll_down(event):
            _scroll_settings(-3)
            return "break"

        def _bind_mousewheel_to_children(parent):
            parent.bind("<MouseWheel>", _on_mousewheel)
            try:
                parent.bind("<Button-4>", _on_linux_scroll_up)
                parent.bind("<Button-5>", _on_linux_scroll_down)
            except Exception:
                pass
            for child in parent.winfo_children():
                _bind_mousewheel_to_children(child)

        canvas.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Button-4>", _on_linux_scroll_up)
        canvas.bind("<Button-5>", _on_linux_scroll_down)

        page = inner
        ttk.Label(page, text="Settings", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Change how the app looks and when it locks", style="Sub.TLabel").pack(anchor="w", pady=(0, 20))

        # Theme Section
        theme_card = ttk.Frame(page, style="Soft.TFrame", padding=16)
        theme_card.pack(fill="x", pady=10)
        ttk.Label(theme_card, text="Look of the app", style="CardTitle.TLabel", background=self.palette["card_soft"]).pack(anchor="w", pady=(0, 10))
        
        btn_row = ttk.Frame(theme_card, style="Soft.TFrame")
        btn_row.pack(anchor="w")
        
        ttk.Button(btn_row, text="Dark", command=lambda: self.set_theme("dark")).pack(side="left", padx=5)
        ttk.Button(btn_row, text="Light", command=lambda: self.set_theme("light")).pack(side="left", padx=5)
        ttk.Button(btn_row, text="High contrast", command=lambda: self.set_theme("high_contrast")).pack(side="left", padx=5)

        sec_card = ttk.Frame(page, style="Soft.TFrame", padding=16)
        sec_card.pack(fill="x", pady=10)
        ttk.Label(sec_card, text="Session Security", style="CardTitle.TLabel", background=self.palette["card_soft"]).pack(anchor="w", pady=(0, 6))
        ttk.Label(sec_card, text="Idle lock = unlock to continue. Hard expiry = sign in again after a maximum time.", style="Sub.TLabel", background=self.palette["card_soft"], wraplength=520).pack(anchor="w", pady=(0, 4))
        ttk.Label(sec_card, text="The app also locks when it stays in the background (unfocused) for the time below.", style="Sub.TLabel", background=self.palette["card_soft"], wraplength=520).pack(anchor="w", pady=(0, 10))

        if not hasattr(self, "idle_lock_enabled_var"):
            self.idle_lock_enabled_var = tk.BooleanVar(value=self.session_security.get_policy().get("idle_lock_enabled", True))
        self.idle_lock_enabled_var.set(self.session_security.get_policy().get("idle_lock_enabled", True))
        self._make_checkbutton(sec_card, "Enable idle lock (lock app when away)", self.idle_lock_enabled_var, background=self.palette["card_soft"]).pack(anchor="w", pady=(0, 4))
        ttk.Label(sec_card, text="Lock app after no use (minutes):", background=self.palette["card_soft"]).pack(anchor="w")
        if not hasattr(self, 'idle_var'):
            self.idle_var = tk.StringVar()
        self.idle_var.set(str(self.idle_timeout_ms // 60000))
        self._make_entry(sec_card, self.idle_var).pack(anchor="w", pady=(0, 10))

        ttk.Label(sec_card, text="Hard session expiry", style="CardTitle.TLabel", background=self.palette["card_soft"]).pack(anchor="w", pady=(8, 4))
        ttk.Label(sec_card, text="After this time you must sign in again, even if you're using the app.", style="Sub.TLabel", background=self.palette["card_soft"], wraplength=520).pack(anchor="w", pady=(0, 6))
        if not hasattr(self, "hard_expiry_enabled_var"):
            self.hard_expiry_enabled_var = tk.BooleanVar(value=self.session_security.get_policy().get("hard_session_expiry_enabled", True))
        self.hard_expiry_enabled_var.set(self.session_security.get_policy().get("hard_session_expiry_enabled", True))
        self._make_checkbutton(sec_card, "Enable hard session expiry", self.hard_expiry_enabled_var, background=self.palette["card_soft"]).pack(anchor="w", pady=(0, 4))
        ttk.Label(sec_card, text="Maximum session length (hours, 1–24):", background=self.palette["card_soft"]).pack(anchor="w")
        if not hasattr(self, "hard_expiry_hours_var"):
            self.hard_expiry_hours_var = tk.StringVar(value=str(self.session_security.get_policy().get("hard_session_expiry_hours", 8)))
        self.hard_expiry_hours_var.set(str(self.session_security.get_policy().get("hard_session_expiry_hours", 8)))
        self._make_entry(sec_card, self.hard_expiry_hours_var).pack(anchor="w", pady=(0, 10))

        if not hasattr(self, "fresh_login_on_restart_var"):
            self.fresh_login_on_restart_var = tk.BooleanVar(value=self.session_security.get_policy().get("require_fresh_login_on_app_restart", True))
        self.fresh_login_on_restart_var.set(self.session_security.get_policy().get("require_fresh_login_on_app_restart", True))
        self._make_checkbutton(sec_card, "Require fresh login on app restart", self.fresh_login_on_restart_var, background=self.palette["card_soft"]).pack(anchor="w", pady=(0, 10))

        ttk.Label(sec_card, text="Step-up re-auth", style="CardTitle.TLabel", background=self.palette["card_soft"]).pack(anchor="w", pady=(8, 4))
        ttk.Label(sec_card, text="Ask for your password again before revealing or copying passwords.", style="Sub.TLabel", background=self.palette["card_soft"], wraplength=520).pack(anchor="w", pady=(0, 6))
        if not hasattr(self, "step_up_enabled_var"):
            self.step_up_enabled_var = tk.BooleanVar(value=self.session_security.get_policy().get("step_up_reauth_enabled", True))
        self.step_up_enabled_var.set(self.session_security.get_policy().get("step_up_reauth_enabled", True))
        self._make_checkbutton(sec_card, "Enable step-up re-auth for sensitive actions", self.step_up_enabled_var, background=self.palette["card_soft"]).pack(anchor="w", pady=(0, 4))
        ttk.Label(sec_card, text="Step-up approval window (seconds, 60–300):", background=self.palette["card_soft"]).pack(anchor="w")
        if not hasattr(self, "step_up_ttl_var"):
            self.step_up_ttl_var = tk.StringVar(value=str(self.session_security.get_policy().get("step_up_ttl_seconds", 90)))
        self.step_up_ttl_var.set(str(self.session_security.get_policy().get("step_up_ttl_seconds", 90)))
        self._make_entry(sec_card, self.step_up_ttl_var).pack(anchor="w", pady=(0, 10))

        ttk.Label(sec_card, text="Security notifications", style="CardTitle.TLabel", background=self.palette["card_soft"]).pack(anchor="w", pady=(8, 4))
        ttk.Label(sec_card, text="In-app banner for security events (lock, expiry, failed unlock, etc.).", style="Sub.TLabel", background=self.palette["card_soft"], wraplength=520).pack(anchor="w", pady=(0, 4))
        if not hasattr(self, "security_alerts_banner_enabled_var"):
            self.security_alerts_banner_enabled_var = tk.BooleanVar(value=getattr(self, "security_alerts_banner_enabled", True))
        self.security_alerts_banner_enabled_var.set(getattr(self, "security_alerts_banner_enabled", True))
        self._make_checkbutton(sec_card, "Show in-app security alerts", self.security_alerts_banner_enabled_var, background=self.palette["card_soft"]).pack(anchor="w", pady=(0, 4))
        if platform.system() == "Windows":
            if not hasattr(self, "security_alerts_windows_toast_enabled_var"):
                self.security_alerts_windows_toast_enabled_var = tk.BooleanVar(value=getattr(self, "security_alerts_windows_toast_enabled", True))
            self.security_alerts_windows_toast_enabled_var.set(getattr(self, "security_alerts_windows_toast_enabled", True))
            self._make_checkbutton(sec_card, "Show Windows notification for security alerts", self.security_alerts_windows_toast_enabled_var, background=self.palette["card_soft"]).pack(anchor="w", pady=(0, 4))
        ttk.Label(sec_card, text="Auto-hide banner after (seconds, 3–30):", background=self.palette["card_soft"]).pack(anchor="w")
        if not hasattr(self, "security_alerts_banner_autohide_var"):
            self.security_alerts_banner_autohide_var = tk.StringVar(value=str(getattr(self, "security_alerts_banner_autohide_seconds", 6)))
        self.security_alerts_banner_autohide_var.set(str(getattr(self, "security_alerts_banner_autohide_seconds", 6)))
        self._make_entry(sec_card, self.security_alerts_banner_autohide_var).pack(anchor="w", pady=(0, 10))

        ttk.Label(sec_card, text="Clipboard", style="CardTitle.TLabel", background=self.palette["card_soft"]).pack(anchor="w", pady=(8, 4))
        if not hasattr(self, 'clipboard_clear_enabled_var'):
            self.clipboard_clear_enabled_var = tk.BooleanVar(value=getattr(self, 'clipboard_clear_enabled', True))
        self.clipboard_clear_enabled_var.set(getattr(self, 'clipboard_clear_enabled', True))
        self._make_checkbutton(sec_card, "Enable auto-clear clipboard (clear copied passwords after timeout)", self.clipboard_clear_enabled_var, background=self.palette["card_soft"]).pack(anchor="w", pady=(0, 4))
        ttk.Label(sec_card, text="Clear after (seconds):", background=self.palette["card_soft"]).pack(anchor="w")
        if not hasattr(self, 'clip_var'):
            self.clip_var = tk.StringVar()
        self.clip_var.set(str(self.clipboard_clear_seconds))
        self._make_entry(sec_card, self.clip_var).pack(anchor="w", pady=(0, 10))

        ttk.Button(sec_card, text="Save", command=self._save_settings).pack(anchor="w")

        # So mouse wheel scrolls when hovering anywhere over Settings content, not just the scrollbar
        _bind_mousewheel_to_children(inner)

        return outer

    def _save_settings(self):
        try:
            clip_seconds = int(self.clip_var.get())
            idle_minutes = int(self.idle_var.get())
            clipboard_enabled = self.clipboard_clear_enabled_var.get() if hasattr(self, "clipboard_clear_enabled_var") and self.clipboard_clear_enabled_var else True

            # Input validation: ensure positive values when clipboard clear is enabled
            if clipboard_enabled and clip_seconds < self.MIN_CLIPBOARD_CLEAR_SECONDS:
                messagebox.showerror("Error", f"Clipboard auto-clear must be at least {self.MIN_CLIPBOARD_CLEAR_SECONDS} second(s) when enabled.")
                return
            if idle_minutes < self.MIN_IDLE_TIMEOUT_MINUTES:
                messagebox.showerror("Error", f"Idle timeout must be at least {self.MIN_IDLE_TIMEOUT_MINUTES} minute(s).")
                return
            
            # FIXED: Update settings immediately
            self.clipboard_clear_seconds = clip_seconds
            self.clipboard_clear_enabled = clipboard_enabled
            self.idle_timeout_ms = idle_minutes * 60 * 1000
            hard_expiry_hours = 8
            if hasattr(self, "hard_expiry_hours_var") and self.hard_expiry_hours_var:
                try:
                    h = int(self.hard_expiry_hours_var.get())
                    hard_expiry_hours = max(1, min(24, h))
                except (ValueError, TypeError):
                    pass
            step_up_ttl = 90
            if hasattr(self, "step_up_ttl_var") and self.step_up_ttl_var:
                try:
                    t = int(self.step_up_ttl_var.get())
                    step_up_ttl = max(60, min(300, t))
                except (ValueError, TypeError):
                    pass
            if not (60 <= step_up_ttl <= 300):
                messagebox.showerror("Error", "Step-up approval window must be between 60 and 300 seconds.")
                return

            # Sync session security policy (Phase 6.1–6.6)
            if hasattr(self, "session_security"):
                idle_enabled = self.idle_lock_enabled_var.get() if hasattr(self, "idle_lock_enabled_var") and self.idle_lock_enabled_var else True
                hard_enabled = self.hard_expiry_enabled_var.get() if hasattr(self, "hard_expiry_enabled_var") and self.hard_expiry_enabled_var else True
                fresh_restart = self.fresh_login_on_restart_var.get() if hasattr(self, "fresh_login_on_restart_var") and self.fresh_login_on_restart_var else True
                step_up_enabled = self.step_up_enabled_var.get() if hasattr(self, "step_up_enabled_var") and self.step_up_enabled_var else True
                self.session_security.set_policy({
                    **self.session_security.get_policy(),
                    "idle_lock_minutes": idle_minutes,
                    "idle_lock_enabled": idle_enabled,
                    "hard_session_expiry_enabled": hard_enabled,
                    "hard_session_expiry_hours": hard_expiry_hours,
                    "require_fresh_login_on_app_restart": fresh_restart,
                    "step_up_reauth_enabled": step_up_enabled,
                    "step_up_ttl_seconds": step_up_ttl,
                })
            if hasattr(self, "security_alerts_banner_enabled_var") and self.security_alerts_banner_enabled_var:
                self.security_alerts_banner_enabled = self.security_alerts_banner_enabled_var.get()
            if hasattr(self, "security_alerts_banner_autohide_var") and self.security_alerts_banner_autohide_var:
                try:
                    s = max(3, min(30, int(self.security_alerts_banner_autohide_var.get())))
                    self.security_alerts_banner_autohide_seconds = s
                except (ValueError, TypeError):
                    pass
            if platform.system() == "Windows" and hasattr(self, "security_alerts_windows_toast_enabled_var") and self.security_alerts_windows_toast_enabled_var:
                self.security_alerts_windows_toast_enabled = self.security_alerts_windows_toast_enabled_var.get()

            # FIXED: Save to config file
            self._save_config()
            try:
                self.security_alert_service.notify_security_alert(
                    "security_settings_updated",
                    user_id=int(self.session["user_id"]) if self.session else None,
                )
            except Exception:
                pass
            # FIXED: Restart idle timer with new timeout if session is active
            if self.session:
                self._clear_idle_lock()
                self._arm_idle_lock()
            if self.session:
                self._schedule_hard_expiry_check()
            self._show_toast("Settings saved", "success")
            self._set_status(f"Settings saved: Clipboard = {clip_seconds}s, Idle = {idle_minutes}min, Hard expiry = {hard_expiry_hours}h")
        except (ValueError, TypeError) as e:
            messagebox.showerror("Error", f"Invalid values provided: {e}")
        except Exception as e:
            self.logger.error("Error saving settings: %s", e, exc_info=True)
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")

    def _load_config(self):
        """Load application settings from app data config (includes session security policy)."""
        settings_path = config_path("app_settings.json")
        self._session_security_policy = {}
        if settings_path.exists():
            try:
                data = json.loads(settings_path.read_text(encoding="utf-8"))
                self._current_theme_name = data.get("theme", "dark")
                self.clipboard_clear_seconds = data.get("clipboard_clear_seconds", self.DEFAULT_CLIPBOARD_CLEAR_SECONDS)
                self.clipboard_clear_enabled = data.get("clipboard_clear_enabled", True)
                # Prefer idle_lock_minutes for session policy; fallback to legacy idle_timeout_ms
                idle_min = data.get("idle_lock_minutes")
                if idle_min is not None:
                    self.idle_timeout_ms = int(idle_min) * 60 * 1000
                else:
                    self.idle_timeout_ms = data.get("idle_timeout_ms", self.DEFAULT_IDLE_TIMEOUT_MS)
                # Session security policy (Phase 6.1); validation in SessionSecurityService
                self._session_security_policy = {
                    "idle_lock_enabled": data.get("idle_lock_enabled", True),
                    "idle_lock_minutes": data.get("idle_lock_minutes", self.DEFAULT_IDLE_TIMEOUT_MINUTES),
                    "hard_session_expiry_enabled": data.get("hard_session_expiry_enabled", True),
                    "hard_session_expiry_hours": data.get("hard_session_expiry_hours", 8),
                    "require_fresh_login_on_app_restart": data.get("require_fresh_login_on_app_restart", True),
                    "step_up_reauth_window_seconds": data.get("step_up_reauth_window_seconds", 90),
                    "step_up_reauth_enabled": data.get("step_up_reauth_enabled", True),
                    "step_up_ttl_seconds": data.get("step_up_ttl_seconds", 90),
                }
                self.security_alerts_banner_enabled = data.get("security_alerts_banner_enabled", True)
                self.security_alerts_banner_autohide_seconds = max(3, min(30, data.get("security_alerts_banner_autohide_seconds", 6)))
                default_windows_toast = platform.system() == "Windows"
                self.security_alerts_windows_toast_enabled = data.get("security_alerts_windows_toast_enabled", default_windows_toast)
            except Exception as e:
                self.logger.error("Failed to load config: %s", e)
        if not getattr(self, "security_alerts_banner_enabled", None):
            self.security_alerts_banner_enabled = True
        if not getattr(self, "security_alerts_banner_autohide_seconds", None):
            self.security_alerts_banner_autohide_seconds = 6
        if not getattr(self, "security_alerts_windows_toast_enabled", None) and platform.system() == "Windows":
            self.security_alerts_windows_toast_enabled = True
        if getattr(self, "security_alerts_windows_toast_enabled", None) is None:
            self.security_alerts_windows_toast_enabled = platform.system() == "Windows"
        if not self._session_security_policy:
            self._session_security_policy = {
                "idle_lock_enabled": True,
                "idle_lock_minutes": self.DEFAULT_IDLE_TIMEOUT_MINUTES,
                "hard_session_expiry_enabled": True,
                "hard_session_expiry_hours": 8,
                "require_fresh_login_on_app_restart": True,
                "step_up_reauth_window_seconds": 90,
                "step_up_reauth_enabled": True,
                "step_up_ttl_seconds": 90,
            }

    def _save_config(self):
        """Save application settings and session security policy to app data config."""
        settings_path = config_path("app_settings.json")
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        policy = self.session_security.get_policy() if hasattr(self, "session_security") else getattr(self, "_session_security_policy", {})
        data = {
            "theme": self._current_theme_name,
            "clipboard_clear_seconds": self.clipboard_clear_seconds,
            "clipboard_clear_enabled": getattr(self, "clipboard_clear_enabled", True),
            "idle_timeout_ms": self.idle_timeout_ms,
            "idle_lock_enabled": policy.get("idle_lock_enabled", True),
            "idle_lock_minutes": policy.get("idle_lock_minutes", self.DEFAULT_IDLE_TIMEOUT_MINUTES),
            "hard_session_expiry_enabled": policy.get("hard_session_expiry_enabled", True),
            "hard_session_expiry_hours": policy.get("hard_session_expiry_hours", 8),
            "require_fresh_login_on_app_restart": policy.get("require_fresh_login_on_app_restart", True),
            "step_up_reauth_window_seconds": policy.get("step_up_reauth_window_seconds", 90),
            "step_up_reauth_enabled": policy.get("step_up_reauth_enabled", True),
            "step_up_ttl_seconds": policy.get("step_up_ttl_seconds", 90),
            "security_alerts_banner_enabled": getattr(self, "security_alerts_banner_enabled", True),
            "security_alerts_banner_autohide_seconds": getattr(self, "security_alerts_banner_autohide_seconds", 6),
            "security_alerts_windows_toast_enabled": getattr(self, "security_alerts_windows_toast_enabled", platform.system() == "Windows"),
        }
        try:
            settings_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            self.logger.error("Failed to save config: %s", e)


    def _set_active_nav(self, key: str):
        self.active_nav_key = key
        for k in self.nav_buttons.keys():
            self._apply_nav_btn_style(k)

    def show_page(self, key: str):
        for frame in self.frames.values():
            frame.pack_forget()
        self.frames[key].pack(fill="both", expand=True)
        self._set_active_nav(key)

        if key == "dashboard":
            self.refresh_dashboard()
        elif key == "vault":
            self.refresh_vault_table()
        elif key == "sync":
            self.refresh_sync_page()
        elif key == "extension":
            self.refresh_extension_page()
        elif key == "import":
            self._refresh_import_table()
        elif key == "backup":
            self.refresh_backup_page()

    # ---------------------- dashboard ----------------------
    def _mk_card(self, parent, title: str):
        box = ttk.Frame(parent, style="Panel.TFrame", padding=16)
        ttk.Label(box, text=title, style="CardTitle.TLabel").pack(anchor="w")
        val = ttk.Label(box, text="-", style="CardValue.TLabel")
        val.pack(anchor="w", pady=(6, 0))
        return box, val

    def _build_dashboard_page(self):
        page = ttk.Frame(self.content)
        header = ttk.Frame(page)
        header.pack(fill="x")

        ttk.Label(header, text="Dashboard", style="Title.TLabel").pack(anchor="w")
        ttk.Label(header, text="Quick look at your passwords", style="Sub.TLabel").pack(anchor="w", pady=(0, 10))
        ttk.Button(header, text="Update numbers", command=lambda: self.refresh_dashboard(force_health=True)).pack(anchor="w", pady=(0, 8))

        cards = ttk.Frame(page)
        cards.pack(fill="x")

        self.card_total_box, self.card_total = self._mk_card(cards, "How many passwords you have")
        self.card_weak_box, self.card_weak = self._mk_card(cards, "Weak (easy to guess)")
        self.card_reused_box, self.card_reused = self._mk_card(cards, "Same password used twice")
        self.card_old_box, self.card_old = self._mk_card(cards, "Not changed in 6+ months")

        for i, box in enumerate([self.card_total_box, self.card_weak_box, self.card_reused_box, self.card_old_box]):
            box.grid(row=0, column=i, padx=(0 if i == 0 else 10, 0), sticky="nsew")
            cards.columnconfigure(i, weight=1)

        recent = ttk.Frame(page, style="Panel.TFrame", padding=12)
        recent.pack(fill="both", expand=True, pady=(12, 0))
        ttk.Label(recent, text="Passwords you added lately", style="CardTitle.TLabel").pack(anchor="w")

        table_wrap = ttk.Frame(recent)
        table_wrap.pack(fill="both", expand=True, pady=(8, 0))

        cols = ("service", "username", "url", "created")
        self.recent_table = ttk.Treeview(table_wrap, columns=cols, show="headings", height=10)
        for col, width in [("service", 240), ("username", 240), ("url", 420), ("created", 180)]:
            self.recent_table.heading(col, text=col.title())
            self.recent_table.column(col, width=width, anchor="w")

        y = ttk.Scrollbar(table_wrap, orient="vertical", command=self.recent_table.yview)
        x = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.recent_table.xview)
        self.recent_table.configure(yscrollcommand=y.set, xscrollcommand=x.set)

        self.recent_table.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        table_wrap.rowconfigure(0, weight=1)
        table_wrap.columnconfigure(0, weight=1)

        return page

    def _apply_health(self, data: dict):
        self.card_total.configure(text=str(data.get("total", 0)))
        self.card_weak.configure(text=str(data.get("weak", 0)))
        self.card_reused.configure(text=str(data.get("reused_entries", 0)))
        self.card_old.configure(text=str(data.get("old_entries", 0)))

    def _compute_health_async(self):
        if not self.session or not self.session.get("enc_priv"):
            return
        try:
            # Convert bytearray to bytes for API call
            enc_priv_bytes = bytes(self.session["enc_priv"]) if isinstance(self.session["enc_priv"], bytearray) else self.session["enc_priv"]
            data = self.api.get_password_health(self.session["user_id"], enc_priv_bytes)
        except Exception:
            data = {"total": 0, "weak": 0, "reused_entries": 0, "old_entries": 0}

        def finish():
            self.health_loading = False
            self.health_cache = {"timestamp": time.time(), "data": data}
            self._apply_health(data)
            self._set_status("Health metrics updated")

        self.root.after(0, finish)

    def refresh_dashboard(self, force_health: bool = False):
        if not self.session:
            return

        for rid in self.recent_table.get_children():
            self.recent_table.delete(rid)

        rows = self.api.get_secrets_metadata(self.session["user_id"])[:20]
        for r in rows:
            self.recent_table.insert(
                "",
                "end",
                iid=str(r["id"]),
                values=(r["service_name"], r["username_email"], r.get("url", ""), r["created_at"]),
            )

        now = time.time()
        cached = self.health_cache.get("data")
        age = now - float(self.health_cache.get("timestamp", 0.0))

        if cached and age < self.HEALTH_CACHE_TTL_SECONDS and not force_health:
            self._apply_health(cached)
            return

        if self.health_loading:
            return

        self.health_loading = True
        self.card_total.configure(text="...")
        self.card_weak.configure(text="...")
        self.card_reused.configure(text="...")
        self.card_old.configure(text="...")
        self._set_status("Computing health metrics...")

        th = threading.Thread(target=self._compute_health_async, daemon=True)
        th.start()

    # ---------------------- vault ----------------------
    def _build_vault_page(self):
        page = ttk.Frame(self.content)

        ttk.Label(page, text="Your passwords", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="See, add, and copy your saved passwords", style="Sub.TLabel").pack(anchor="w", pady=(0, 10))

        top = ttk.Frame(page)
        top.pack(fill="x", pady=(0, 8))

        top_row1 = ttk.Frame(top)
        top_row1.pack(fill="x", pady=(0, 6))
        self.search_entry = self._make_entry(top_row1, self.search_var)
        self.search_entry.config(width=42)
        self.search_entry.pack(side="left")
        self.search_entry.bind("<Return>", lambda e: self.refresh_vault_table())
        ttk.Button(top_row1, text="Search", command=self.refresh_vault_table).pack(side="left", padx=6)
        ttk.Button(top_row1, text="Clear", command=self._clear_search, style="Secondary.TButton").pack(side="left", padx=2)
        ttk.Button(top_row1, text="Refresh", command=self.refresh_vault_table, style="Secondary.TButton").pack(side="left", padx=6)
        ttk.Label(top_row1, text="Sort by:", font=self.font_base).pack(side="left", padx=(12, 4))
        sort_frame = tk.Frame(top_row1, bg=self.palette["bg"])
        sort_frame.pack(side="left", padx=6)
        self.sort_dropdown_btn = tk.Button(
            sort_frame,
            textvariable=self.sort_column_var,
            command=self._show_sort_menu,
            font=self.font_base,
            bg=self.palette["card_soft"],
            fg=self.palette["text"],
            activebackground="#eef2ff",
            activeforeground="#000000",
            relief="solid",
            borderwidth=1,
            width=12,
            anchor="w",
            padx=10,
            pady=7
        )
        self.sort_dropdown_btn.pack(side="left")
        self.sort_column_var.set("Service")
        ttk.Button(top_row1, text="Export CSV", command=self._export_csv_flow, style="Secondary.TButton").pack(side="left", padx=6)
        ttk.Button(top_row1, text="Export JSON", command=self._export_json_flow, style="Secondary.TButton").pack(side="left", padx=2)

        top_row2 = ttk.Frame(top)
        top_row2.pack(fill="x")
        ttk.Button(top_row2, text="Select all", command=self._vault_select_all, style="Secondary.TButton").pack(side="left", padx=(0, 2))
        ttk.Button(top_row2, text="Clear selection", command=self._vault_clear_selection, style="Secondary.TButton").pack(side="left", padx=2)
        ttk.Button(top_row2, text="Show passwords", command=self._reveal_passwords_for_selected, style="Secondary.TButton").pack(side="left", padx=(12, 2))
        ttk.Button(top_row2, text="Hide passwords", command=self._hide_passwords_in_vault, style="Secondary.TButton").pack(side="left", padx=2)

        body = ttk.Panedwindow(page, orient="horizontal")
        body.pack(fill="both", expand=True)

        left_panel = ttk.Frame(body, style="Panel.TFrame", padding=10)
        body.add(left_panel, weight=5)

        cols = ("service", "username", "url", "created", "password")
        table_wrap = ttk.Frame(left_panel)
        table_wrap.pack(fill="both", expand=True)

        self.vault_table = ttk.Treeview(table_wrap, columns=cols, show="headings", selectmode="extended")
        self._vault_col_config = [
            ("service", 100, 22),
            ("username", 120, 24),
            ("url", 150, 32),
            ("created", 130, 14),
            ("password", 80, 8),
        ]
        for col, min_w, _ in self._vault_col_config:
            self.vault_table.heading(col, text=col.title())
            self.vault_table.column(col, width=min_w, minwidth=min_w, anchor="w")
        self.vault_table.bind("<<TreeviewSelect>>", self._on_select_vault)
        self.vault_table.tag_configure("odd", background=self.palette["panel"], foreground=self.palette["text"])
        self.vault_table.tag_configure("even", background=self.palette.get("table_row_alt", self.palette["panel"]), foreground=self.palette["text"])

        def _resize_vault_columns(_e=None):
            w = table_wrap.winfo_width()
            if w <= 1:
                return
            avail = max(300, w - 18)
            total_weight = sum(c[2] for c in self._vault_col_config)
            widths = [max(mw, int(avail * wt / total_weight)) for _, mw, wt in self._vault_col_config]
            diff = avail - sum(widths)
            if diff != 0:
                widths[2] += diff
            for (col, min_w, _), wd in zip(self._vault_col_config, widths):
                self.vault_table.column(col, width=max(min_w, wd))

        table_wrap.bind("<Configure>", _resize_vault_columns)
        self.root.after(100, _resize_vault_columns)

        self._bind_table_header_hover(self.vault_table)

        y = ttk.Scrollbar(table_wrap, orient="vertical", command=self.vault_table.yview)
        x = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.vault_table.xview)
        self.vault_table.configure(yscrollcommand=y.set, xscrollcommand=x.set)

        self.vault_table.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        table_wrap.rowconfigure(0, weight=1)
        table_wrap.columnconfigure(0, weight=1)

        # Right side: scrollable panel so "Save a new password" and "Click one password" never get clipped
        right_outer = ttk.Frame(body)
        body.add(right_outer, weight=3)
        try:
            body.paneconfig(right_outer, minsize=320)
        except Exception:
            pass
        right_outer.columnconfigure(0, weight=1)
        right_outer.rowconfigure(0, weight=1)
        right_canvas = tk.Canvas(right_outer, bg=self.palette["bg"], highlightthickness=0)
        right_scrollbar = ttk.Scrollbar(right_outer)
        right_panel = ttk.Frame(right_canvas, style="Panel.TFrame", padding=16)
        right_inner_id = right_canvas.create_window(0, 0, window=right_panel, anchor="nw")

        def _on_right_configure(_e=None):
            right_panel.update_idletasks()
            b = right_canvas.bbox("all")
            if b:
                # Ensure scroll region covers full content height so nothing is cut off at bottom
                cw = max(right_canvas.winfo_width(), 1)
                rh = right_panel.winfo_reqheight()
                right_canvas.configure(scrollregion=(0, 0, cw, max(b[3] - b[1], rh, 1)))
            else:
                right_canvas.configure(scrollregion=right_canvas.bbox("all"))

        def _on_right_canvas_configure(event):
            w = max(event.width, 1)
            right_canvas.itemconfig(right_inner_id, width=w)
            # Keep inner frame at least as wide as canvas; height follows content
            right_panel.update_idletasks()
            _on_right_configure()

        right_panel.bind("<Configure>", _on_right_configure)
        right_canvas.bind("<Configure>", _on_right_canvas_configure)
        right_canvas.configure(yscrollcommand=right_scrollbar.set)
        right_scrollbar.configure(command=right_canvas.yview)
        right_canvas.grid(row=0, column=0, sticky="nsew")
        right_scrollbar.grid(row=0, column=1, sticky="ns")

        def _vault_right_scroll(delta_units: int):
            right_canvas.yview_scroll(-delta_units, "units")

        def _on_vault_right_wheel(event):
            if getattr(event, "delta", None) is not None:
                _vault_right_scroll(int(event.delta / 120))
            return "break"

        def _on_vault_right_linux_up(e):
            _vault_right_scroll(3)
            return "break"

        def _on_vault_right_linux_down(e):
            _vault_right_scroll(-3)
            return "break"

        def _bind_vault_right_wheel(parent):
            parent.bind("<MouseWheel>", _on_vault_right_wheel)
            try:
                parent.bind("<Button-4>", _on_vault_right_linux_up)
                parent.bind("<Button-5>", _on_vault_right_linux_down)
            except Exception:
                pass
            for child in parent.winfo_children():
                _bind_vault_right_wheel(child)

        right_canvas.bind("<MouseWheel>", _on_vault_right_wheel)
        try:
            right_canvas.bind("<Button-4>", _on_vault_right_linux_up)
            right_canvas.bind("<Button-5>", _on_vault_right_linux_down)
        except Exception:
            pass

        ttk.Label(right_panel, text="Save a new password", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 6))
        instr = ttk.Label(
            right_panel,
            text="Fill in the website or app name, your username, and the password. Then click Add.",
            style="Sub.TLabel",
            wraplength=300,
        )
        instr.pack(anchor="w", pady=(0, 12))

        self.service_var = tk.StringVar()
        self.username_var = tk.StringVar()
        self.url_var = tk.StringVar()
        self.password_var = tk.StringVar()

        self._form_entry(right_panel, "Where? (e.g. Gmail, Netflix)", self.service_var)
        self._form_entry(right_panel, "Username or email", self.username_var)
        self._form_entry(right_panel, "Website address (optional)", self.url_var)
        pwd_entry = self._form_password(right_panel, "Password", self.password_var)

        # Strength meter container
        self.strength_meter_frame = ttk.Frame(right_panel)
        self.strength_meter_frame.pack(fill="x", pady=(0, 10))
        self.strength_canvas = tk.Canvas(self.strength_meter_frame, height=6, bg=self.palette.get("border", "#e2e8f0"), highlightthickness=0)
        self.strength_canvas.pack(fill="x", pady=(0, 2))
        self.strength_label = ttk.Label(self.strength_meter_frame, text="Too weak", style="Sub.TLabel")
        self.strength_label.pack(anchor="w")
        self.password_var.trace_add("write", lambda *args: self._update_strength_meter())

        ttk.Button(right_panel, text="Add this password", command=self.add_secret).pack(anchor="w", pady=(6, 16))

        ttk.Separator(right_panel, orient="horizontal").pack(fill="x", pady=(4, 12))
        ttk.Label(right_panel, text="Click one password in the list", style="CardTitle.TLabel").pack(anchor="w", pady=(0, 10))

        self.sel_service = tk.StringVar(value="-")
        self.sel_user = tk.StringVar(value="-")
        self.sel_url = tk.StringVar(value="-")
        self.sel_created = tk.StringVar(value="-")

        self._meta_row(right_panel, "Service:", self.sel_service)
        self._meta_row(right_panel, "Username:", self.sel_user)
        self._meta_row(right_panel, "URL:", self.sel_url)
        self._meta_row(right_panel, "Created:", self.sel_created)

        # TOTP Row
        self.totp_var = tk.StringVar(value="-")
        self.totp_row = self._meta_row(right_panel, "TOTP:", self.totp_var)
        self.totp_copy_btn = ttk.Button(right_panel, text="Copy TOTP", command=self.copy_selected_totp, style="Secondary.TButton")
        self.totp_copy_btn.pack(anchor="w", pady=(4, 12))

        action_row1 = ttk.Frame(right_panel)
        action_row1.pack(fill="x", pady=(4, 6))
        ttk.Button(action_row1, text="Show password", command=self.show_selected_password).pack(side="left")
        ttk.Button(action_row1, text="Copy password", command=self.copy_selected_password, style="Secondary.TButton").pack(side="left", padx=6)

        action_row2 = ttk.Frame(right_panel)
        action_row2.pack(fill="x", pady=(0, 6))
        ttk.Button(action_row2, text="Copy username", command=self.copy_selected_username, style="Secondary.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(action_row2, text="Copy URL", command=self.copy_selected_url, style="Secondary.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(action_row2, text="Copy service", command=self.copy_selected_service, style="Secondary.TButton").pack(side="left")

        self.vault_delete_btn_text = tk.StringVar(value="Delete this password")
        ttk.Button(right_panel, textvariable=self.vault_delete_btn_text, command=self.delete_selected).pack(anchor="w", pady=(10, 0))

        # So mouse wheel works when hovering over any widget in the right panel, not just the scrollbar
        _bind_vault_right_wheel(right_panel)

        # Refresh scroll region after layout so full content (including bottom buttons) is scrollable
        self.root.after(250, _on_right_configure)

        return page

    def _form_entry(self, parent, label: str, var: tk.StringVar):
        ttk.Label(parent, text=label).pack(anchor="w")
        e = self._make_entry(parent, var)
        e.pack(anchor="w", fill="x", pady=(0, 8))
        return e

    def _form_password(self, parent, label: str, var: tk.StringVar):
        ttk.Label(parent, text=label).pack(anchor="w")
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=(0, 8))
        row.columnconfigure(0, weight=1)
        e = self._make_entry(row, var, show="*")
        e.grid(row=0, column=0, sticky="ew")
        eye = tk.Button(
            row,
            text="👁",
            font=self.font_eye,
            width=3,
            relief="flat",
            bg=self.palette.get("card_soft", "#f1f5f9"),
            fg=self.palette["text"],
            activebackground=self.palette.get("accent_soft", "#e2e8f0"),
            command=lambda: self._toggle_password_entry(e, eye),
        )
        eye.grid(row=0, column=1, padx=(6, 0))
        self._bind_hover_button(
            eye,
            self.palette.get("card_soft", "#f1f5f9"),
            self.palette.get("accent_soft", "#e2e8f0"),
            self.palette["text"],
            self.palette["text"]
        )
        return e

    def _meta_row(self, parent, key: str, var: tk.StringVar):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=1)
        ttk.Label(row, text=key, width=10).pack(side="left")
        ttk.Label(row, textvariable=var, style="Sub.TLabel").pack(side="left", fill="x", expand=True)

    def _on_select_vault(self, _event=None):
        try:
            self._on_select_vault_impl()
        except Exception as e:
            self.logger.debug("Vault selection update: %s", e)

    def _on_select_vault_impl(self):
        ids = self._get_selected_entry_ids()
        if getattr(self, "vault_delete_btn_text", None):
            if not ids:
                self.vault_delete_btn_text.set("Delete this password")
            elif len(ids) == 1:
                self.vault_delete_btn_text.set("Delete this password")
            else:
                self.vault_delete_btn_text.set(f"Delete {len(ids)} passwords")
        if not ids:
            self.sel_service.set("-")
            self.sel_user.set("-")
            self.sel_url.set("-")
            self.sel_created.set("-")
            self.totp_var.set("-")
            return
        if len(ids) > 1:
            self.sel_service.set(f"{len(ids)} entries selected")
            self.sel_user.set("—")
            self.sel_url.set("—")
            self.sel_created.set("—")
            self.totp_var.set("—")
            return
        data = self._get_selected_values()
        if not data:
            return
        self.sel_service.set(str(data.get("service", "")))
        self.sel_user.set(str(data.get("username", "")))
        self.sel_url.set(str(data.get("url", "")))
        self.sel_created.set(str(data.get("created", "")))
        self.totp_var.set("-")
        try:
            if not self.session or not self.session.get("enc_priv"):
                self.totp_var.set("N/A")
                return
            enc_priv_bytes = bytes(self.session["enc_priv"]) if isinstance(self.session["enc_priv"], bytearray) else self.session["enc_priv"]
            res, msg = self.api.decrypt_secret(self.session["user_id"], data["id"], enc_priv_bytes)
            if msg == "Success" and res is not None and isinstance(res, dict) and res.get("totp_secret"):
                code = self.api.generate_totp_code(res["totp_secret"])
                self.totp_var.set(code)
            else:
                self.totp_var.set("N/A")
        except (KeyError, AttributeError, TypeError) as e:
            self.logger.debug("TOTP update failed: %s", e)
            self.totp_var.set("N/A")
        except Exception as e:
            self.logger.error("Unexpected error updating TOTP: %s", e)
            self.totp_var.set("N/A")

    def refresh_vault_table(self):
        if not self.session:
            return

        query = self.search_var.get().strip() or None
        # Convert user-friendly name to database column name
        sort_display = self.sort_column_var.get()
        if not sort_display or sort_display not in self.sort_column_map:
            sort_display = "Service"
            self.sort_column_var.set("Service")
        sort_column = self.sort_column_map.get(sort_display, "service_name")
        sort_direction = self.sort_direction_var.get() or "ASC"
        
        rows = self.api.get_secrets_metadata(
            self.session["user_id"], 
            query, 
            sort_column=sort_column,
            sort_direction=sort_direction
        )

        if self._password_reveal_timer:
            try:
                self.root.after_cancel(self._password_reveal_timer)
            except Exception:
                pass
            self._password_reveal_timer = None
        self._password_revealed_iids = set()

        for rid in self.vault_table.get_children():
            self.vault_table.delete(rid)

        for i, r in enumerate(rows):
            tag = "even" if i % 2 == 0 else "odd"
            self.vault_table.insert(
                "",
                "end",
                iid=str(r["id"]),
                values=(r["service_name"], r["username_email"], r.get("url", ""), r["created_at"], "••••••"),
                tags=(tag,)
            )

        self._on_select_vault()
        sort_info = f" (sorted by {sort_display} {sort_direction})" if sort_display != "Service" or sort_direction != "ASC" else ""
        search_info = f" - Found {len(rows)} result(s)" if query else ""
        self._set_status(f"Loaded {len(rows)} entries{sort_info}{search_info}")
    
    def _style_combobox_popdown_direct(self, popdown_name):
        """Directly style the Combobox popdown listbox by name (dark theme: input_bg)."""
        try:
            listbox = self.root.nametowidget(popdown_name)
            if isinstance(listbox, tk.Listbox):
                listbox.configure(
                    bg=self.palette.get("input_bg", self.palette["panel"]),
                    fg=self.palette["text"],
                    selectbackground=self.palette["accent"],
                    selectforeground="white",
                    font=self.font_base,
                    height=8,
                )
        except Exception:
            self._apply_combobox_listbox_style()
    
    def _style_combobox_dropdown(self, event=None):
        """Style the Combobox dropdown listbox to match theme."""
        try:
            # Try multiple times with increasing delays to catch the dropdown
            # The dropdown is created asynchronously, so we need multiple attempts
            for delay in [5, 10, 20, 30, 50, 80, 120]:
                self.root.after(delay, self._apply_combobox_listbox_style)
        except Exception:
            pass
    
    def _apply_combobox_listbox_style(self):
        """Apply theme styling to Combobox dropdown listbox."""
        try:
            # Custom menu is used instead of Combobox, so no need for popdown styling
            pass
            
            # Method 2: Search all windows recursively
            all_windows = [self.root]
            
            def find_toplevels(parent):
                try:
                    for child in parent.winfo_children():
                        if isinstance(child, tk.Toplevel):
                            all_windows.append(child)
                            find_toplevels(child)
                except Exception:
                    pass
            
            find_toplevels(self.root)
            
            # Style all Listbox widgets in all windows (dropdowns: dark input_bg)
            for window in all_windows:
                try:
                    if isinstance(window, tk.Toplevel):
                        window.configure(bg=self.palette.get("input_bg", self.palette["panel"]))
                    self._style_listbox_recursive(window)
                except Exception:
                    continue
        except Exception:
            pass
    
    def _style_listbox_recursive(self, widget):
        """Recursively find and style Listbox widgets (dropdowns: dark input_bg to match theme)."""
        try:
            if isinstance(widget, tk.Listbox):
                widget.configure(
                    bg=self.palette.get("input_bg", self.palette["panel"]),
                    fg=self.palette["text"],
                    selectbackground=self.palette["accent"],
                    selectforeground="white",
                    font=self.font_base,
                    relief="solid",
                    borderwidth=1,
                    highlightthickness=1,
                    highlightbackground=self.palette["border"],
                    highlightcolor=self.palette["accent"],
                    activestyle="none",
                    exportselection=False,
                    height=8,
                )
                widget.update_idletasks()
            elif isinstance(widget, tk.Toplevel):
                widget.configure(bg=self.palette.get("input_bg", self.palette["panel"]))
                # Also try to configure any Frame widgets inside
                for child in widget.winfo_children():
                    if isinstance(child, (tk.Frame, ttk.Frame)):
                        try:
                            if isinstance(child, tk.Frame):
                                child.configure(bg=self.palette.get("input_bg", self.palette["panel"]))
                        except Exception:
                            pass
            # Recursively check children
            for child in widget.winfo_children():
                self._style_listbox_recursive(child)
        except Exception:
            pass

    def _show_themed_dropdown(self, trigger_widget, options, current_value, on_select, min_width=None):
        """Show a themed dropdown (Toplevel + Listbox) matching first-image design: dark bg, accent highlight, thin accent border."""
        # Close any existing activity-log dropdown
        if getattr(self, "_themed_dropdown_window", None):
            try:
                self._themed_dropdown_window.destroy()
            except Exception:
                pass
            self._themed_dropdown_window = None
        if not options:
            return
        bg_dark = self.palette.get("input_bg", self.palette["panel"])
        accent = self.palette.get("accent", "#58a6ff")
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.configure(bg=accent)
        # Inner frame: 1px padding so Toplevel accent shows as thin border
        inner = tk.Frame(win, bg=bg_dark, padx=1, pady=1)
        inner.pack(fill="both", expand=True)
        listbox = tk.Listbox(
            inner,
            bg=bg_dark,
            fg=self.palette["text"],
            selectbackground=accent,
            selectforeground=self.palette.get("accent_fg", "white"),
            font=self.font_base,
            relief="flat",
            borderwidth=0,
            highlightthickness=0,
            activestyle="none",
            height=min(10, max(4, len(options))),
            exportselection=False,
        )
        listbox.pack(fill="both", expand=True)
        for opt in options:
            listbox.insert("end", opt)
        try:
            idx = options.index(current_value) if current_value in options else 0
            listbox.selection_set(idx)
            listbox.see(idx)
        except Exception:
            pass

        def do_select(event=None):
            sel = listbox.curselection()
            if sel:
                val = options[sel[0]]
                try:
                    win.destroy()
                except Exception:
                    pass
                self._themed_dropdown_window = None
                on_select(val)

        listbox.bind("<Button-1>", lambda e: self.root.after(80, do_select))
        listbox.bind("<Return>", do_select)

        def close_dropdown(event=None):
            try:
                if win.winfo_exists():
                    win.destroy()
            except Exception:
                pass
            self._themed_dropdown_window = None

        win.bind("<Escape>", close_dropdown)

        def on_focus_out(event):
            try:
                if not win.winfo_exists():
                    return
                w = event.widget
                while w:
                    if w == win or w == listbox:
                        return
                    try:
                        w = w.master
                    except Exception:
                        break
                close_dropdown()
            except Exception:
                pass

        win.bind("<FocusOut>", on_focus_out)
        listbox.focus_set()
        try:
            x = trigger_widget.winfo_rootx()
            y = trigger_widget.winfo_rooty() + trigger_widget.winfo_height()
            win.geometry(f"+{x}+{y}")
        except Exception:
            pass
        listbox.update_idletasks()
        w = max(min_width or 100, trigger_widget.winfo_width() if trigger_widget.winfo_exists() else 100)
        h = listbox.winfo_reqheight()
        win.geometry(f"{w}x{h}")
        self._themed_dropdown_window = win

    def _show_sort_menu(self):
        """Show custom dropdown menu for sort selection with full theme control."""
        # Close any existing dropdown
        if hasattr(self, '_sort_dropdown_window') and self._sort_dropdown_window:
            try:
                self._sort_dropdown_window.destroy()
            except Exception:
                pass
        
        # Create custom Toplevel window for dropdown (full theme control)
        self._sort_dropdown_window = tk.Toplevel(self.root)
        self._sort_dropdown_window.overrideredirect(True)  # Remove window decorations
        self._sort_dropdown_window.configure(bg=self.palette["card_soft"])
        
        # Position below the button
        try:
            x = self.sort_dropdown_btn.winfo_rootx()
            y = self.sort_dropdown_btn.winfo_rooty() + self.sort_dropdown_btn.winfo_height()
            self._sort_dropdown_window.geometry(f"+{x}+{y}")
        except Exception:
            pass
        
        # Create listbox with theme colors
        listbox = tk.Listbox(
            self._sort_dropdown_window,
            bg=self.palette["card_soft"],
            fg=self.palette["text"],
            selectbackground=self.palette["accent"],
            selectforeground="white",
            font=self.font_base,
            relief="solid",
            borderwidth=1,
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            highlightcolor=self.palette["accent"],
            activestyle="none",
            height=4,
            exportselection=False
        )
        listbox.pack(fill="both", expand=True)
        
        # Add options
        options = ["Service", "Username", "Url", "Created"]
        for option in options:
            listbox.insert("end", option)
        
        # Set current selection
        current = self.sort_column_var.get()
        if current in options:
            listbox.selection_set(options.index(current))
            listbox.see(options.index(current))
        
        # Bind selection
        def on_select(event):
            selection = listbox.curselection()
            if selection:
                selected_option = options[selection[0]]
                self._select_sort_option(selected_option)
                self._sort_dropdown_window.destroy()
                self._sort_dropdown_window = None
        
        listbox.bind("<Double-Button-1>", on_select)
        listbox.bind("<Return>", on_select)
        
        # Close on click outside
        def close_on_focus_out(event):
            if event.widget != listbox and event.widget != self._sort_dropdown_window:
                try:
                    self._sort_dropdown_window.destroy()
                    self._sort_dropdown_window = None
                except Exception:
                    pass
        
        self._sort_dropdown_window.bind("<FocusOut>", close_on_focus_out)
        listbox.focus_set()
        
        # Calculate and set window size
        listbox.update_idletasks()
        width = max(120, self.sort_dropdown_btn.winfo_width())
        height = listbox.winfo_reqheight()
        self._sort_dropdown_window.geometry(f"{width}x{height}")
    
    def _select_sort_option(self, option):
        """Handle sort option selection from menu."""
        self.sort_column_var.set(option)
        self.refresh_vault_table()
    
    def _on_sort_column_changed(self):
        """Handle sort column dropdown change - kept for compatibility."""
        # This is now handled by _select_sort_option
        pass
    
    def _clear_search(self):
        """Clear search field and refresh table."""
        self.search_var.set("")
        self.refresh_vault_table()
    
    def _toggle_sort_direction(self):
        """Toggle between ASC and DESC sort direction - REMOVED: No longer needed."""
        # This function is kept for compatibility but ASC/DESC button has been removed
        pass

    def add_secret(self):
        if not self.session:
            return

        service = self.service_var.get().strip()
        user = self.username_var.get().strip()
        url = self.url_var.get().strip()
        pwd = self.password_var.get().strip()

        if not service or not user or not pwd:
            return messagebox.showwarning("Add", "Service, Username, and Password are required.")

        # Check for insegure flags
        flags = self.api.security.check_insecure_flags(pwd, user, service)
        if flags:
            msg = "Suspicious/Insecure patterns detected:\n\n" + "\n".join(f"• {f}" for f in flags)
            msg += "\n\nDo you want to continue anyway?"
            if not messagebox.askyesno("Security Warning", msg):
                return

        # Check for lookalike domains
        existing_metadata = self.api.get_secrets_metadata(self.session["user_id"])
        existing_domains = [m["url"] for m in existing_metadata if m.get("url")]
        lookalikes = self.api.security.check_lookalike_domain(url, existing_domains)
        if lookalikes:
            msg = "Phishing/Lookalike warning!\nThis URL is very similar to existing entries:\n\n"
            for domain, dist in lookalikes:
                msg += f"• {domain} (distance: {dist})\n"
            msg += "\nIs this definitely the correct URL?"
            if not messagebox.askyesno("Typosquat Protection", msg):
                return

        cert = self._get_active_encryption_cert()
        if not cert:
            return messagebox.showerror("Error", "No active encryption certificate.")

        # Check if user wants to add TOTP secret too
        totp_secret = None
        if messagebox.askyesno("TOTP", "Would you like to add a TOTP secret for this entry?"):
            totp_secret = simpledialog.askstring("TOTP", "Enter TOTP Base32 Secret:")

        ok, msg = self.api.add_secret(self.session["user_id"], service, user, url, pwd, cert, totp_secret=totp_secret)
        if ok:
            self.service_var.set("")
            self.username_var.set("")
            self.url_var.set("")
            self.password_var.set("")
            self._show_toast(f"Secret added: {service}", "success")
            self.refresh_vault_table()
            self.refresh_dashboard(force_health=False)
            messagebox.showinfo("Success", "Entry added successfully.")
        else:
            messagebox.showerror("Failed", msg)

    def _decrypt_selected_password(self):
        if not self.session:
            return None

        entry_id = self._get_selected_entry_id()
        if entry_id is None:
            messagebox.showwarning("Select", "Select an entry first.")
            return None

        # Convert bytearray to bytes for API call
        enc_priv_bytes = bytes(self.session["enc_priv"]) if isinstance(self.session["enc_priv"], bytearray) else self.session["enc_priv"]
        res, msg = self.api.decrypt_secret(self.session["user_id"], entry_id, enc_priv_bytes)
        if msg != "Success":
            messagebox.showerror("Decrypt failed", msg)
            return None
        
        if isinstance(res, dict):
            return res["password"]
        return res

    def show_selected_password(self):
        if not self.session:
            return

        data = self._get_selected_values()
        if not data:
            return messagebox.showwarning("Select", "Select an entry first.")

        if not self._require_step_up_or_phrase("reveal_password", "reveal this password"):
            return

        try:
            # Convert bytearray to bytes for API call
            enc_priv_bytes = bytes(self.session["enc_priv"]) if isinstance(self.session["enc_priv"], bytearray) else self.session["enc_priv"]
            res, msg = self.api.decrypt_secret(self.session["user_id"], data["id"], enc_priv_bytes)
            if msg != "Success":
                return messagebox.showerror("Decrypt failed", msg)
                
            # FIXED: Properly extract password value, not the whole dict
            # decrypt_secret returns ({"password": "...", "totp_secret": "..."}, "Success")
            # CRITICAL: res should be a dict, extract password key value
            pwd = ""
            
            # Do not log res content (may contain password)
            
            if res is None:
                pwd = ""
            elif isinstance(res, dict):
                # Extract just the password string value from the dict
                # Use .get() to safely get the password key
                password_value = res.get("password")
                if password_value is not None:
                    # Convert to string, but check it's not a dict/list
                    if isinstance(password_value, (dict, list)):
                        self.logger.error("Password value is %s, expected string", type(password_value).__name__)
                        pwd = ""
                    elif isinstance(password_value, str):
                        # Already a string, use it directly
                        pwd = password_value
                    else:
                        # Convert other types to string
                        pwd = str(password_value)
                else:
                    pwd = ""
            elif isinstance(res, str):
                # If res is a string, check if it's a dict representation
                if res.strip().startswith("{") and ("'password'" in res or '"password"' in res):
                    # It's a dict string, extract password
                    import re
                    match = re.search(r"'password':\s*['\"]([^'\"]+)['\"]", res)
                    if not match:
                        match = re.search(r'"password":\s*["\']([^"\']+)["\']', res)
                    if match:
                        pwd = match.group(1)
                    else:
                        pwd = ""
                else:
                    # It's a plain string password (legacy format)
                    pwd = res
            else:
                # Fallback: log type only (do not log res; may contain password)
                self.logger.warning("Unexpected res type in show_selected_password: %s", type(res).__name__)
                pwd = ""
            
            # Do not log pwd (it may be the actual password)
            if isinstance(pwd, str) and pwd.strip().startswith("{") and "'password'" in pwd:
                self.logger.error("Password extraction failed - got dict string")
            
            # Debug: Log if we're getting the wrong type
            if isinstance(pwd, dict):
                self.logger.error("Password extraction failed: got dict instead of string")
                pwd = ""
            
            w = tk.Toplevel(self.root)
            w.title("Credential details")
            w.configure(bg=self.palette["bg"])
            self._set_auth_window(target=w)  # FIXED: Use keyword argument
            
            # FIXED: Ensure proper text color for visibility
            title_label = ttk.Label(w, text=f"Details for {data['service']}", style="CardTitle.TLabel")
            title_label.pack(pady=(12, 8), padx=20)
            
            row = ttk.Frame(w)
            row.pack(fill="x", padx=20, pady=4)
            ttk.Label(row, text="Password:", width=10).pack(side="left")
            
            # FIXED: For password field visibility - use light background with black text in dark theme
            if self._current_theme_name == "light":
                # Light theme: black text on white background
                text_color = "#000000"
                bg_color = "#ffffff"
            else:
                # Dark theme: BLACK text on LIGHT background for maximum visibility
                text_color = "#000000"  # Pure black text
                bg_color = "#ffffff"    # Pure white background
            
            p_val = tk.Entry(
                row, 
                relief="solid", 
                bd=1,
                bg=bg_color,  # FIXED: Use explicit background for better contrast
                fg=text_color,  # FIXED: Explicit text color for visibility
                font=self.font_mono,
                insertbackground=text_color,  # Cursor color matches text
                highlightthickness=1,
                highlightbackground=self.palette.get("border", "#30363d"),
                highlightcolor=self.palette.get("accent", "#58a6ff")
            )
            # FIXED: Final safety check - ensure we never insert a dict representation
            password_final = str(pwd) if pwd else ""
            
            # If somehow we got a dict string representation, extract the password value
            if password_final.strip().startswith("{") and ("'password'" in password_final or '"password"' in password_final):
                import re
                # Try to extract password from dict string like "{'password': 'value', ...}"
                match = re.search(r"'password':\s*['\"]([^'\"]+)['\"]", password_final)
                if not match:
                    # Try with double quotes
                    match = re.search(r'"password":\s*["\']([^"\']+)["\']', password_final)
                if match:
                    password_final = match.group(1)
                    self.logger.warning("Extracted password from dict string - this should not happen")
                else:
                    # Last resort: try ast parsing
                    try:
                        import ast
                        parsed = ast.literal_eval(password_final)
                        if isinstance(parsed, dict):
                            password_final = str(parsed.get("password", ""))
                    except Exception:
                        password_final = ""
            
            # Insert the clean password string
            p_val.insert(0, password_final)
            p_val.config(state="readonly")
            p_val.pack(side="left", fill="x", expand=True)
            
            if isinstance(res, dict) and res.get("totp_secret"):
                rowt = ttk.Frame(w)
                rowt.pack(fill="x", padx=20, pady=4)
                ttk.Label(rowt, text="TOTP:", width=10).pack(side="left")
                t_val = tk.Entry(
                    rowt, 
                    relief="solid", 
                    bd=1,
                    bg=bg_color,  # FIXED: Use explicit background for better contrast
                    fg=text_color,  # FIXED: Explicit text color for visibility
                    font=self.font_mono,
                    insertbackground=text_color,  # Cursor color matches text
                    highlightthickness=1,
                    highlightbackground=self.palette.get("border", "#30363d"),
                    highlightcolor=self.palette.get("accent", "#58a6ff")
                )
                code = self.api.generate_totp_code(res["totp_secret"])
                t_val.insert(0, str(code))
                t_val.config(state="readonly")
                t_val.pack(side="left", fill="x", expand=True)

            ttk.Button(w, text="Close", command=w.destroy).pack(pady=12)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to reveal: {e}")

    def copy_selected_password(self):
        if not self.session:
            return
        ids = self._get_selected_entry_ids()
        if len(ids) > 1:
            self._show_toast("Select a single entry to copy its password.", "warning")
            return
        if not self._require_step_up_or_phrase("copy_password", "copy the saved password"):
            return

        pw = self._decrypt_selected_password()
        if pw is None:
            return
        self._copy_to_clipboard(pw, "Password")

    def copy_selected_username(self):
        data = self._get_selected_values()
        if not data:
            return messagebox.showwarning("Select", "Select an entry first.")
        self._copy_to_clipboard(str(data.get("username", "")), "Username")

    def copy_selected_url(self):
        data = self._get_selected_values()
        if not data:
            return messagebox.showwarning("Select", "Select an entry first.")
        self._copy_to_clipboard(str(data.get("url", "")), "URL")

    def copy_selected_service(self):
        data = self._get_selected_values()
        if not data:
            return messagebox.showwarning("Select", "Select an entry first.")
        self._copy_to_clipboard(str(data.get("service", "")), "Service")

    def copy_selected_totp(self):
        code = self.totp_var.get()
        if not code or code == "-" or code == "N/A":
            return self._show_toast("No TOTP secret for this entry", "warning")
        self._copy_to_clipboard(code, "TOTP")

    def delete_selected(self):
        if not self.session:
            return
        ids = self._get_selected_entry_ids()
        if not ids:
            return messagebox.showwarning("Delete", "Select at least one entry to delete.")
        if not self._require_step_up_or_phrase("delete_secret", "delete selected password entries"):
            return

        if len(ids) > 1:
            if not messagebox.askyesno("Delete", f"Permanently delete {len(ids)} entries? This cannot be undone."):
                return
            if self._undo_buffer:
                self._commit_undo_action()
            deleted = 0
            for entry_id in ids:
                ok, _ = self.api.delete_secret(self.session["user_id"], entry_id)
                if ok:
                    deleted += 1
            self.refresh_vault_table()
            self._show_toast(f"{deleted} entries deleted.", "info")
            return

        data = self._get_selected_values()
        if not data:
            return
        entry_id = data["id"]
        service = data["service"]
        if self._undo_buffer:
            self._commit_undo_action()
        target_rid = None
        for rid in self.vault_table.get_children():
            try:
                if int(rid) == entry_id:
                    target_rid = rid
                    break
            except (ValueError, TypeError):
                pass
        if not target_rid:
            return
        self.vault_table.delete(target_rid)

        def _do_actual_delete():
            if not self.session:
                self._undo_buffer = None
                return
            if self._undo_buffer and self._undo_buffer["entry_id"] == entry_id:
                ok, _ = self.api.delete_secret(self.session["user_id"], entry_id)
                if ok:
                    self.logger.info("Secret deleted permanently: %s", service)
                else:
                    self._show_toast(f"Failed to delete {service}", "error")
                    self.refresh_vault_table()
                self._undo_buffer = None

        undo_job = self.root.after(self.DEFAULT_UNDO_TIMEOUT_MS, _do_actual_delete)
        self._undo_buffer = {
            "action": "delete",
            "entry_id": entry_id,
            "service": service,
            "job_id": undo_job
        }
        self._show_toast(f"Deleted {service}. Undo? (Ctrl+Z)", "info", duration_ms=10000)
        self.root.bind("<Control-z>", self.undo_action)

    def undo_action(self, _event=None):
        """Reverses the last destructive action if it is still in the buffer."""
        if not self._undo_buffer:
            return

        if self._undo_buffer["action"] == "delete":
            self.root.after_cancel(self._undo_buffer["job_id"])
            self._undo_buffer = None
            self.refresh_vault_table()
            self._show_toast("Deletion undone", "success")
            self.root.unbind("<Control-z>")

    def _commit_undo_action(self):
        """Executes the pending action immediately."""
        if not self._undo_buffer:
            return
        self.root.after_cancel(self._undo_buffer["job_id"])
        if self._undo_buffer["action"] == "delete":
            self.api.delete_secret(self.session["user_id"], self._undo_buffer["entry_id"])
        self._undo_buffer = None

    def _update_strength_meter(self):
        pwd = self.password_var.get()
        if not pwd:
            self.strength_canvas.delete("all")
            self.strength_label.config(text="")
            return

        score, reasons = self.api.calculate_strength(pwd)
        color = STRENGTH_COLOURS.get(score, "#e2e8f0")
        label = STRENGTH_LABELS.get(score, "Unknown")

        if reasons and score < 4:
            label += f" ({reasons[0]})"

        self.strength_canvas.delete("all")
        w = self.strength_canvas.winfo_width()
        if w < 10: w = 240 # fallback
        fill_w = (w * (score + 1)) / 5
        self.strength_canvas.create_rectangle(0, 0, fill_w, 6, fill=color, outline="")
        self.strength_label.config(text=label, foreground=color)

    # ---------------------- import ----------------------
    def _build_import_page(self):
        page = ttk.Frame(self.content)
        ttk.Label(page, text="Bring passwords from another app", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Pick a CSV or JSON file (e.g. exported from Chrome or Firefox), then click Import.", style="Sub.TLabel").pack(anchor="w", pady=(0, 4))
        
        info_frame = ttk.Frame(page, style="Panel.TFrame", padding=10)
        info_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(
            info_frame,
            text="💡 This is for a list of passwords from a file. To restore everything from a backup you made here, use the Backup tab.",
            style="Sub.TLabel",
            foreground=self.palette.get("accent", "#58a6ff"),
            justify="left",
            wraplength=800
        ).pack(anchor="w")

        self.import_path_var = tk.StringVar()

        row = ttk.Frame(page)
        row.pack(fill="x")
        self.import_entry = self._make_entry(row, self.import_path_var)
        self.import_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row, text="Browse", command=self._pick_csv).pack(side="left")
        ttk.Button(row, text="Preview file", command=self._preview_import_file, style="Secondary.TButton").pack(side="left", padx=4)
        ttk.Button(row, text="Import now", command=self.import_csv, style="Accent.TButton").pack(side="left", padx=8)

        summary = ttk.Frame(page)
        summary.pack(fill="x", pady=(10, 8))

        self.imp_total_var = tk.StringVar(value="Total rows: 0")
        self.imp_imported_var = tk.StringVar(value="Imported: 0")
        self.imp_skipped_var = tk.StringVar(value="Skipped: 0")

        for i, var in enumerate([self.imp_total_var, self.imp_imported_var, self.imp_skipped_var]):
            box = ttk.Frame(summary, style="Panel.TFrame", padding=10)
            box.grid(row=0, column=i, padx=(0 if i == 0 else 8, 0), sticky="nsew")
            ttk.Label(box, textvariable=var, style="CardTitle.TLabel").pack(anchor="w")
            summary.columnconfigure(i, weight=1)

        ctrl = ttk.Frame(page)
        ctrl.pack(fill="x", pady=(0, 6))
        self.import_toggle_btn = ttk.Button(ctrl, text="👁 Show passwords", command=self._toggle_import_passwords)
        self.import_toggle_btn.pack(side="left")
        ttk.Button(ctrl, text="Clear list", command=self._clear_import_view, style="Secondary.TButton").pack(side="left", padx=8)

        table_panel = ttk.Frame(page, style="Panel.TFrame", padding=8)
        table_panel.pack(fill="both", expand=True)

        cols = ("row", "service", "username", "url", "password")
        self.import_table = ttk.Treeview(table_panel, columns=cols, show="headings", height=12)
        headers = {
            "row": ("Row", 80),
            "service": ("Service", 240),
            "username": ("Username", 240),
            "url": ("URL", 380),
            "password": ("Password", 220),
        }
        for key, (title, width) in headers.items():
            self.import_table.heading(key, text=title)
            self.import_table.column(key, width=width, anchor="w")

        y = ttk.Scrollbar(table_panel, orient="vertical", command=self.import_table.yview)
        x = ttk.Scrollbar(table_panel, orient="horizontal", command=self.import_table.xview)
        self.import_table.configure(yscrollcommand=y.set, xscrollcommand=x.set)

        self.import_table.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        table_panel.rowconfigure(0, weight=1)
        table_panel.columnconfigure(0, weight=1)

        err_panel = ttk.Frame(page)
        err_panel.pack(fill="x", pady=(8, 0))
        ttk.Label(err_panel, text="Import notes", style="Sub.TLabel").pack(anchor="w")
        self.import_notes = tk.Text(
            err_panel,
            height=5,
            wrap="word",
            bg=self.palette.get("input_bg", self.palette["panel"]),
            fg=self.palette["text"],
            font=self.font_small,
            relief="solid",
            bd=1,
        )
        self.import_notes.pack(fill="x")
        self.import_notes.insert("1.0", "No import yet.")
        self.import_notes.configure(state="disabled")

        return page

    def _clear_import_view(self):
        self.import_rows = []
        self.import_show_passwords = False
        self.imp_total_var.set("Total rows: 0")
        self.imp_imported_var.set("Imported: 0")
        self.imp_skipped_var.set("Skipped: 0")
        self.import_toggle_btn.configure(text="👁 Show passwords")
        self._set_import_notes("No import yet.")
        self._refresh_import_table()

    def _set_import_notes(self, text: str):
        self.import_notes.configure(state="normal")
        self.import_notes.delete("1.0", "end")
        self.import_notes.insert("1.0", text)
        self.import_notes.configure(state="disabled")

    def _refresh_import_table(self):
        if not hasattr(self, "import_table"):
            return
        for iid in self.import_table.get_children():
            self.import_table.delete(iid)

        for idx, row in enumerate(self.import_rows, start=1):
            pw = row.get("password", "")
            if not self.import_show_passwords:
                pw_val = "•" * min(max(len(pw), 8), 16) if pw else ""
            else:
                pw_val = pw
            self.import_table.insert(
                "",
                "end",
                iid=f"imp-{idx}",
                values=(row.get("row", ""), row.get("service", ""), row.get("username", ""), row.get("url", ""), pw_val),
            )

    def _toggle_import_passwords(self):
        if not self.import_rows:
            messagebox.showinfo("Show passwords", "Load a file first: click Preview file or Import now.")
            return
        if not self.import_show_passwords:
            if not self._require_step_up_or_phrase("show_import_passwords", "show imported passwords"):
                return
            self.import_show_passwords = True
            self.import_toggle_btn.configure(text="🙈 Hide passwords")
        else:
            self.import_show_passwords = False
            self.import_toggle_btn.configure(text="👁 Show passwords")
        self._refresh_import_table()

    def _preview_import_file(self):
        """Load file for preview without importing. Use Show passwords to reveal."""
        file_path = self.import_path_var.get().strip()
        if not file_path:
            messagebox.showwarning("Preview", "Choose a file first (Browse).")
            return
        fp = Path(file_path)
        if not fp.exists():
            messagebox.showerror("Preview", f"File not found:\n{file_path}")
            return
        try:
            ext = (fp.suffix or "").lower()
            if ext == ".json":
                rows = self._fallback_preview_from_json(file_path, max_rows=10000)
            else:
                rows = self._fallback_preview_from_csv(file_path, max_rows=10000)
            self.import_rows = rows
            self.import_show_passwords = False
            self.import_toggle_btn.configure(text="👁 Show passwords")
            self.imp_total_var.set(f"Total rows: {len(rows)}")
            self.imp_imported_var.set("Imported: 0")
            self.imp_skipped_var.set("Skipped: 0")
            self._refresh_import_table()
            self._set_import_notes(f"Preview loaded: {len(rows)} entries. Click Show passwords to reveal, or Import now to add to vault.")
        except Exception as e:
            messagebox.showerror("Preview failed", str(e))
            self._set_import_notes(f"Preview failed: {e}")

    def _pick_csv(self):
        path = filedialog.askopenfilename(
            title="Select password file (CSV or JSON)",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")],
        )
        if path:
            self.import_path_var.set(path)

    def _fallback_preview_from_csv(self, csv_path: str, max_rows: int = 10000):
        out = []
        try:
            with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
                r = csv.DictReader(f)
                for i, row in enumerate(r, start=2):
                    if len(out) >= max_rows:
                        break
                    service = (row.get("name") or row.get("service") or row.get("site") or row.get("title") or "Imported Entry").strip()
                    username = (row.get("username") or row.get("username_email") or row.get("email") or row.get("login") or "unknown").strip()
                    url = (row.get("url") or row.get("website") or row.get("site_url") or "").strip()
                    password = (row.get("password") or row.get("secret") or row.get("pass") or "").strip()
                    if password:
                        out.append({"row": i, "service": service, "username": username, "url": url, "password": password})
        except Exception:
            return []
        return out

    def _fallback_preview_from_json(self, json_path: str, max_rows: int = 10000):
        out = []
        try:
            with open(json_path, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            
            # Handle different JSON formats
            entries = []
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                if "logins" in data:
                    entries = data["logins"]
                elif "entries" in data:
                    entries = data["entries"]
                elif "passwords" in data:
                    entries = data["passwords"]
                else:
                    for key, value in data.items():
                        if isinstance(value, list) and value:
                            entries = value
                            break
            
            for i, entry in enumerate(entries, start=1):
                if len(out) >= max_rows:
                    break
                
                entry_lower = {str(k).lower(): v for k, v in entry.items() if isinstance(k, str)}
                
                service = ""
                username = ""
                url = ""
                password = ""
                
                for key in ["hostname", "origin", "url", "site", "website", "name", "service", "title"]:
                    if key in entry_lower and isinstance(entry_lower[key], str):
                        service = entry_lower[key].strip()
                        break
                
                for key in ["username", "user", "email", "login"]:
                    if key in entry_lower and isinstance(entry_lower[key], str):
                        username = entry_lower[key].strip()
                        break
                
                for key in ["url", "website", "site", "origin"]:
                    if key in entry_lower and isinstance(entry_lower[key], str):
                        url = entry_lower[key].strip()
                        break
                
                for key in ["password", "pass", "pwd", "secret"]:
                    if key in entry_lower and isinstance(entry_lower[key], str):
                        password = entry_lower[key].strip()
                        break
                
                if not service:
                    service = "Imported Entry"
                if password:
                    out.append({"row": i, "service": service, "username": username, "url": url, "password": password})
        except Exception:
            return []
        return out

    def import_csv(self):
        if not self.session:
            return messagebox.showwarning("Import", "Login first.")

        # Re-auth gate for import (security best practice)
        if not self._require_step_up_or_phrase("import_passwords", "import passwords from file"):
            return

        file_path = self.import_path_var.get().strip()
        if not file_path:
            return messagebox.showwarning("Import", "Choose a file first.")

        fp = Path(file_path)
        if not fp.exists():
            return messagebox.showerror("Import failed", f"File not found:\n{file_path}")

        try:
            cert = self.api.get_active_certificate(self.session["user_id"], "encryption")
            if not cert:
                return messagebox.showerror("Import failed", "No active encryption certificate available. Please ensure you are logged in properly.")
            
            # Detect file type and import accordingly
            file_ext = fp.suffix.lower()
            if file_ext == ".json":
                ok, result = self.api.import_secrets_from_json(self.session["user_id"], file_path, cert, max_rows=10000)
            elif file_ext == ".csv":
                ok, result = self.api.import_secrets_from_csv(self.session["user_id"], file_path, cert, max_rows=10000)
            else:
                # Try to auto-detect by reading first few bytes
                with open(file_path, "rb") as f:
                    first_bytes = f.read(1024)
                    try:
                        first_bytes.decode("utf-8").strip().startswith("{")
                        ok, result = self.api.import_secrets_from_json(self.session["user_id"], file_path, cert, max_rows=10000)
                    except (UnicodeDecodeError, AttributeError):
                        ok, result = self.api.import_secrets_from_csv(self.session["user_id"], file_path, cert, max_rows=10000)

            # FIXED: Better error message extraction with detailed logging
            if not ok:
                # Check for error message in various possible keys
                if isinstance(result, dict):
                    error_msg = (
                        result.get("error") or 
                        result.get("message") or 
                        result.get("error_message") or
                        "Import failed. Check the CSV file format and try again."
                    )
                elif isinstance(result, str):
                    error_msg = result
                else:
                    error_msg = f"Import failed: {str(result)}"
                
                self.logger.error("Import failed: %s (result type: %s)", error_msg, type(result).__name__)
                
                # Show detailed error message
                detailed_msg = f"{error_msg}\n\nFile: {fp.name}"
                messagebox.showerror("Import failed", detailed_msg)
                self._set_import_notes(f"Import failed: {error_msg}")
                return

            # Process successful import
            total = int(result.get("total_rows", 0))
            imported = int(result.get("imported", result.get("added", 0)))
            skipped = int(result.get("skipped", 0))
            failed = int(result.get("failed", 0))

            self.imp_total_var.set(f"Total rows: {total}")
            self.imp_imported_var.set(f"Imported: {imported}")
            self.imp_skipped_var.set(f"Skipped: {skipped}")

            self.import_show_passwords = False
            self.import_toggle_btn.configure(text="👁 Show passwords")

            rows = result.get("imported_items") or []
            if not rows and imported > 0:
                # Try to generate preview from file
                if file_ext == ".csv":
                    rows = self._fallback_preview_from_csv(file_path, max_rows=min(imported, 10000))
                elif file_ext == ".json":
                    rows = self._fallback_preview_from_json(file_path, max_rows=min(imported, 10000))

            self.import_rows = rows
            self._refresh_import_table()

            errors = result.get("errors") or result.get("messages") or []
            if errors:
                preview = "\n".join(f"• {e}" for e in errors[:30])
                if len(errors) > 30:
                    preview += f"\n• ... and {len(errors)-30} more"
                notes = f"Import completed with warnings.\n\n{preview}"
            else:
                notes = "Import completed successfully. No warnings."
            self._set_import_notes(notes)

            self.refresh_vault_table()
            self.refresh_dashboard(force_health=True)

            if imported > 0:
                self._run_backup_after_import()
                messagebox.showinfo("Import", f"Imported {imported} entries.\nSkipped: {skipped}\nFailed: {failed}")
                self._set_status(f"CSV import complete: {imported} imported, {skipped} skipped")
            else:
                messagebox.showwarning("Import", f"No entries imported.\nSkipped: {skipped}\nFailed: {failed}\n\nCheck the file format.")
                self._set_status(f"Import: {skipped} skipped, {failed} failed")
                
        except Exception as e:
            error_msg = f"Import error: {str(e)}"
            self.logger.error("Import exception: %s", e, exc_info=True)
            messagebox.showerror("Import failed", f"{error_msg}\n\nFile: {fp.name}\n\nCheck the file format and try again.")
            self._set_import_notes(f"Import failed: {error_msg}")

    def _run_backup_after_import(self):
        """Run a change-triggered backup immediately after import if backup-on-change is enabled."""
        if not self.session:
            return
        try:
            uid = int(self.session["user_id"])
            enc_priv = self.session.get("enc_priv")
            if not enc_priv:
                return
            enc_priv_bytes = bytes(enc_priv) if isinstance(enc_priv, bytearray) else enc_priv
            status = self.api.get_backup_status(uid)
            if not status.get("enabled") or not status.get("backup_on_change_enabled"):
                return
            key_or_pass = None
            mode = None
            if hasattr(self, "backup_recovery_key_var"):
                key_or_pass = (self.backup_recovery_key_var.get() or "").strip()
            if key_or_pass:
                ok_resolve, mode, err = self.api.resolve_recovery_factor(uid, key_or_pass)
                if ok_resolve:
                    ok, msg = self.api.create_local_backup_now(
                        uid, enc_priv_bytes, reason="change_triggered",
                        recovery_key_or_password=key_or_pass, mode=mode
                    )
                    if ok:
                        self.api.set_auto_backup_key_for_session(uid, key_or_pass, mode)
                else:
                    ok, msg = False, err
            else:
                ok, msg = self.api.create_local_backup_now(uid, enc_priv_bytes, reason="change_triggered")
            if ok and hasattr(self, "backup_phase2_status_var"):
                self.refresh_backup_page()
                self._show_toast("Backup created after import", "success")
        except Exception:
            pass

    # ---------------------- backup ----------------------
    def _build_backup_page(self):
        # Scrollable container so checkboxes and bottom section are never clipped
        outer = ttk.Frame(self.content)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(0, weight=1)
        canvas = tk.Canvas(
            outer,
            bg=self.palette["bg"],
            highlightthickness=0,
        )
        scrollbar = ttk.Scrollbar(outer)
        inner = ttk.Frame(canvas)
        inner_window = canvas.create_window(0, 0, window=inner, anchor="nw")

        def _on_frame_configure(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def _on_canvas_configure(event):
            w = event.width
            canvas.itemconfig(inner_window, width=max(w, inner.winfo_reqwidth()))

        inner.bind("<Configure>", _on_frame_configure)
        canvas.bind("<Configure>", _on_canvas_configure)
        canvas.configure(yscrollcommand=scrollbar.set)
        scrollbar.configure(command=canvas.yview)

        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        def _scroll_backup(delta_units: int):
            canvas.yview_scroll(-delta_units, "units")

        def _on_mousewheel(event):
            if getattr(event, "delta", None) is not None:
                _scroll_backup(int(event.delta / 120))
            return "break"

        def _on_linux_scroll_up(event):
            _scroll_backup(3)
            return "break"

        def _on_linux_scroll_down(event):
            _scroll_backup(-3)
            return "break"

        def _bind_mousewheel_to_children(parent):
            parent.bind("<MouseWheel>", _on_mousewheel)
            try:
                parent.bind("<Button-4>", _on_linux_scroll_up)
                parent.bind("<Button-5>", _on_linux_scroll_down)
            except Exception:
                pass
            for child in parent.winfo_children():
                _bind_mousewheel_to_children(child)

        canvas.bind("<MouseWheel>", _on_mousewheel)
        canvas.bind("<Button-4>", _on_linux_scroll_up)
        canvas.bind("<Button-5>", _on_linux_scroll_down)

        page = inner
        ttk.Label(page, text="Backup & recovery", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            page,
            text="Save a copy of your passwords on this device. You need a key or password to open it later.",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(0, 10))
        
        info_frame = ttk.Frame(page, style="Panel.TFrame", padding=10)
        info_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(
            info_frame,
            text="💡 To bring in passwords from a browser file (CSV/JSON), use the Import tab. To get back everything from a backup you made here, use the Backup tab.",
            style="Sub.TLabel",
            foreground=self.palette.get("accent", "#58a6ff"),
            justify="left",
            wraplength=800
        ).pack(anchor="w")
        ttk.Label(
            info_frame,
            text="Forgot both login and recovery passwords? On the login screen click \"Forgot both? Restore from a backup file\" and use your backup key or backup password.",
            style="Sub.TLabel",
            foreground=self.palette.get("accent", "#58a6ff"),
            justify="left",
            wraplength=800,
        ).pack(anchor="w", pady=(4, 0))

        # ── 1) Recovery Setup (Phase 5: clear sections) ──
        recovery_frame = ttk.Frame(page, style="Panel.TFrame", padding=12)
        recovery_frame.pack(fill="x", pady=(0, 12))
        ttk.Label(recovery_frame, text="Step 1: Choose how to protect your backup", style="Header.TLabel").pack(anchor="w")
        self.backup_recovery_status_var = tk.StringVar(value="Checking…")
        self.backup_recovery_status_label = ttk.Label(recovery_frame, textvariable=self.backup_recovery_status_var, style="Sub.TLabel")
        self.backup_recovery_status_label.pack(anchor="w", pady=(4, 8))
        btn_row = ttk.Frame(recovery_frame)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Get a recovery key (long code – save it once)", style="Accent.TButton", command=self._on_enable_backup_recovery_key).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Use a password I choose instead", style="Secondary.TButton", command=self._on_set_backup_password).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Save backup to a file (on my PC)", style="Secondary.TButton", command=self._on_create_recovery_backup).pack(side="left")
        ttk.Label(recovery_frame, text="Type your backup key or backup password here (same one you set above):", style="Sub.TLabel").pack(anchor="w", pady=(8, 2))
        self.backup_recovery_key_var = tk.StringVar()
        row1 = self._make_password_entry_with_eye(
            recovery_frame,
            self.backup_recovery_key_var,
            mask="•",
            require_step_up_for_reveal=True,
            step_up_action_name="reveal_backup_key",
            step_up_action_text="reveal backup key or password",
        )
        row1.pack(fill="x")
        self.backup_recovery_key_entry = row1.winfo_children()[0]
        save_row = ttk.Frame(recovery_frame)
        save_row.pack(anchor="w", pady=(6, 0))
        ttk.Button(save_row, text="Save credentials for this session", style="Secondary.TButton", command=self._on_save_backup_credentials).pack(side="left", padx=(0, 8))
        ttk.Label(save_row, text="(enables auto backup until logout)", style="Sub.TLabel").pack(side="left")
        self.backup_cred_status_var = tk.StringVar(value="")
        self.backup_cred_status_label = ttk.Label(save_row, textvariable=self.backup_cred_status_var, style="Sub.TLabel", foreground="green")
        self.backup_cred_status_label.pack(side="left", padx=(12, 0))
        ttk.Label(recovery_frame, text="If you use a recovery key: save it somewhere safe. The app shows it only once.", style="Sub.TLabel", wraplength=700).pack(anchor="w", pady=(8, 0))

        # ── 2) Local Backups (Phase 5) — grid layout for alignment and resize ──
        phase2_frame = ttk.Frame(page, style="Panel.TFrame", padding=12)
        phase2_frame.pack(fill="x", pady=(0, 12))
        phase2_frame.columnconfigure(1, weight=1)

        row = 0
        ttk.Label(phase2_frame, text="Step 2: Make and check backups", style="Header.TLabel").grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 4))
        row += 1
        self.backup_phase2_status_var = tk.StringVar(value="")
        ttk.Label(phase2_frame, textvariable=self.backup_phase2_status_var, style="Sub.TLabel", wraplength=700).grid(row=row, column=0, columnspan=3, sticky="w", pady=(0, 6))
        row += 1
        ttk.Label(phase2_frame, text="Your backup key or password (same as above):", style="Sub.TLabel").grid(row=row, column=0, columnspan=3, sticky="w", pady=(6, 2))
        row += 1
        row_p2 = self._make_password_entry_with_eye(
            phase2_frame,
            self.backup_recovery_key_var,
            mask="•",
            require_step_up_for_reveal=True,
            step_up_action_name="reveal_backup_key",
            step_up_action_text="reveal backup key or password",
        )
        row_p2.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(0, 8))
        self.backup_recovery_key_entry_p2 = row_p2.winfo_children()[0]
        phase2_frame.rowconfigure(row, weight=0)
        row += 1
        p2_btn_frame = ttk.Frame(phase2_frame)
        p2_btn_frame.grid(row=row, column=0, columnspan=3, sticky="w")
        ttk.Button(p2_btn_frame, text="Create backup now", style="Accent.TButton", command=self._on_create_backup_now).pack(side="left", padx=(0, 8))
        ttk.Button(p2_btn_frame, text="Check selected backup", style="Secondary.TButton", command=self._on_validate_selected_backup).pack(side="left", padx=(0, 8))
        ttk.Button(p2_btn_frame, text="Check latest backup", style="Secondary.TButton", command=self._on_validate_latest_backup).pack(side="left")
        row += 1
        ttk.Label(phase2_frame, text="Your backup files:", style="Sub.TLabel").grid(row=row, column=0, columnspan=3, sticky="w", pady=(8, 2))
        row += 1
        self.backup_listbox = tk.Listbox(
            phase2_frame, height=4, selectmode="single",
            bg=self.palette.get("input_bg", self.palette["panel"]),
            fg=self.palette["text"],
            font=self.font_small,
            highlightthickness=1,
            highlightbackground=self.palette["border"],
        )
        self.backup_listbox.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(0, 8))
        row += 1
        ttk.Label(phase2_frame, text="How many backups to keep:", style="Sub.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(0, 4))
        self.backup_keep_n_var = tk.StringVar(value="10")
        self.backup_keep_n_spin = self._make_spinbox(phase2_frame, self.backup_keep_n_var, 1, 100, width=8)
        self.backup_keep_n_spin.grid(row=row, column=1, sticky="w", padx=(0, 8), pady=(0, 4))
        ttk.Button(phase2_frame, text="Save", command=self._on_save_backup_retention).grid(row=row, column=2, sticky="w", pady=(0, 4))
        row += 1
        ttk.Label(phase2_frame, text="Auto backup every (hours):", style="Sub.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(0, 4))
        self.backup_schedule_hours_var = tk.StringVar(value="24")
        self.backup_schedule_spin = self._make_spinbox(phase2_frame, self.backup_schedule_hours_var, 1, 168, width=8)
        self.backup_schedule_spin.grid(row=row, column=1, sticky="w", padx=(0, 8), pady=(0, 4))
        ttk.Button(phase2_frame, text="Save schedule", command=self._on_save_backup_schedule).grid(row=row, column=2, sticky="w", pady=(0, 4))
        row += 1
        ttk.Label(phase2_frame, text="Warn me if no backup for (days):", style="Sub.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(0, 4))
        self.backup_stale_days_var = tk.StringVar(value="7")
        self.backup_stale_spin = self._make_spinbox(phase2_frame, self.backup_stale_days_var, 1, 90, width=8)
        self.backup_stale_spin.grid(row=row, column=1, sticky="w", padx=(0, 8), pady=(0, 4))
        ttk.Button(phase2_frame, text="Save", command=self._on_save_stale_warning_days).grid(row=row, column=2, sticky="w", pady=(0, 4))
        row += 1
        ttk.Label(phase2_frame, text="To use automatic backups, enter your backup key or password in the field above once. The app will use it until you log out.", style="Sub.TLabel", wraplength=700).grid(row=row, column=0, columnspan=3, sticky="w", pady=(8, 4))
        row += 1
        self.backup_auto_var = tk.BooleanVar(value=False)
        self.backup_on_change_var = tk.BooleanVar(value=False)
        self._make_checkbutton(phase2_frame, "Make a backup automatically on a schedule", self.backup_auto_var, background=self.palette["panel"], command=self._on_backup_auto_toggle).grid(row=row, column=0, columnspan=3, sticky="w", pady=(8, 4))
        row += 1
        self._make_checkbutton(phase2_frame, "Make a backup when I add or change passwords", self.backup_on_change_var, background=self.palette["panel"], command=self._on_backup_on_change_toggle).grid(row=row, column=0, columnspan=3, sticky="w", pady=(4, 4))
        row += 1
        ttk.Label(phase2_frame, text="Backup on change delay (seconds, 0=immediate):", style="Sub.TLabel").grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(0, 4))
        self.backup_on_change_debounce_var = tk.StringVar(value="60")
        self.backup_on_change_debounce_spin = self._make_spinbox(phase2_frame, self.backup_on_change_debounce_var, 0, 300, width=8)
        self.backup_on_change_debounce_spin.grid(row=row, column=1, sticky="w", padx=(0, 8), pady=(0, 4))
        ttk.Button(phase2_frame, text="Save", command=self._on_save_backup_on_change_debounce).grid(row=row, column=2, sticky="w", pady=(0, 4))
        row += 1
        ttk.Button(phase2_frame, text="Open folder where backups are saved", style="Secondary.TButton", command=self._on_open_backup_folder).grid(row=row, column=0, sticky="w", padx=(0, 8), pady=(0, 4))
        self.backup_folder_path_var = tk.StringVar(value="")
        self.backup_folder_path_entry = self._make_entry(phase2_frame, self.backup_folder_path_var)
        self.backup_folder_path_entry.grid(row=row, column=1, sticky="ew", padx=(0, 8), pady=(0, 4))
        ttk.Button(phase2_frame, text="Copy path", command=self._on_copy_backup_folder_path).grid(row=row, column=2, sticky="w", pady=(0, 4))
        row += 1
        ttk.Label(phase2_frame, text="Backups stay on your computer. You need your key or password to open them.", style="Sub.TLabel", wraplength=700).grid(row=row, column=0, columnspan=3, sticky="w", pady=(4, 0))

        # ── 3) Restore & Reset (Phase 5) ──
        restore_frame = ttk.Frame(page, style="Panel.TFrame", padding=12)
        restore_frame.pack(fill="x", pady=(0, 12))
        ttk.Label(restore_frame, text="Forgot everything?", style="Header.TLabel").pack(anchor="w")
        ttk.Label(restore_frame, text="On the login screen click \"Forgot both? Restore from a backup file\" and follow the steps.", style="Sub.TLabel", wraplength=700).pack(anchor="w", pady=(4, 0))

        # ── 4) Health (Phase 5 dashboard) ──
        health_frame = ttk.Frame(page, style="Panel.TFrame", padding=12)
        health_frame.pack(fill="x", pady=(0, 12))
        ttk.Label(health_frame, text="Backup status", style="Header.TLabel").pack(anchor="w")
        self.backup_health_summary_var = tk.StringVar(value="")
        self.backup_health_label = ttk.Label(health_frame, textvariable=self.backup_health_summary_var, style="Sub.TLabel", wraplength=750, justify="left")
        self.backup_health_label.pack(anchor="w", pady=(4, 0))

        content = ttk.Frame(page, style="Panel.TFrame", padding=12)
        content.pack(fill="both", expand=True)

        ttk.Label(content, text="Restore your passwords from a backup", style="Header.TLabel").pack(anchor="w")
        ttk.Label(content, text="1. Choose your backup file (.json or .enc)", style="Sub.TLabel").pack(anchor="w", pady=(8, 4))

        path_row = ttk.Frame(content)
        path_row.pack(fill="x")
        self.backup_import_path_var = tk.StringVar()
        self.backup_import_path_entry = self._make_entry(path_row, self.backup_import_path_var)
        self.backup_import_path_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(path_row, text="Browse", command=self._pick_backup_file).pack(side="left")

        ttk.Label(
            content,
            text="2. Type the password or key you used when you made the backup",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(10, 4))
        self.backup_import_pass_var = tk.StringVar()
        self.backup_import_pass_entry = self._make_entry(content, self.backup_import_pass_var, show="•")
        self.backup_import_pass_entry.pack(fill="x")
        self.backup_import_show = tk.BooleanVar(value=False)
        self._make_checkbutton(
            content,
            "Show passphrase",
            self.backup_import_show,
            background=self.palette["panel"],
            command=lambda: self.backup_import_pass_entry.configure(show="" if self.backup_import_show.get() else "•"),
        ).pack(anchor="w", pady=(6, 8))
        ttk.Button(content, text="Restore from this backup", style="Secondary.TButton", command=self._import_backup_file).pack(anchor="w")

        ttk.Separator(content, orient="horizontal").pack(fill="x", pady=12)
        ttk.Label(content, text="What happened lately (backup log)", style="Header.TLabel").pack(anchor="w")
        self.backup_events_box = tk.Text(
            content,
            height=10,
            wrap="word",
            bg=self.palette.get("input_bg", self.palette["panel"]),
            fg=self.palette["text"],
            font=self.font_small,
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.palette["border"],
        )
        self.backup_events_box.pack(fill="both", expand=True)
        self.backup_events_box.configure(state="disabled")

        # So mouse wheel scrolls when hovering anywhere over backup content, not just the scrollbar
        _bind_mousewheel_to_children(inner)

        return outer

    def _pick_backup_file(self):
        path = filedialog.askopenfilename(
            title="Select backup file",
            filetypes=[
                ("Backup files (.json or .enc)", "*.json;*.enc"),
                ("JSON files", "*.json"),
                ("Encrypted backup", "*.enc"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.backup_import_path_var.set(path)

    def _on_enable_backup_recovery_key(self):
        if not self.session:
            messagebox.showwarning("Backup", "Login first.")
            return
        if not self._require_step_up_or_phrase("reveal_backup_recovery_key", "enable backup recovery key"):
            return
        try:
            ok, msg, one_time_key = self.api.initialize_backup_recovery_for_user(int(self.session["user_id"]))
            if not ok:
                messagebox.showerror("Backup Recovery", msg)
                return
            warning = "Store this key offline in a safe place. It will NOT be shown again.\n\nYou need this key to restore from an encrypted backup if you forget your main passphrase and recovery phrase."
            # Show key in a dialog with selectable/copyable field and Copy button (messagebox text is not copyable)
            dialog = tk.Toplevel(self.root)
            dialog.title("Backup Recovery Key — save it now")
            dialog.transient(self.root)
            dialog.grab_set()
            dialog.configure(bg=self.palette["bg"])
            f = ttk.Frame(dialog, style="Panel.TFrame", padding=16)
            f.pack(fill="both", expand=True)
            ttk.Label(f, text=msg, style="Sub.TLabel", wraplength=450).pack(anchor="w", pady=(0, 8))
            ttk.Label(f, text=warning, style="Sub.TLabel", wraplength=450).pack(anchor="w", pady=(0, 12))
            ttk.Label(f, text="Recovery key (select and Ctrl+C, or use Copy):", style="Sub.TLabel").pack(anchor="w", pady=(0, 4))
            key_entry = tk.Entry(
                f,
                font=self.font_entry,
                bg=self.palette.get("input_bg", self.palette["panel"]),
                fg=self.palette.get("input_fg", self.palette["text"]),
                relief="solid",
                bd=1,
                highlightthickness=1,
                highlightbackground=self.palette["border"],
            )
            key_entry.pack(fill="x", pady=(0, 8))
            key_entry.insert(0, one_time_key)
            key_entry.select_range(0, tk.END)
            key_entry.focus_set()
            def _prevent_edit(evt):
                # Allow Ctrl+C, Ctrl+A, navigation; block typing that would change the key
                if (evt.state & 0x4) or evt.keysym in ("Left", "Right", "Up", "Down", "Home", "End", "Tab", "Return"):
                    return
                return "break"
            key_entry.bind("<KeyPress>", _prevent_edit)
            btn_row = ttk.Frame(f)
            btn_row.pack(fill="x", pady=(8, 0))
            def _copy_key():
                self.root.clipboard_clear()
                self.root.clipboard_append(one_time_key)
                self._set_status("Recovery key copied to clipboard")
            ttk.Button(btn_row, text="Copy to clipboard", style="Accent.TButton", command=_copy_key).pack(side="left", padx=(0, 8))
            ttk.Button(btn_row, text="OK", style="Secondary.TButton", command=dialog.destroy).pack(side="left")
            dialog.update_idletasks()
            dialog.geometry(f"+{self.root.winfo_rootx() + 80}+{self.root.winfo_rooty() + 80}")
            dialog.resizable(True, False)
            self.refresh_backup_page()
            self._set_status("Backup recovery key enabled")
        except Exception as e:
            self.logger.error("Enable backup recovery: %s", e, exc_info=True)
            messagebox.showerror("Backup Recovery", str(e))

    def _on_set_backup_password(self):
        """Set a memorable backup password (alternative to recovery key) for creating/restoring backups."""
        if not self.session:
            messagebox.showwarning("Backup", "Login first.")
            return
        if not self._require_step_up_or_phrase("set_backup_password", "set backup password"):
            return
        dialog = tk.Toplevel(self.root)
        dialog.title("Set Backup Password")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(bg=self.palette["bg"])
        f = ttk.Frame(dialog, style="Panel.TFrame", padding=16)
        f.pack(fill="both", expand=True)
        ttk.Label(f, text="Choose a backup password (min 12 characters). Use it only for backup and restore.", style="Sub.TLabel", wraplength=400).pack(anchor="w", pady=(0, 8))
        ttk.Label(f, text="Backup password:", style="Sub.TLabel").pack(anchor="w", pady=(0, 2))
        pass_var = tk.StringVar()
        self._make_password_entry_with_eye(f, pass_var, mask="•").pack(fill="x", pady=(0, 6))
        ttk.Label(f, text="Confirm backup password:", style="Sub.TLabel").pack(anchor="w", pady=(4, 2))
        confirm_var = tk.StringVar()
        self._make_password_entry_with_eye(f, confirm_var, mask="•").pack(fill="x", pady=(0, 12))
        err_var = tk.StringVar()

        def do_set():
            p = pass_var.get() or ""
            c = confirm_var.get() or ""
            if len(p) < 12:
                err_var.set("Password must be at least 12 characters.")
                return
            if p != c:
                err_var.set("Passwords do not match.")
                return
            ok, msg = self.api.set_backup_password(int(self.session["user_id"]), p)
            if not ok:
                err_var.set(msg)
                return
            dialog.destroy()
            self.refresh_backup_page()
            self._set_status("Backup password set")
            messagebox.showinfo("Backup", "Backup password set. Use this password in the field below when creating or restoring backups.")

        ttk.Label(f, textvariable=err_var, style="Sub.TLabel", foreground="red").pack(anchor="w", pady=(0, 4))
        btn_row = ttk.Frame(f)
        btn_row.pack(fill="x", pady=(8, 0))
        ttk.Button(btn_row, text="Set Backup Password", style="Accent.TButton", command=do_set).pack(side="left", padx=(0, 8))
        ttk.Button(btn_row, text="Cancel", style="Secondary.TButton", command=dialog.destroy).pack(side="left")
        dialog.geometry("+%d+%d" % (self.root.winfo_rootx() + 100, self.root.winfo_rooty() + 100))

    def _on_create_backup_now(self):
        """Create versioned local backup now (Phase 2) using recovery key or backup password from field."""
        if not self.session:
            messagebox.showwarning("Backup", "Login first.")
            return
        if not self._require_step_up_or_phrase("create_backup", "create backup"):
            return
        status = self.api.get_backup_recovery_status(int(self.session["user_id"]))
        if not status.get("enabled"):
            messagebox.showwarning("Backup", "First choose how to protect your backup: click \"Get a recovery key\" or \"Use a password I choose instead\" above.")
            return
        key_or_pass = (self.backup_recovery_key_var.get() or "").strip()
        ok_resolve, mode, err = self.api.resolve_recovery_factor(int(self.session["user_id"]), key_or_pass)
        if not ok_resolve:
            messagebox.showerror("Backup", err)
            return
        enc_priv = self.session.get("enc_priv")
        if not enc_priv:
            messagebox.showerror("Backup", "Session key not available. Re-login.")
            return
        enc_priv_bytes = bytes(enc_priv) if isinstance(enc_priv, bytearray) else enc_priv
        try:
            ok, msg = self.api.create_local_backup_now(
                int(self.session["user_id"]), enc_priv_bytes, reason="manual",
                recovery_key_or_password=key_or_pass, mode=mode,
            )
            if not ok:
                try:
                    uid = int(self.session["user_id"]) if self.session else None
                    self.security_alert_service.notify_security_alert(
                        "local_backup_failed", {"reason": msg}, user_id=uid
                    )
                except Exception:
                    pass
                messagebox.showerror("Backup", msg)
                return
            self._set_status("Backup created")
            try:
                self.refresh_backup_page()
            except Exception as re:
                self.logger.debug("Refresh backup page after create: %s", re)
            messagebox.showinfo("Backup", f"Backup created.\n{msg}")
        except Exception as e:
            self.logger.error("Create backup now: %s", e, exc_info=True)
            messagebox.showerror("Backup", str(e))

    def _on_validate_selected_backup(self):
        if not self.session:
            messagebox.showwarning("Backup", "Login first.")
            return
        sel = self.backup_listbox.curselection()
        path = None
        if sel:
            idx = int(sel[0])
            backups = self.api.list_local_backups(int(self.session["user_id"]))
            if 0 <= idx < len(backups):
                path = backups[idx].get("path")
        if not path:
            backups = self.api.list_local_backups(int(self.session["user_id"]))
            if backups:
                path = backups[0].get("path")
        if not path:
            messagebox.showwarning("Backup", "No backup selected or no local backups.")
            return
        key_or_pass = (self.backup_recovery_key_var.get() or "").strip()
        ok_resolve, mode, err = self.api.resolve_recovery_factor(int(self.session["user_id"]), key_or_pass)
        if not ok_resolve:
            messagebox.showerror("Backup", err)
            return
        try:
            ok, msg = self.api.validate_backup_package(
                path, key_or_pass, mode, user_id=int(self.session["user_id"])
            )
            if ok:
                messagebox.showinfo("Backup", msg)
            else:
                try:
                    uid = int(self.session["user_id"]) if self.session else None
                    self.security_alert_service.notify_security_alert(
                        "backup_validation_failed", {"reason": msg}, user_id=uid
                    )
                except Exception:
                    pass
                messagebox.showerror("Backup", msg)
        except Exception as e:
            self.logger.error("Validate selected backup: %s", e, exc_info=True)
            messagebox.showerror("Backup", "Validation failed: " + str(e))
        finally:
            try:
                self.refresh_backup_page()
            except Exception:
                pass

    def _on_save_backup_retention(self):
        if not self.session:
            return
        try:
            n = int(self.backup_keep_n_var.get())
            if n < 1 or n > 100:
                messagebox.showwarning("Backup", "Keep last N must be between 1 and 100.")
                return
        except ValueError:
            messagebox.showwarning("Backup", "Enter a number between 1 and 100.")
            return
        ok, msg = self.api.update_backup_settings(int(self.session["user_id"]), keep_last_n_backups=n)
        if ok:
            self._set_status("Retention saved")
            self.refresh_backup_page()
        else:
            messagebox.showerror("Backup", msg)

    def _on_save_backup_schedule(self):
        if not self.session:
            return
        try:
            h = float(self.backup_schedule_hours_var.get())
            if h < 0.25 or h > 168:
                messagebox.showwarning("Backup", "Schedule interval must be between 0.25 and 168 hours.")
                return
        except ValueError:
            messagebox.showwarning("Backup", "Enter a valid number for hours.")
            return
        ok, msg = self.api.update_backup_settings(int(self.session["user_id"]), schedule_interval_hours=h)
        if ok:
            self._set_status("Schedule saved")
            self.refresh_backup_page()
        else:
            messagebox.showerror("Backup", msg)

    def _on_save_backup_on_change_debounce(self):
        if not self.session:
            return
        try:
            d = int(self.backup_on_change_debounce_var.get())
            if d < 0 or d > 300:
                messagebox.showwarning("Backup", "Delay must be between 0 and 300 seconds (0=immediate).")
                return
        except ValueError:
            messagebox.showwarning("Backup", "Enter a number between 0 and 300.")
            return
        ok, msg = self.api.update_backup_settings(int(self.session["user_id"]), on_change_debounce_seconds=d)
        if ok:
            self._set_status("Backup on change delay saved")
            self.refresh_backup_page()
        else:
            messagebox.showerror("Backup", msg)

    def _on_save_stale_warning_days(self):
        if not self.session:
            return
        try:
            d = int(self.backup_stale_days_var.get())
            if d < 1 or d > 90:
                messagebox.showwarning("Backup", "Stale warning days must be between 1 and 90.")
                return
        except ValueError:
            messagebox.showwarning("Backup", "Enter a number between 1 and 90.")
            return
        ok, msg = self.api.update_backup_settings(int(self.session["user_id"]), stale_warning_days=d)
        if ok:
            self._set_status("Stale warning setting saved")
            self.refresh_backup_page()
        else:
            messagebox.showerror("Backup", msg)

    def _on_validate_latest_backup(self):
        if not self.session:
            messagebox.showwarning("Backup", "Login first.")
            return
        backups = self.api.list_local_backups(int(self.session["user_id"]))
        if not backups:
            messagebox.showwarning("Backup", "No local backups to validate.")
            return
        path = backups[0].get("path")
        if not path:
            messagebox.showwarning("Backup", "No backup file path.")
            return
        key_or_pass = (self.backup_recovery_key_var.get() or "").strip()
        ok_resolve, mode, err = self.api.resolve_recovery_factor(int(self.session["user_id"]), key_or_pass)
        if not ok_resolve:
            messagebox.showerror("Backup", err)
            return
        try:
            ok, msg = self.api.validate_backup_package(
                path, key_or_pass, mode, user_id=int(self.session["user_id"])
            )
            if ok:
                messagebox.showinfo("Backup", msg)
            else:
                try:
                    uid = int(self.session["user_id"]) if self.session else None
                    self.security_alert_service.notify_security_alert(
                        "backup_validation_failed", {"reason": msg}, user_id=uid
                    )
                except Exception:
                    pass
                messagebox.showerror("Backup", msg)
        except Exception as e:
            self.logger.error("Validate latest backup: %s", e, exc_info=True)
            messagebox.showerror("Backup", "Validation failed: " + str(e))
        finally:
            try:
                self.refresh_backup_page()
            except Exception:
                pass

    def _on_open_backup_folder(self):
        if not self.session:
            messagebox.showwarning("Backup", "Login first.")
            return
        path = self.api.get_backup_folder_path(int(self.session["user_id"]))
        if not path:
            messagebox.showwarning("Backup", "Backup folder not found.")
            return
        folder = Path(path)
        if not folder.is_dir():
            messagebox.showwarning("Backup", "Backup folder not found.")
            return
        ok, err = platform_open_folder(folder)
        if not ok and err:
            messagebox.showerror("Backup", err)

    def _on_copy_backup_folder_path(self):
        if not self.session:
            return
        path = self.api.get_backup_folder_path(int(self.session["user_id"]))
        if path:
            self.root.clipboard_clear()
            self.root.clipboard_append(path)
            self._set_status("Backup folder path copied")

    def _on_backup_auto_toggle(self):
        if not self.session:
            return
        enabled = self.backup_auto_var.get()
        if not enabled:
            ok, msg = self.api.update_backup_settings(int(self.session["user_id"]), backup_auto_enabled=False)
            if not ok:
                messagebox.showerror("Backup", msg)
                self.backup_auto_var.set(True)
            return
        # Enabling: require key to be entered and cached first
        key_or_pass = (self.backup_recovery_key_var.get() or "").strip()
        ok_resolve, mode, err = self.api.resolve_recovery_factor(int(self.session["user_id"]), key_or_pass)
        if not ok_resolve:
            self.backup_auto_var.set(False)
            self.api.update_backup_settings(int(self.session["user_id"]), backup_auto_enabled=False)
            messagebox.showwarning("Backup", "Enter your backup key or password in the field above first, then turn on automatic backups again.")
            return
        ok2, msg2 = self.api.set_auto_backup_key_for_session(int(self.session["user_id"]), key_or_pass, mode)
        if not ok2:
            self.backup_auto_var.set(False)
            self.api.update_backup_settings(int(self.session["user_id"]), backup_auto_enabled=False)
            messagebox.showwarning("Backup", msg2)
            return
        ok, msg = self.api.update_backup_settings(int(self.session["user_id"]), backup_auto_enabled=True)
        if not ok:
            messagebox.showerror("Backup", msg)
            self.backup_auto_var.set(False)
        else:
            self.refresh_backup_page()

    def _on_save_backup_credentials(self):
        """Save backup key/password to session cache so auto backup can run until logout."""
        if not self.session:
            return
        key_or_pass = (self.backup_recovery_key_var.get() or "").strip()
        if not key_or_pass:
            messagebox.showwarning("Backup", "Enter your backup key or password in the field above first.")
            return
        ok_resolve, mode, err = self.api.resolve_recovery_factor(int(self.session["user_id"]), key_or_pass)
        if not ok_resolve:
            messagebox.showwarning("Backup", err or "Invalid backup key or password.")
            return
        ok, msg = self.api.set_auto_backup_key_for_session(int(self.session["user_id"]), key_or_pass, mode)
        if not ok:
            messagebox.showwarning("Backup", msg)
            return
        self._show_toast("Credentials saved for auto backup", "success")
        self.refresh_backup_page()

    def _on_backup_on_change_toggle(self):
        if not self.session:
            return
        enabled = self.backup_on_change_var.get()
        if not enabled:
            ok, msg = self.api.update_backup_settings(int(self.session["user_id"]), backup_on_change_enabled=False)
            if not ok:
                messagebox.showerror("Backup", msg)
                self.backup_on_change_var.set(True)
            return
        # Enabling: require key to be entered and cached first
        key_or_pass = (self.backup_recovery_key_var.get() or "").strip()
        ok_resolve, mode, err = self.api.resolve_recovery_factor(int(self.session["user_id"]), key_or_pass)
        if not ok_resolve:
            self.backup_on_change_var.set(False)
            self.api.update_backup_settings(int(self.session["user_id"]), backup_on_change_enabled=False)
            messagebox.showwarning("Backup", "Enter your backup key or password in the field above first, then turn on automatic backups again.")
            return
        ok2, msg2 = self.api.set_auto_backup_key_for_session(int(self.session["user_id"]), key_or_pass, mode)
        if not ok2:
            self.backup_on_change_var.set(False)
            self.api.update_backup_settings(int(self.session["user_id"]), backup_on_change_enabled=False)
            messagebox.showwarning("Backup", msg2)
            return
        ok, msg = self.api.update_backup_settings(int(self.session["user_id"]), backup_on_change_enabled=True)
        if not ok:
            messagebox.showerror("Backup", msg)
            self.backup_on_change_var.set(False)
        else:
            self.refresh_backup_page()

    def _on_create_recovery_backup(self):
        if not self.session:
            messagebox.showwarning("Backup", "Login first.")
            return
        if not self._require_step_up_or_phrase("export_backup", "create encrypted backup"):
            return
        status = self.api.get_backup_recovery_status(int(self.session["user_id"]))
        if not status.get("enabled"):
            messagebox.showwarning("Backup", "First choose how to protect your backup: click \"Get a recovery key\" or \"Use a password I choose instead\" above.")
            return
        key_or_pass = (self.backup_recovery_key_var.get() or "").strip()
        ok_resolve, mode, err = self.api.resolve_recovery_factor(int(self.session["user_id"]), key_or_pass)
        if not ok_resolve:
            messagebox.showerror("Backup export failed", err)
            return
        out_path = filedialog.asksaveasfilename(
            title="Save encrypted backup",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"securevault_recovery_backup_{int(time.time())}.json",
        )
        if not out_path:
            return
        enc_priv = self.session.get("enc_priv")
        if not enc_priv:
            messagebox.showerror("Backup", "Session key not available. Re-login and try again.")
            return
        enc_priv_bytes = bytes(enc_priv) if isinstance(enc_priv, bytearray) else enc_priv
        try:
            ok, msg, _ = self.api.export_user_backup_encrypted(
                int(self.session["user_id"]), enc_priv_bytes, out_path, key_or_pass, mode
            )
            if not ok:
                messagebox.showerror("Backup export failed", msg)
                return
            uid = int(self.session["user_id"])
            settings = self.api.get_backup_settings(uid)
            if settings.get("backup_on_change_enabled"):
                self.api.set_auto_backup_key_for_session(uid, key_or_pass, mode)
            self.backup_recovery_key_var.set("")
            self._set_status("Encrypted backup created")
            self.refresh_backup_page()
            messagebox.showinfo("Backup", f"Encrypted backup saved.\n\n{out_path}")
        except Exception as e:
            self.logger.error("Recovery backup export: %s", e, exc_info=True)
            messagebox.showerror("Backup export failed", str(e))

    def _import_backup_file(self):
        if not self.session:
            return messagebox.showwarning("Backup", "Login first.")

        path = (self.backup_import_path_var.get() or "").strip()
        if not path:
            return messagebox.showwarning("Backup", "Choose a backup file first.")
        if not Path(path).exists():
            return messagebox.showerror("Backup", "Backup file not found.")

        passphrase = (self.backup_import_pass_var.get() or "").strip()
        if not passphrase:
            return messagebox.showwarning("Backup", "Type the password or key you used when you made this backup.")

        backup_obj = None
        try:
            with open(path, "r", encoding="utf-8") as f:
                backup_obj = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            # Binary or non-JSON file (e.g. .enc): treat as recovery-format backup; API will read from path
            backup_obj = None
        except Exception as e:
            return messagebox.showerror("Backup", f"Could not read backup file: {e}")

        cert = self._get_active_encryption_cert()
        if not cert:
            return messagebox.showerror("Backup", "No active encryption certificate available.")

        # Support both formats: passphrase export (sv_backup_v2) and recovery backup (sv_backup_recovery_v1)
        # If file could not be loaded as JSON (e.g. .enc), assume recovery format and pass path to API
        is_recovery_format = backup_obj is None or (
            backup_obj.get("format_version") == "sv_backup_recovery_v1"
            or (backup_obj.get("key_verifier") is not None and backup_obj.get("encryption") is not None)
        )
        try:
            if is_recovery_format:
                ok, result = self.api.import_recovery_backup(
                    self.session["user_id"], path, passphrase, cert
                )
            else:
                ok, result = self.api.import_vault_backup(self.session["user_id"], cert, backup_obj, passphrase)
        except Exception as e:
            error_msg = f"Backup import error: {str(e)}"
            self.logger.error("Backup import exception: %s", e, exc_info=True)
            return messagebox.showerror("Backup import failed", error_msg)
        
        if not ok:
            # FIXED: Handle result that might be a list or dict
            if isinstance(result, dict):
                error_msg = result.get("error") or result.get("message") or "Import failed"
            elif isinstance(result, (list, tuple)):
                error_msg = f"Import failed: {result[0] if result else 'Unknown error'}"
            else:
                error_msg = f"Import failed: {str(result)}"
            self.logger.error("Backup import failed: %s", error_msg)
            return messagebox.showerror("Backup import failed", error_msg)

        # FIXED: Ensure result is a dict before accessing keys
        if not isinstance(result, dict):
            self.logger.error("Backup import returned unexpected type: %s", type(result).__name__)
            return messagebox.showerror("Backup import failed", "Unexpected result format: " + type(result).__name__)

        added = int(result.get("added", result.get("imported", 0)) or 0)
        skipped = int(result.get("skipped", 0) or 0)
        failed = int(result.get("failed", 0) or 0)

        self.backup_import_pass_var.set("")
        self._set_status(f"Backup imported: {added} added, {skipped} skipped, {failed} failed")
        self.refresh_vault_table()
        self.refresh_dashboard(force_health=True)
        self.refresh_backup_page()

        detail = f"Added: {added}\nSkipped: {skipped}\nFailed: {failed}"
        errs = result.get("errors") or result.get("messages") or []
        if errs:
            preview = "\n".join(f"• {e}" for e in errs[:8])
            detail += f"\n\nWarnings:\n{preview}"
            if len(errs) > 8:
                detail += f"\n• ... and {len(errs) - 8} more"
        messagebox.showinfo("Backup import complete", detail)

    def refresh_backup_page(self):
        if not hasattr(self, "backup_events_box"):
            return

        self.backup_events_box.configure(state="normal")
        self.backup_events_box.delete("1.0", "end")

        if not self.session:
            self.backup_events_box.insert("end", "Login to view backup activity.")
            self.backup_events_box.configure(state="disabled")
            if hasattr(self, "backup_recovery_status_var"):
                self.backup_recovery_status_var.set("Login to view.")
            return

        # Backup recovery status (Phase 1)
        if hasattr(self, "backup_recovery_status_var"):
            try:
                status = self.api.get_backup_recovery_status(int(self.session["user_id"]))
                if status.get("enabled"):
                    mode = status.get("mode") or "recovery_key"
                    self.backup_recovery_status_var.set(f"Backup recovery: Enabled ({mode})")
                else:
                    self.backup_recovery_status_var.set("Backup recovery: Not enabled")
            except Exception:
                self.backup_recovery_status_var.set("Backup recovery: —")
        # Credentials cached status
        if hasattr(self, "backup_cred_status_var"):
            try:
                bs = self.api.get_backup_status(int(self.session["user_id"]))
                if bs.get("credentials_cached_for_session"):
                    self.backup_cred_status_var.set("✓ Credentials saved for this session")
                else:
                    self.backup_cred_status_var.set("")
            except Exception:
                self.backup_cred_status_var.set("")
        # Phase 2: status, list, settings
        if hasattr(self, "backup_phase2_status_var"):
            try:
                bs = self.api.get_backup_status(int(self.session["user_id"]))
                parts = []
                if bs.get("last_backup_at"):
                    parts.append(f"Last backup: {bs['last_backup_at']}")
                if bs.get("next_scheduled_due"):
                    parts.append(f"Next due: {bs['next_scheduled_due']}")
                parts.append(f"Local backups: {bs.get('local_backup_count', 0)}")
                self.backup_phase2_status_var.set("  |  ".join(parts) if parts else "No backups yet.")
            except Exception:
                self.backup_phase2_status_var.set("")
        if hasattr(self, "backup_listbox"):
            try:
                self.backup_listbox.delete(0, "end")
                for b in self.api.list_local_backups(int(self.session["user_id"])):
                    line = f"{b.get('created_at', '')}  {b.get('filename', '')}  ({b.get('size', 0)} B)"
                    self.backup_listbox.insert("end", line)
            except Exception:
                pass
        if hasattr(self, "backup_keep_n_var"):
            try:
                s = self.api.get_backup_settings(int(self.session["user_id"]))
                self.backup_keep_n_var.set(str(s.get("keep_last_n_backups", 10)))
                if hasattr(self, "backup_auto_var"):
                    self.backup_auto_var.set(bool(s.get("backup_auto_enabled", False)))
                if hasattr(self, "backup_on_change_var"):
                    self.backup_on_change_var.set(bool(s.get("backup_on_change_enabled", False)))
                if hasattr(self, "backup_schedule_hours_var"):
                    self.backup_schedule_hours_var.set(str(s.get("schedule_interval_hours", 24)))
                if hasattr(self, "backup_stale_days_var"):
                    self.backup_stale_days_var.set(str(s.get("stale_warning_days", 7)))
                if hasattr(self, "backup_on_change_debounce_var"):
                    self.backup_on_change_debounce_var.set(str(s.get("on_change_debounce_seconds", 60)))
            except Exception:
                pass
        if hasattr(self, "backup_folder_path_var"):
            try:
                path = self.api.get_backup_folder_path(int(self.session["user_id"]))
                self.backup_folder_path_var.set(path or "")
            except Exception:
                self.backup_folder_path_var.set("")
        if hasattr(self, "backup_health_summary_var"):
            try:
                bs = self.api.get_backup_status(int(self.session["user_id"]))
                lines = []
                lines.append("Recovery configured: " + ("Yes (" + (bs.get("mode") or "recovery_key") + ")" if bs.get("recovery_configured") else "No"))
                lines.append("Scheduled backup: " + ("Yes" if bs.get("backup_auto_enabled") else "No") + "  |  Backup on change: " + ("Yes" if bs.get("backup_on_change_enabled") else "No"))
                if bs.get("last_backup_at"):
                    age = bs.get("last_backup_age_days")
                    if age is not None and age >= 0:
                        if age < 1:
                            lines.append("Last backup: " + str(bs["last_backup_at"]) + " (today)")
                        else:
                            lines.append("Last backup: " + str(bs["last_backup_at"]) + " (" + str(int(age)) + " days ago)")
                    else:
                        lines.append("Last backup: " + str(bs["last_backup_at"]))
                else:
                    lines.append("Last backup: Never")
                if bs.get("next_scheduled_due"):
                    lines.append("Next scheduled: " + str(bs["next_scheduled_due"]))
                lines.append("Local backups retained: " + str(bs.get("local_backup_count", 0)) + "  (keep last " + str(bs.get("keep_last_n_backups", 10)) + ")")
                val = bs.get("latest_validation_ok")
                if val is True:
                    lines.append("Latest validation: Valid")
                elif val is False:
                    lines.append("Latest validation: Error (validation failed)")
                else:
                    lines.append("Latest validation: Not validated yet")
                if bs.get("staleness_warning"):
                    lines.append("⚠ " + bs["staleness_warning"])
                lines.append("— " + (bs.get("restore_readiness") or ""))
                self.backup_health_summary_var.set("\n".join(lines))
            except Exception:
                self.backup_health_summary_var.set("Unable to load health status.")

        # FIXED: Proper database connection handling with context manager
        try:
            conn = self.api.db.get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT event_type, summary, created_at
                    FROM backup_events
                    WHERE user_id = ?
                    ORDER BY id DESC
                    LIMIT 30
                    """,
                    (int(self.session["user_id"]),),
                )
                rows = cursor.fetchall()
            finally:
                conn.close()
        except Exception as e:
            self.logger.error("Error loading backup events: %s", e)
            rows = []

        if not rows:
            self.backup_events_box.insert("end", "No backup events yet.")
        else:
            for r in rows:
                when = str(r["created_at"] or "")
                event_type = str(r["event_type"] or "").upper()
                try:
                    meta = json.loads(r["summary"] or "{}")
                except Exception:
                    meta = {"raw": str(r["summary"])}
                pairs = []
                for k in ("entries", "added", "imported", "skipped", "failed", "format"):
                    if k in meta:
                        pairs.append(f"{k}={meta[k]}")
                self.backup_events_box.insert("end", f"[{when}] {event_type}")
                if pairs:
                    self.backup_events_box.insert("end", "  " + ", ".join(pairs))
                self.backup_events_box.insert("end", "\n")

        self.backup_events_box.configure(state="disabled")

    # ---------------------- activity log ----------------------
    def _build_activity_log_page(self):
        page = ttk.Frame(self.content)
        page.columnconfigure(0, weight=1)
        page.rowconfigure(0, weight=0)
        page.rowconfigure(1, weight=0)
        page.rowconfigure(2, weight=0)
        page.rowconfigure(3, weight=0)
        page.rowconfigure(4, weight=1)
        page.rowconfigure(5, weight=0, minsize=140)

        ttk.Label(page, text="Activity Log", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            page,
            text="Recent security and app activity. Use search and filters to find entries.",
            style="Sub.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(0, 12))

        # Recent Security Alerts: themed card (panel bg, border) to match dark theme
        recent_alerts_frame = ttk.LabelFrame(page, text="Recent Security Alerts (last 5)", padding=10)
        recent_alerts_frame.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        recent_alerts_frame.columnconfigure(0, weight=1)
        recent_alerts_frame.rowconfigure(0, weight=0)
        alerts_inner = ttk.Frame(recent_alerts_frame, style="Panel.TFrame")
        alerts_inner.grid(row=0, column=0, sticky="nsew")
        alerts_inner.columnconfigure(0, weight=1)
        self.recent_alerts_listbox = tk.Listbox(
            alerts_inner,
            height=5,
            font=self.font_base,
            bg=self.palette.get("input_bg", self.palette["panel"]),
            fg=self.palette["text"],
            selectbackground=self.palette.get("accent", "#58a6ff"),
            selectforeground=self.palette.get("accent_fg", "#ffffff"),
            selectmode="single",
            activestyle="none",
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            highlightcolor=self.palette["border"],
        )
        recent_alerts_sb = ttk.Scrollbar(alerts_inner, orient="vertical", command=self.recent_alerts_listbox.yview)
        self.recent_alerts_listbox.configure(yscrollcommand=recent_alerts_sb.set)
        self.recent_alerts_listbox.grid(row=0, column=0, sticky="nsew")
        recent_alerts_sb.grid(row=0, column=1, sticky="ns")
        ttk.Button(
            recent_alerts_frame,
            text="View full log below",
            style="Secondary.TButton",
            command=self._scroll_activity_log_to_table,
        ).grid(row=1, column=0, sticky="w", pady=(8, 0))

        # Toolbar: two rows — filters on row 0, action buttons grouped on row 1
        toolbar = ttk.Frame(page)
        toolbar.grid(row=3, column=0, sticky="ew", pady=(0, 10))
        toolbar.columnconfigure(0, weight=0)
        self.audit_search_var = tk.StringVar()
        self.audit_search_var.trace_add("write", lambda *a: self._refresh_activity_log())
        col = 0
        ttk.Label(toolbar, text="Search:", style="ActivityLog.TLabel").grid(row=0, column=col, sticky="w", padx=(0, 6))
        col += 1
        search_entry = self._make_entry(toolbar, self.audit_search_var)
        search_entry.config(width=22, font=self.font_base)
        search_entry.grid(row=0, column=col, sticky="w", padx=(0, 16))
        col += 1
        ttk.Label(toolbar, text="Category:", style="ActivityLog.TLabel").grid(row=0, column=col, sticky="w", padx=(0, 4))
        col += 1
        self.audit_category_var = tk.StringVar(value="All")
        _cat_opts = ["All", "Session", "Security", "Vault", "Backup", "Restore", "Extension", "API", "Settings", "System"]
        _cat_frame = tk.Frame(toolbar, bg=self.palette["bg"])
        _cat_frame.grid(row=0, column=col, sticky="w", padx=(0, 12))
        _cat_btn = tk.Button(
            _cat_frame,
            textvariable=self.audit_category_var,
            command=lambda: self._show_themed_dropdown(
                _cat_btn, _cat_opts, self.audit_category_var.get(),
                lambda v: (self.audit_category_var.set(v), self._refresh_activity_log()),
                min_width=140,
            ),
            font=self.font_base,
            bg=self.palette.get("card_soft", self.palette["panel"]),
            fg=self.palette["text"],
            activebackground=self.palette.get("accent_active", self.palette["accent"]),
            activeforeground=self.palette.get("accent_fg", "white"),
            relief="solid",
            borderwidth=1,
            highlightthickness=0,
            width=10,
            anchor="w",
            padx=6,
            pady=4,
        )
        _cat_btn.pack()
        col += 1
        ttk.Label(toolbar, text="Status:", style="ActivityLog.TLabel").grid(row=0, column=col, sticky="w", padx=(0, 4))
        col += 1
        self.audit_status_var = tk.StringVar(value="All")
        _status_opts = ["All", "Success", "Warning", "Failed", "Info"]
        _status_frame = tk.Frame(toolbar, bg=self.palette["bg"])
        _status_frame.grid(row=0, column=col, sticky="w", padx=(0, 12))
        _status_btn = tk.Button(
            _status_frame,
            textvariable=self.audit_status_var,
            command=lambda: self._show_themed_dropdown(
                _status_btn, _status_opts, self.audit_status_var.get(),
                lambda v: (self.audit_status_var.set(v), self._refresh_activity_log()),
                min_width=120,
            ),
            font=self.font_base,
            bg=self.palette.get("card_soft", self.palette["panel"]),
            fg=self.palette["text"],
            activebackground=self.palette.get("accent_active", self.palette["accent"]),
            activeforeground=self.palette.get("accent_fg", "white"),
            relief="solid",
            borderwidth=1,
            highlightthickness=0,
            width=10,
            anchor="w",
            padx=6,
            pady=4,
        )
        _status_btn.pack()
        col += 1
        ttk.Label(toolbar, text="Date:", style="ActivityLog.TLabel").grid(row=0, column=col, sticky="w", padx=(0, 4))
        col += 1
        self.audit_date_var = tk.StringVar(value="All")
        _date_opts = ["All", "Today", "Last 7 days", "Last 30 days"]
        _date_frame = tk.Frame(toolbar, bg=self.palette["bg"])
        _date_frame.grid(row=0, column=col, sticky="w", padx=(0, 12))
        _date_btn = tk.Button(
            _date_frame,
            textvariable=self.audit_date_var,
            command=lambda: self._show_themed_dropdown(
                _date_btn, _date_opts, self.audit_date_var.get(),
                lambda v: (self.audit_date_var.set(v), self._refresh_activity_log()),
                min_width=140,
            ),
            font=self.font_base,
            bg=self.palette.get("card_soft", self.palette["panel"]),
            fg=self.palette["text"],
            activebackground=self.palette.get("accent_active", self.palette["accent"]),
            activeforeground=self.palette.get("accent_fg", "white"),
            relief="solid",
            borderwidth=1,
            highlightthickness=0,
            width=12,
            anchor="w",
            padx=6,
            pady=4,
        )
        _date_btn.pack()
        col += 1
        ttk.Label(toolbar, text="Sort:", style="ActivityLog.TLabel").grid(row=0, column=col, sticky="w", padx=(0, 4))
        col += 1
        self.audit_sort_var = tk.StringVar(value="Time")
        _sort_opts = ["Time", "Category", "Status", "Action"]
        _sort_frame = tk.Frame(toolbar, bg=self.palette["bg"])
        _sort_frame.grid(row=0, column=col, sticky="w", padx=(0, 8))
        _sort_btn = tk.Button(
            _sort_frame,
            textvariable=self.audit_sort_var,
            command=lambda: self._show_themed_dropdown(
                _sort_btn, _sort_opts, self.audit_sort_var.get(),
                lambda v: (self.audit_sort_var.set(v), self._refresh_activity_log()),
                min_width=100,
            ),
            font=self.font_base,
            bg=self.palette.get("card_soft", self.palette["panel"]),
            fg=self.palette["text"],
            activebackground=self.palette.get("accent_active", self.palette["accent"]),
            activeforeground=self.palette.get("accent_fg", "white"),
            relief="solid",
            borderwidth=1,
            highlightthickness=0,
            width=8,
            anchor="w",
            padx=6,
            pady=4,
        )
        _sort_btn.pack()
        col += 1
        self.audit_sort_desc_var = tk.BooleanVar(value=True)
        self._make_checkbutton(
            toolbar,
            "Newest first",
            self.audit_sort_desc_var,
            background=self.palette["bg"],
            command=self._refresh_activity_log,
        ).grid(row=0, column=col, sticky="w", padx=(0, 12))
        col += 1
        self.audit_include_system_var = tk.BooleanVar(value=False)
        self._make_checkbutton(
            toolbar,
            "Include system events",
            self.audit_include_system_var,
            background=self.palette["bg"],
            command=self._refresh_activity_log,
        ).grid(row=0, column=col, sticky="w", padx=(0, 12))
        col += 1
        toolbar.columnconfigure(col, weight=1)
        # Action buttons grouped in one frame so they stay together (no large gaps)
        toolbar_btns = ttk.Frame(toolbar)
        toolbar_btns.grid(row=1, column=0, columnspan=col + 1, sticky="w", pady=(8, 0))
        ttk.Button(toolbar_btns, text="Refresh", command=self._refresh_activity_log, style="Secondary.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(toolbar_btns, text="Clear filters", command=self._clear_activity_log_filters, style="Secondary.TButton").pack(side="left", padx=(0, 6))
        ttk.Button(toolbar_btns, text="Export visible", command=self._export_activity_log_visible, style="Secondary.TButton").pack(side="left")

        table_wrap = ttk.Frame(page)
        table_wrap.grid(row=4, column=0, sticky="nsew")
        table_wrap.columnconfigure(0, weight=1)
        table_wrap.rowconfigure(0, weight=1)
        cols = ("time", "category", "action", "status", "message")
        self.audit_log_table = ttk.Treeview(
            table_wrap,
            columns=cols,
            show="headings",
            selectmode="browse",
            height=16,
        )
        # Column widths and minwidth so headers (Time, Category, Action, Status, Message) are never truncated
        for c, w, mw in [("time", 180, 70), ("category", 100, 80), ("action", 100, 80), ("status", 90, 70), ("message", 480, 150)]:
            self.audit_log_table.heading(c, text=c.title())
            self.audit_log_table.column(c, width=w, minwidth=mw, anchor="w")
        self.audit_log_table.tag_configure("odd", background=self.palette["panel"], foreground=self.palette["text"])
        self.audit_log_table.tag_configure("even", background=self.palette.get("table_row_alt", self.palette["panel"]), foreground=self.palette["text"])
        self.audit_log_table.tag_configure("empty", background=self.palette["panel"], foreground=self.palette["muted"])
        y_sb = ttk.Scrollbar(table_wrap, orient="vertical", command=self.audit_log_table.yview)
        x_sb = ttk.Scrollbar(table_wrap, orient="horizontal", command=self.audit_log_table.xview)
        self.audit_log_table.configure(yscrollcommand=y_sb.set, xscrollcommand=x_sb.set)
        self.audit_log_table.grid(row=0, column=0, sticky="nsew")
        y_sb.grid(row=0, column=1, sticky="ns")
        x_sb.grid(row=1, column=0, sticky="ew")
        self.audit_log_table.bind("<<TreeviewSelect>>", self._on_select_activity_log_row)

        details_frame = ttk.LabelFrame(page, text="Details", padding=10)
        details_frame.grid(row=5, column=0, sticky="nsew", pady=(12, 0))
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)
        self.audit_details_text = tk.Text(
            details_frame,
            height=6,
            wrap="word",
            bg=self.palette.get("input_bg", self.palette["panel"]),
            fg=self.palette["text"],
            font=self.font_base,
            state="disabled",
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.palette["border"],
            padx=8,
            pady=6,
        )
        self.audit_details_text.grid(row=0, column=0, sticky="nsew")

        self.audit_log_data = []
        self.root.after(200, self._refresh_activity_log)
        return page

    def _scroll_activity_log_to_table(self):
        """Scroll the Activity Log main table into view and focus it."""
        if hasattr(self, "audit_log_table") and self.audit_log_table.winfo_exists():
            self.audit_log_table.focus_set()
            try:
                self.audit_log_table.yview_moveto(0.0)
            except Exception:
                pass

    def _clear_activity_log_filters(self):
        self.audit_search_var.set("")
        self.audit_category_var.set("All")
        self.audit_status_var.set("All")
        self.audit_date_var.set("All")
        self.audit_sort_var.set("Time")
        self.audit_sort_desc_var.set(True)
        if getattr(self, "audit_include_system_var", None):
            self.audit_include_system_var.set(False)
        self._refresh_activity_log()

    def _get_activity_log_date_range(self):
        date_val = self.audit_date_var.get() or "All"
        if date_val == "All":
            return None, None
        now = datetime.datetime.utcnow()
        if date_val == "Today":
            start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            return start.strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y-%m-%d %H:%M:%S")
        if date_val == "Last 7 days":
            start = now - datetime.timedelta(days=7)
            return start.strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y-%m-%d %H:%M:%S")
        if date_val == "Last 30 days":
            start = now - datetime.timedelta(days=30)
            return start.strftime("%Y-%m-%d %H:%M:%S"), now.strftime("%Y-%m-%d %H:%M:%S")
        return None, None

    def _refresh_activity_log(self):
        if not getattr(self, "audit_log_table", None):
            return
        for iid in self.audit_log_table.get_children():
            self.audit_log_table.delete(iid)
        self.audit_details_text.configure(state="normal")
        self.audit_details_text.delete("1.0", "end")
        self.audit_details_text.configure(state="disabled")
        self.audit_log_data = []
        try:
            since_ts, until_ts = self._get_activity_log_date_range()
            sort_by = self.audit_sort_var.get() or "Time"
            sort_map = {"Time": "created_at", "Category": "category", "Status": "status", "Action": "action"}
            sort_key = sort_map.get(sort_by, "created_at")
            current_user_id = int(self.session["user_id"]) if self.session and self.session.get("user_id") else None
            rows = self.api.list_audit_logs(
                limit=500,
                since_ts=since_ts,
                until_ts=until_ts,
                category=self.audit_category_var.get() if self.audit_category_var.get() != "All" else None,
                status=self.audit_status_var.get() if self.audit_status_var.get() != "All" else None,
                search=self.audit_search_var.get().strip() or None,
                sort_by=sort_key,
                sort_desc=self.audit_sort_desc_var.get(),
                user_id=current_user_id,
                include_system=bool(getattr(self, "audit_include_system_var", None) and self.audit_include_system_var.get()),
            )
            self.audit_log_data = rows
            if getattr(self, "recent_alerts_listbox", None):
                try:
                    self.recent_alerts_listbox.delete(0, tk.END)
                    for r in rows[:5]:
                        ts = (r.get("timestamp") or "—")[:19]
                        st = (r.get("status") or "—")[:10]
                        msg = (r.get("message") or "—")[:60]
                        self.recent_alerts_listbox.insert(tk.END, f"  {ts}  |  {st}  |  {msg}")
                except Exception:
                    pass
            if not rows:
                self.audit_log_table.insert("", "end", values=("—", "—", "—", "—", "No matching log entries."), tags=("empty",))
            else:
                for i, r in enumerate(rows):
                    tag = "even" if i % 2 == 0 else "odd"
                    self.audit_log_table.insert(
                        "",
                        "end",
                        iid=str(i),
                        values=(
                            r.get("timestamp", "—"),
                            r.get("category", "—"),
                            r.get("action", "—"),
                            r.get("status", "—"),
                            (r.get("message") or "—")[:200],
                        ),
                        tags=(tag,),
                    )
        except Exception as e:
            self.logger.debug("Activity log refresh: %s", e)
            self.audit_log_table.insert("", "end", values=("—", "—", "—", "—", "Could not load logs."), tags=("empty",))

    def _on_select_activity_log_row(self, _event=None):
        if not getattr(self, "audit_details_text", None):
            return
        sel = self.audit_log_table.selection()
        self.audit_details_text.configure(state="normal")
        self.audit_details_text.delete("1.0", "end")
        if not sel:
            self.audit_details_text.configure(state="disabled")
            return
        iid = sel[0]
        try:
            idx = int(iid)
            row = self.audit_log_data[idx] if 0 <= idx < len(self.audit_log_data) else None
        except (ValueError, TypeError):
            row = None
        if not row:
            self.audit_details_text.configure(state="disabled")
            return
        details_safe = row.get("details_safe") or {}
        context_lines = []
        for k in sorted(details_safe.keys()):
            v = details_safe[k]
            if isinstance(v, (dict, list)):
                context_lines.append(f"{k}: {json.dumps(v)}")
            else:
                context_lines.append(f"{k}: {v}")
        context_block = "\n".join(context_lines) if context_lines else "—"
        lines = [
            f"Time: {row.get('timestamp', '—')}",
            f"Category: {row.get('category', '—')}",
            f"Action: {row.get('action', '—')}",
            f"Status: {row.get('status', '—')}",
            f"Message: {row.get('message', '—')}",
            f"Event code: {row.get('event_code', '—')}",
            f"Source: {row.get('source', '—')}",
            "",
            "Context:",
            context_block,
        ]
        self.audit_details_text.insert("1.0", "\n".join(lines))
        self.audit_details_text.configure(state="disabled")

    def _export_activity_log_visible(self):
        if not self.audit_log_data:
            messagebox.showinfo("Export", "No log entries to export.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("Text files", "*.txt"), ("All files", "*.*")],
            title="Export activity log",
        )
        if not path:
            return
        try:
            header = ["Time", "Category", "Action", "Status", "Message", "Event code", "Source"]
            with open(path, "w", encoding="utf-8", newline="") as f:
                if path.lower().endswith(".csv"):
                    import csv as csv_module
                    w = csv_module.writer(f)
                    f.write("# Secure Vault Activity Log\n")
                    w.writerow(header)
                    for r in self.audit_log_data:
                        w.writerow([
                            r.get("timestamp", ""),
                            r.get("category", ""),
                            r.get("action", ""),
                            r.get("status", ""),
                            (r.get("message") or "").replace("\n", " "),
                            r.get("event_code", ""),
                            r.get("source", ""),
                        ])
                else:
                    f.write("\t".join(header) + "\n")
                    for r in self.audit_log_data:
                        f.write(f"{r.get('timestamp', '')}\t{r.get('category', '')}\t{r.get('action', '')}\t{r.get('status', '')}\t{(r.get('message') or '').replace(chr(10), ' ')}\t{r.get('event_code', '')}\t{r.get('source', '')}\n")
            messagebox.showinfo("Export", f"Exported {len(self.audit_log_data)} entries to {path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    # ---------------------- command palette ----------------------
    def _open_command_palette(self, _event=None):
        if getattr(self, "_palette_window", None) and self._palette_window.winfo_exists():
            self._palette_window.focus_force()
            return "break"

        actions = [
            ("Open Dashboard", lambda: self.show_page("dashboard")),
            ("Open Vault", lambda: self.show_page("vault")),
            ("Open Import", lambda: self.show_page("import")),
            ("Open Backup", lambda: self.show_page("backup")),
            ("Open Activity Log", lambda: self.show_page("activity_log")),
            ("Open Sync", lambda: self.show_page("sync")),
            ("Open Extension", lambda: self.show_page("extension")),
            ("Refresh Vault", self.refresh_vault_table),
            ("Refresh Dashboard", lambda: self.refresh_dashboard(force_health=True)),
            ("Lock app", self._do_manual_lock),
            ("Logout", self._logout),
        ]

        self._palette_actions = actions
        self._palette_filtered = list(range(len(actions)))

        width = 560
        height = 360
        x = self.root.winfo_rootx() + max(20, (self.root.winfo_width() - width) // 2)
        y = self.root.winfo_rooty() + 72

        win = tk.Toplevel(self.root)
        self._palette_window = win
        win.title("Command Palette")
        win.geometry(f"{width}x{height}+{x}+{y}")
        win.transient(self.root)
        win.configure(bg=self.palette["bg"])
        win.resizable(False, False)
        win.grab_set()

        card = ttk.Frame(win, style="Panel.TFrame", padding=12)
        card.pack(fill="both", expand=True, padx=12, pady=12)

        ttk.Label(card, text="Quick Actions", style="Header.TLabel").pack(anchor="w")
        ttk.Label(card, text="Type to filter, press Enter to run", style="Sub.TLabel").pack(anchor="w", pady=(2, 8))

        query = tk.StringVar()
        entry = self._make_entry(card, query)
        entry.pack(fill="x")

        results = tk.Listbox(
            card,
            activestyle="none",
            relief="flat",
            bg=self.palette["panel"],
            fg=self.palette["text"],
            font=self.font_base,
            borderwidth=0,
            highlightthickness=0,
            selectmode="browse",
            selectbackground=self.palette["accent_soft"],
            selectforeground=self.palette["text"],
        )
        results.pack(fill="both", expand=True, pady=(8, 0))

        def _refill(*_args):
            q = (query.get() or "").strip().lower()
            self._palette_filtered = []
            results.delete(0, "end")
            for i, (name, _fn) in enumerate(self._palette_actions):
                if (not q) or (q in name.lower()):
                    self._palette_filtered.append(i)
                    results.insert("end", name)
            if results.size() > 0:
                results.selection_clear(0, "end")
                results.selection_set(0)
                results.activate(0)

        def _run_selected(_evt=None):
            if results.size() == 0:
                return "break"
            pos = results.curselection()[0] if results.curselection() else 0
            action_idx = self._palette_filtered[pos]
            name, fn = self._palette_actions[action_idx]
            try:
                fn()
                self._set_status(f"Action executed: {name}")
            finally:
                try:
                    win.grab_release()
                except Exception:
                    pass
                win.destroy()
            return "break"

        query.trace_add("write", _refill)
        entry.bind("<Return>", _run_selected)
        results.bind("<Double-Button-1>", _run_selected)
        results.bind("<Return>", _run_selected)
        win.bind("<Escape>", lambda _e: (win.grab_release(), win.destroy(), "break"))

        _refill()
        entry.focus_set()
        return "break"

    # ---------------------- sync ----------------------
    def _build_sync_page(self):
        page = ttk.Frame(self.content)
        ttk.Label(page, text="Sync setup", style="Title.TLabel").pack(anchor="w")
        ttk.Label(page, text="Zero-cost sync using Syncthing", style="Sub.TLabel").pack(anchor="w", pady=(0, 10))

        self.sync_folder_var = tk.StringVar()

        row = ttk.Frame(page)
        row.pack(fill="x", pady=(0, 8))
        self.sync_entry = self._make_entry(row, self.sync_folder_var)
        self.sync_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row, text="Choose folder", command=self._pick_sync_folder).pack(side="left")
        ttk.Button(row, text="Save", command=self._save_sync_folder).pack(side="left", padx=(8, 0))

        row2 = ttk.Frame(page)
        row2.pack(fill="x", pady=(0, 8))
        ttk.Button(row2, text="Check Syncthing", command=self.refresh_sync_page).pack(side="left")
        ttk.Button(row2, text="Launch Syncthing", command=self._launch_syncthing).pack(side="left", padx=8)

        self.sync_status = ttk.Label(page, text="", style="Sub.TLabel")
        self.sync_status.pack(anchor="w", pady=(0, 8))

        info_wrap = ttk.Frame(page, style="Panel.TFrame", padding=10)
        info_wrap.pack(fill="both", expand=True)

        self.sync_steps = tk.Text(
            info_wrap,
            wrap="word",
            bg=self.palette.get("input_bg", self.palette["panel"]),
            fg=self.palette["text"],
            font=self.font_small
        )
        y = ttk.Scrollbar(info_wrap, orient="vertical", command=self.sync_steps.yview)
        self.sync_steps.configure(yscrollcommand=y.set)

        self.sync_steps.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        info_wrap.rowconfigure(0, weight=1)
        info_wrap.columnconfigure(0, weight=1)
        return page

    def _pick_sync_folder(self):
        folder = filedialog.askdirectory(title="Choose sync folder")
        if folder:
            self.sync_folder_var.set(folder)

    def _save_sync_folder(self):
        folder = self.sync_folder_var.get().strip()
        if not folder:
            return messagebox.showwarning("Sync", "Select a folder.")
        saved = self.sync_service.set_sync_folder(folder)
        self._set_status(f"Sync folder saved: {saved}")
        messagebox.showinfo("Sync", f"Sync folder set:\n{saved}")

    def _launch_syncthing(self):
        ok, msg = self.sync_service.launch_syncthing()
        if ok:
            messagebox.showinfo("Syncthing", msg)
            self._set_status(msg)
        else:
            messagebox.showwarning("Syncthing", msg)
        self.refresh_sync_page()

    def refresh_sync_page(self):
        self.sync_folder_var.set(self.sync_service.get_sync_folder())
        installed = self.sync_service.is_syncthing_installed()
        running = self.sync_service.is_syncthing_running()

        self.sync_status.configure(text=f"Installed: {'Yes' if installed else 'No'}   Running: {'Yes' if running else 'No'}")

        self.sync_steps.delete("1.0", "end")
        for i, step in enumerate(self.sync_service.setup_steps(), start=1):
            self.sync_steps.insert("end", f"{i}. {step}\n")

    # ---------------------- extension ----------------------
    def _build_extension_page(self):
        page = ttk.Frame(self.content)
        ttk.Label(page, text="Browser Extension Token", style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            page,
            text="Manage your browser extension token. Regenerating the token will disconnect all extensions using the current token.",
            style="Sub.TLabel",
        ).pack(anchor="w", pady=(0, 16))

        # Token display and management
        token_frame = ttk.Frame(page, style="Panel.TFrame", padding=16)
        token_frame.pack(fill="x", pady=(0, 16))
        
        ttk.Label(token_frame, text="Current Token", style="Sub.TLabel").pack(anchor="w", pady=(0, 8))
        self.token_var = tk.StringVar(value=self.extension_server.token)
        token_row = ttk.Frame(token_frame)
        token_row.pack(fill="x", pady=(0, 12))
        self.token_entry = self._make_entry(token_row, self.token_var)
        self.token_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(token_row, text="Copy Token", command=self._copy_token, style="Secondary.TButton").pack(side="left", padx=(0, 8))
        ttk.Button(token_row, text="Regenerate Token", command=self._regenerate_token, style="Accent.TButton").pack(side="left")

        # Token usage information
        usage_frame = ttk.Frame(page, style="Panel.TFrame", padding=16)
        usage_frame.pack(fill="x", pady=(0, 16))
        
        ttk.Label(usage_frame, text="Token Usage Information", style="Sub.TLabel").pack(anchor="w", pady=(0, 8))
        self.token_usage_label = ttk.Label(
            usage_frame,
            text="No usage data available. Token will be tracked when extension makes requests.",
            style="Sub.TLabel",
            foreground=self.palette.get("muted", "#94a3b8")
        )
        self.token_usage_label.pack(anchor="w", pady=(0, 8))
        
        # Refresh usage button
        ttk.Button(usage_frame, text="Refresh Usage Info", command=self._refresh_token_usage, style="Secondary.TButton").pack(anchor="w")
        
        # API control
        api_frame = ttk.Frame(page, style="Panel.TFrame", padding=16)
        api_frame.pack(fill="x", pady=(0, 8))
        
        ttk.Label(api_frame, text="Extension API Server", style="Sub.TLabel").pack(anchor="w", pady=(0, 8))
        api_row = ttk.Frame(api_frame)
        api_row.pack(fill="x")
        ttk.Button(api_row, text="Start API", command=self._start_extension_api).pack(side="left", padx=(0, 8))
        ttk.Button(api_row, text="Stop API", command=self._stop_extension_api, style="Secondary.TButton").pack(side="left")

        self.ext_status = ttk.Label(page, text="", style="Sub.TLabel")
        self.ext_status.pack(anchor="w", pady=(0, 8))
        
        # Refresh usage on page load
        self._refresh_token_usage()

        help_wrap = ttk.Frame(page, style="Panel.TFrame", padding=10)
        help_wrap.pack(fill="both", expand=True)

        self.ext_help = tk.Text(
            help_wrap,
            wrap="word",
            bg=self.palette.get("input_bg", self.palette["panel"]),
            fg=self.palette["text"],
            font=self.font_small
        )
        y = ttk.Scrollbar(help_wrap, orient="vertical", command=self.ext_help.yview)
        self.ext_help.configure(yscrollcommand=y.set)

        self.ext_help.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        help_wrap.rowconfigure(0, weight=1)
        help_wrap.columnconfigure(0, weight=1)

        self.ext_help.insert(
            "end",
            "1) Open browser extensions page and enable Developer Mode.\n"
            "2) Click Load unpacked and choose the browser_extension folder.\n"
            "3) In extension popup set API URL to http://127.0.0.1:5005 and paste token.\n"
            "4) Keep desktop app logged in and API running.\n"
            "5) Visit login page and use extension Autofill.\n",
        )
        self.ext_help.config(state="disabled")

        return page

    def _refresh_token_usage(self):
        """Refresh and display token usage information."""
        usage = self.extension_server.get_token_usage()
        if usage:
            browser = usage.get("browser", "Unknown")
            device = usage.get("device", "Unknown")
            last_used = usage.get("last_used", "")
            
            if last_used:
                try:
                    from datetime import datetime
                    dt = datetime.fromisoformat(last_used.replace('Z', '+00:00'))
                    last_used_str = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    last_used_str = last_used[:19] if len(last_used) > 19 else last_used
            else:
                last_used_str = "Never"
            
            usage_text = f"Browser: {browser}\nDevice: {device}\nLast Used: {last_used_str}"
            self.token_usage_label.configure(text=usage_text, foreground=self.palette.get("text", "#f0f6fc"))
        else:
            self.token_usage_label.configure(
                text="No usage data available. Token will be tracked when extension makes requests.",
                foreground=self.palette.get("muted", "#94a3b8")
            )

    def _regenerate_token(self):
        """Regenerate extension token (disconnects all extensions using current token)."""
        if not messagebox.askyesno(
            "Regenerate Token",
            "Regenerating the token will disconnect all browser extensions using the current token.\n\n"
            "You will need to update the token in all your browser extensions.\n\n"
            "Continue?"
        ):
            return
        
        token = self.extension_server.regenerate_token()
        self.token_var.set(token)
        self._refresh_token_usage()
        self._set_status("Extension token regenerated - all extensions disconnected")
        messagebox.showinfo("Token Regenerated", "New extension token generated.\n\nAll extensions using the old token have been disconnected.\n\nUpdate the token in your browser extensions.")

    def _copy_token(self):
        self._copy_to_clipboard(self.token_var.get(), "Token")

    def _start_extension_api(self):
        ok, msg = self.extension_server.start()
        if ok:
            self.ext_status.configure(text=f"✅ {msg}")
            self._set_status(msg)
            self._show_toast("Extension API started", "success")
        else:
            self.ext_status.configure(text=f"❌ Failed: {msg}")
            self._set_status(f"Extension API failed: {msg}")
            messagebox.showerror("Extension API", f"Failed to start extension API:\n{msg}")

    def _stop_extension_api(self):
        ok, msg = self.extension_server.stop()
        if ok:
            self.ext_status.configure(text=f"❌ {msg}")
            self._set_status(msg)
            self._show_toast("Extension API stopped", "info")
        else:
            self.ext_status.configure(text=f"⚠️ {msg}")
            self._set_status(f"Extension API stop warning: {msg}")

    def refresh_extension_page(self):
        self.token_var.set(self.extension_server.token)
        self._refresh_token_usage()
        is_running = self.extension_server._httpd is not None
        status_text = "Status: RUNNING · Endpoint: http://127.0.0.1:5005" if is_running else "Status: STOPPED"
        self.ext_status.configure(text=status_text)

    # ---------------------- session ----------------------
    def _get_extension_session(self):
        # Return session even when locked - extension requires master phrase for security
        # This allows autofill to work when app is locked (user must still enter passphrase)
        return self.session

    def _export_csv_flow(self):
        if not self.session:
            return messagebox.showwarning("Export", "Login first.")

        # Re-auth gate for export
        if not self._require_step_up_or_phrase("export_vault", "export vault to cleartext CSV"):
            return

        out_path = filedialog.asksaveasfilename(
            title="Save vault as cleartext CSV",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"vault_export_{int(time.time())}.csv",
        )
        if not out_path:
            return

        try:
            # Convert bytearray to bytes for API call
            enc_priv_bytes = bytes(self.session["enc_priv"]) if isinstance(self.session["enc_priv"], bytearray) else self.session["enc_priv"]
            csv_data = self.api.export_secrets_as_csv(self.session["user_id"], enc_priv_bytes)
            if not csv_data:
                return messagebox.showinfo("Export", "Vault is empty.")
                
            with open(out_path, "w", encoding="utf-8", newline="") as f:
                f.write(csv_data)
                
            self._set_status("Vault exported to cleartext CSV")
            messagebox.showinfo("Export Successful", f"Vault saved to cleartext CSV:\n{out_path}\n\nWARNING: This file is unencrypted!")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))
    
    def _export_json_flow(self):
        """Export vault as JSON format."""
        if not self.session:
            return messagebox.showwarning("Export", "Login first.")

        # Re-auth gate for export
        if not self._require_phrase("export vault to cleartext JSON"):
            return

        out_path = filedialog.asksaveasfilename(
            title="Save vault as cleartext JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=f"vault_export_{int(time.time())}.json",
        )
        if not out_path:
            return

        try:
            # Convert bytearray to bytes for API call
            enc_priv_bytes = bytes(self.session["enc_priv"]) if isinstance(self.session["enc_priv"], bytearray) else self.session["enc_priv"]
            json_data = self.api.export_secrets_as_json(self.session["user_id"], enc_priv_bytes)
            if not json_data or json_data == "[]":
                return messagebox.showinfo("Export", "Vault is empty.")
                
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(json_data)
                
            self._set_status("Vault exported to cleartext JSON")
            messagebox.showinfo("Export Successful", f"Vault saved to cleartext JSON:\n{out_path}\n\nWARNING: This file is unencrypted!")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    def _logout(self):
        # CRITICAL SECURITY FIX: Wipe all sensitive data before logout
        self._clear_hard_expiry_check()
        self._full_clear_for_logout()
        self.session_security.on_logout()  # runs clear callbacks (Phase 6.1)
        # Cancel all pending timers/jobs
        self._clear_idle_lock()
        if self._clipboard_clear_job:
            try:
                self.root.after_cancel(self._clipboard_clear_job)
            except Exception:
                pass
            self._clipboard_clear_job = None
        
        # Cancel undo buffer job if exists
        if self._undo_buffer and self._undo_buffer.get("job_id"):
            try:
                self.root.after_cancel(self._undo_buffer["job_id"])
            except Exception:
                pass
            self._undo_buffer = None
        # Cancel backup timer (Phase 2)
        if self._backup_timer:
            try:
                self.root.after_cancel(self._backup_timer)
            except Exception:
                pass
            self._backup_timer = None
        if self._backup_cred_prompt_job:
            try:
                self.root.after_cancel(self._backup_cred_prompt_job)
            except Exception:
                pass
            self._backup_cred_prompt_job = None
        # Sensitive caches already cleared by session_security.on_logout() callback
        if self.session:
            self.session.clear()
        self.session = None
        self.current_user = None
        self._current_session_id = None

        # Clear clipboard
        try:
            self._clear_clipboard_windows()
        except Exception:
            pass
        
        self.extension_server.stop()
        self.session = None
        self.current_user = None
        self.health_cache = {"timestamp": 0.0, "data": None}
        self.health_loading = False
        self.import_rows = []
        self.import_show_passwords = False
        self._clipboard_nonce = None
        self._build_login_view()
        self._set_status("Logged out")


# ---------------------- app bootstrap ----------------------
def _enable_high_dpi():
    if sys.platform.startswith("win"):
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            try:
                ctypes.windll.user32.SetProcessDPIAware()
            except Exception:
                pass


def _apply_scaling(root: tk.Tk):
    try:
        dpi = float(root.winfo_fpixels("1i"))
        scale = max(1.0, min(2.0, dpi / 96.0))
        root.tk.call("tk", "scaling", scale)
    except Exception:
        pass


def _fit_to_screen(root: tk.Tk):
    """Set initial window size and position - DEPRECATED: Use app's _set_auth_window instead"""
    try:
        root.update_idletasks()
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()

        w = min(980, int(sw * 0.72))
        h = min(660, int(sh * 0.76))

        w = max(820, min(w, sw - 40))
        h = max(560, min(h, sh - 60))

        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)

        root.geometry(f"{w}x{h}+{x}+{y}")
        root.minsize(820, 560)
    except Exception:
        # Fallback to safe defaults
        root.geometry("980x660")
    root.minsize(820, 560)


def main():
    """Main entry point for the desktop application."""
    # Enable high DPI awareness for Windows
    _enable_high_dpi()
    
    # Create root window
    root = tk.Tk()
    
    # Set window properties before creating app
    root.title("Secure Vault Desktop")
    
    # Apply DPI scaling
    _apply_scaling(root)
    
    # Set initial size before creating app
    root.update_idletasks()
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    initial_w = min(1600, int(sw * 0.92))
    initial_h = min(1000, int(sh * 0.92))
    initial_x = (sw - initial_w) // 2
    initial_y = (sh - initial_h) // 2
    root.geometry(f"{initial_w}x{initial_h}+{initial_x}+{initial_y}")
    root.minsize(1400, 900)
    root.resizable(True, True)
    
    # Create app instance (this will refine the window geometry)
    app = VaultTkApp(root)
    
    # IMPROVED: Final verification and adjustment
    try:
        root.update_idletasks()
        
        # Verify window is on screen and properly sized
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        x = root.winfo_x()
        y = root.winfo_y()
        w = root.winfo_width()
        h = root.winfo_height()
        
        # If window is off-screen or too small, fix it
        if x < 0 or y < 0 or x + w > sw or y + h > sh or w < 900 or h < 600:
            w = max(900, min(w, sw - 40))
            h = max(600, min(h, sh - 60))
            x = max(0, (sw - w) // 2)
            y = max(0, (sh - h) // 2)
            root.geometry(f"{w}x{h}+{x}+{y}")
        
        # Ensure window is visible and open full screen (maximized)
        root.deiconify()
        try:
            root.state("zoomed")
        except Exception:
            try:
                root.attributes("-zoomed", True)
            except Exception:
                try:
                    sw = root.winfo_screenwidth()
                    sh = root.winfo_screenheight()
                    root.geometry(f"{sw}x{sh}+0+0")
                except Exception:
                    pass
        root.lift()
        root.focus_force()
    except Exception as e:
        # Fallback: center window with large defaults
        root.geometry("1600x1000")
        root.update_idletasks()
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        x = (sw - 1600) // 2
        y = (sh - 1000) // 2
        root.geometry(f"1600x1000+{x}+{y}")
        root.minsize(1400, 900)
        root.resizable(True, True)
    
    # Start main event loop
    root.mainloop()


if __name__ == "__main__":
    main()
