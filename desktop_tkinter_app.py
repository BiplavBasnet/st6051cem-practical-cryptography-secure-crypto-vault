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
            child.destroy()

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
        self._clear_idle_lock()
        self._locked_from_page = getattr(self, "active_nav_key", None) or "dashboard"
        try:
            uid = int(self.session["user_id"]) if self.session else None
            self.security_alert_service.notify_security_alert("session_locked_manual", user_id=uid)
        except Exception:
            pass
        self.session_security.lock_session("manual")
        self.logger.info("Session locked (manual)")
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
        """Switch UI to lock screen; vault content is already hidden by clearing root."""
        if reason == "idle":
            msg = "App locked due to inactivity. Unlock to continue."
        else:
            msg = "App locked."
        self._set_status(msg)
        self._show_toast(msg, "warning")
        self._build_lock_screen(reason=reason)

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
        if getattr(self, "unlock_btn", None):
            try:
                self.unlock_btn.config(state="disabled")
            except Exception:
                pass
        passphrase = (self.unlock_pass.get() or "").strip()
        if not passphrase:
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
        username = self.reg_username.get().strip()
        email = self.reg_email.get().strip()
        login_pass = self.reg_login_pass.get()
        recovery_pass = self.reg_recovery_pass.get()

        ok_lp, msg_lp = self.api.validate_passphrase(login_pass)
        if not ok_lp:
            return messagebox.showerror("Validation", f"Login passphrase: {msg_lp}")
        ok_rp, msg_rp = self.api.validate_passphrase(recovery_pass)
        if not ok_rp:
            return messagebox.showerror("Validation", f"Recovery passphrase: {msg_rp}")
        if login_pass == recovery_pass:
            return messagebox.showerror("Validation", "Recovery passphrase must be different.")

        ok_u, msg_u = CryptoUtils.validate_input(username, "username")
        if not ok_u:
            return messagebox.showerror("Validation", msg_u)

        ok_e, msg_e = CryptoUtils.validate_input(email, "email")
        if not ok_e:
            return messagebox.showerror("Validation", msg_e)

        try:
            api_bundle = {}
            for purpose in ["auth", "signing", "encryption"]:
                priv = CryptoUtils.generate_rsa_key_pair(3072)
                priv_pem = CryptoUtils.serialize_private_key(priv)
                pub_pem = CryptoUtils.serialize_public_key(priv.public_key()).decode()

                protected = LocalKeyManager.protect_key_bundle(priv_pem, login_pass, recovery_pass)
                self._secure_write_json(self._safe_key_path(username, purpose), protected)
                api_bundle[purpose] = {"pub_pem": pub_pem}

            ok, msg = self.api.register_user(username, email, api_bundle)
            if ok:
                self.reg_username.set("")
                self.reg_email.set("")
                self.reg_login_pass.set("")
                self.reg_recovery_pass.set("")
                messagebox.showinfo("Success", msg)
                self._set_status("Account created successfully")
            else:
                messagebox.showerror("Registration failed", msg)
        except Exception as e:
            messagebox.showerror("Registration failed", str(e))

    def _login(self):
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
            _reenable_login_btn()
            return messagebox.showerror("Validation", msg_u)

        if not passphrase:
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
            _reenable_login_btn()
            return messagebox.showerror("Login", str(e))

        if not auth_path.exists():
            _reenable_login_btn()
            return messagebox.showerror("Login", "Identity not found on this device.")

        try:
            auth_bundle = json.loads(auth_path.read_text(encoding="utf-8"))
            auth_priv = LocalKeyManager.unlock_key_from_bundle(auth_bundle, passphrase)
            if not auth_priv:
                self.api.record_unlock_failure(username)
                self.login_pass.set("")
                _reenable_login_btn()
                return messagebox.showerror("Login", "Invalid passphrase.")

            ok, user, _, msg = self.api.login_user(
                username,
                priv_key_data=auth_priv,
                client_fingerprint="tk-desktop",
            )
            if not ok:
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
        """Run pending backup jobs (scheduled/change-triggered) without blocking UI."""
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
            if did_run and hasattr(self, "backup_phase2_status_var"):
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