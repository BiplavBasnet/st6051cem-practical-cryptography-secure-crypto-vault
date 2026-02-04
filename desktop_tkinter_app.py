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