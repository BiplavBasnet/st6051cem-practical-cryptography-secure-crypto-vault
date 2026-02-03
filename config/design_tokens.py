"""Design tokens for the SecureCrypt Vault UI.

Centralises typography, spacing, colours, and state colours so every
widget draws from a single source of truth.  Import this module instead
of hard-coding style values.
"""


# ── Typography ────────────────────────────────────────────────────────

FONT_FAMILY = "Segoe UI"
FONT_FAMILY_MONO = "Consolas"

FONT_SIZE_XS = 9
FONT_SIZE_SM = 10
FONT_SIZE_MD = 11
FONT_SIZE_LG = 13
FONT_SIZE_XL = 16
FONT_SIZE_XXL = 22
FONT_SIZE_HERO = 28

FONT_WEIGHT_NORMAL = "normal"
FONT_WEIGHT_BOLD = "bold"


# ── Spacing (px) ──────────────────────────────────────────────────────

SPACE_XXS = 2
SPACE_XS = 4
SPACE_SM = 8
SPACE_MD = 12
SPACE_LG = 16
SPACE_XL = 24
SPACE_XXL = 32
SPACE_XXXL = 48


# ── Border / Radius ──────────────────────────────────────────────────

RADIUS_SM = 4
RADIUS_MD = 8
RADIUS_LG = 12
RADIUS_PILL = 999


# ── Colour palettes ──────────────────────────────────────────────────

THEMES = {
    "dark": {
        "bg": "#0d1117",
        "bg_secondary": "#161b22",
        "bg_tertiary": "#21262d",
        "fg": "#f0f6fc",
        "fg_secondary": "#c9d1d9",
        "fg_muted": "#8b949e",
        "accent": "#58a6ff",
        "accent_fg": "#ffffff",
        "accent_hover": "#79c0ff",
        "accent_active": "#1f6feb",
        "success": "#3fb950",
        "warning": "#d29922",
        "danger": "#f85149",
        "danger_hover": "#da3633",
        "border": "#30363d",
        "border_focus": "#58a6ff",
        "input_bg": "#0d1117",
        "input_fg": "#f0f6fc",
        "card_bg": "#161b22",
        "card_shadow": "#000000",
        "nav_bg": "#161b22",
        "nav_fg": "#f0f6fc",
        "nav_active_bg": "#1f6feb",
        "nav_active_fg": "#ffffff",
        "nav_hover_bg": "#21262d",
        "table_header_bg": "#21262d",
        "table_row_hover": "#1c2128",
        "table_row_alt": "#0d1117",
        "disabled_bg": "#21262d",
        "disabled_fg": "#484f58",
        "tooltip_bg": "#21262d",
        "tooltip_fg": "#f0f6fc",
        "scrollbar_bg": "#0d1117",
        "scrollbar_thumb": "#30363d",
    },
    "light": {
        "bg": "#ffffff",
        "bg_secondary": "#f8f9fa",
        "bg_tertiary": "#e9ecef",
        "fg": "#1a1a1a",
        "fg_secondary": "#495057",
        "fg_muted": "#6c757d",
        "accent": "#0d6efd",
        "accent_fg": "#ffffff",
        "accent_hover": "#0b5ed7",
        "accent_active": "#0a58ca",
        "success": "#198754",
        "warning": "#ffc107",
        "danger": "#dc3545",
        "danger_hover": "#bb2d3b",
        "border": "#dee2e6",
        "border_focus": "#0d6efd",
        "input_bg": "#ffffff",
        "input_fg": "#212529",
        "card_bg": "#ffffff",
        "card_shadow": "#dee2e6",
        "nav_bg": "#f8f9fa",
        "nav_fg": "#212529",
        "nav_active_bg": "#0d6efd",
        "nav_active_fg": "#ffffff",
        "nav_hover_bg": "#e9ecef",
        "table_header_bg": "#f8f9fa",
        "table_row_hover": "#f1f3f5",
        "table_row_alt": "#ffffff",
        "disabled_bg": "#e9ecef",
        "disabled_fg": "#6c757d",
        "tooltip_bg": "#212529",
        "tooltip_fg": "#ffffff",
        "scrollbar_bg": "#f8f9fa",
        "scrollbar_thumb": "#adb5bd",
    },
    "high_contrast": {
        "bg": "#000000",
        "bg_secondary": "#1a1a1a",
        "bg_tertiary": "#333333",
        "fg": "#ffffff",
        "fg_secondary": "#e0e0e0",
        "fg_muted": "#b0b0b0",
        "accent": "#00e5ff",
        "accent_fg": "#000000",
        "accent_hover": "#18ffff",
        "accent_active": "#00b8d4",
        "success": "#00e676",
        "warning": "#ffab00",
        "danger": "#ff1744",
        "danger_hover": "#d50000",
        "border": "#ffffff",
        "border_focus": "#00e5ff",
        "input_bg": "#1a1a1a",
        "input_fg": "#ffffff",
        "card_bg": "#1a1a1a",
        "card_shadow": "#000000",
        "nav_bg": "#000000",
        "nav_fg": "#ffffff",
        "nav_active_bg": "#00e5ff",
        "nav_active_fg": "#000000",
        "nav_hover_bg": "#333333",
        "table_header_bg": "#333333",
        "table_row_hover": "#1a1a1a",
        "table_row_alt": "#0d0d0d",
        "disabled_bg": "#333333",
        "disabled_fg": "#808080",
        "tooltip_bg": "#333333",
        "tooltip_fg": "#ffffff",
        "scrollbar_bg": "#000000",
        "scrollbar_thumb": "#666666",
    },
}


# ── State colours (for any theme) ────────────────────────────────────

STRENGTH_COLOURS = {
    0: "#ef5350",   # Critical
    1: "#ff7043",   # Weak
    2: "#ffa726",   # Fair
    3: "#66bb6a",   # Good
    4: "#26a69a",   # Strong
}

STRENGTH_LABELS = {
    0: "Critical",
    1: "Weak",
    2: "Fair",
    3: "Good",
    4: "Strong",
}


# ── Helpers ───────────────────────────────────────────────────────────

def get_theme(name: str = "dark") -> dict:
    """Return a colour palette dict for the requested theme."""
    return THEMES.get(name, THEMES["dark"])


def strength_colour(score: int) -> str:
    """Return the hex colour for a password strength score (0-4)."""
    return STRENGTH_COLOURS.get(min(max(score, 0), 4), STRENGTH_COLOURS[0])


def strength_label(score: int) -> str:
    """Return the human label for a password strength score (0-4)."""
    return STRENGTH_LABELS.get(min(max(score, 0), 4), STRENGTH_LABELS[0])
