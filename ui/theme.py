"""
UI Theme configuration for the Smart Card Reader application.
Modern dark theme with accent colors.
"""

# ─── Color Palette ──────────────────────────────────────────────────────────

COLORS = {
    # Base colors
    "bg_dark": "#0F1117",
    "bg_main": "#1A1B26",
    "bg_card": "#1E2030",
    "bg_elevated": "#252736",
    "bg_input": "#2A2C3E",

    # Text
    "text_primary": "#C8D3F5",
    "text_secondary": "#828BB8",
    "text_muted": "#545C7E",
    "text_bright": "#FFFFFF",

    # Accent colors
    "accent_blue": "#7AA2F7",
    "accent_cyan": "#7DCFFF",
    "accent_green": "#9ECE6A",
    "accent_orange": "#FF9E64",
    "accent_red": "#F7768E",
    "accent_purple": "#BB9AF7",
    "accent_yellow": "#E0AF68",

    # Status
    "status_connected": "#9ECE6A",
    "status_disconnected": "#F7768E",
    "status_waiting": "#E0AF68",
    "status_info": "#7AA2F7",

    # Borders
    "border": "#2F3241",
    "border_focus": "#7AA2F7",

    # Sidebar
    "sidebar_bg": "#16161E",
    "sidebar_hover": "#1E2030",
    "sidebar_selected": "#252736",

    # Success/Error
    "success": "#9ECE6A",
    "error": "#F7768E",
    "warning": "#E0AF68",
    "info": "#7AA2F7",
}

# ─── Font Configuration ────────────────────────────────────────────────────

FONTS = {
    "heading": ("Segoe UI", 18, "bold"),
    "subheading": ("Segoe UI", 14, "bold"),
    "body": ("Segoe UI", 12),
    "body_bold": ("Segoe UI", 12, "bold"),
    "small": ("Segoe UI", 10),
    "small_bold": ("Segoe UI", 10, "bold"),
    "mono": ("Consolas", 11),
    "mono_small": ("Consolas", 10),
    "mono_large": ("Consolas", 12),
    "label": ("Segoe UI", 11),
    "button": ("Segoe UI", 11, "bold"),
    "tab": ("Segoe UI", 12),
}

# ─── Spacing ────────────────────────────────────────────────────────────────

PADDING = {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 24,
}

# ─── Widget Dimensions ─────────────────────────────────────────────────────

DIMENSIONS = {
    "sidebar_width": 280,
    "corner_radius": 8,
    "button_height": 36,
    "entry_height": 36,
    "border_width": 1,
}
