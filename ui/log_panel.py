"""
Log Panel.
Bottom panel displaying application logs with timestamps and colored levels.
"""

import customtkinter as ctk
from datetime import datetime
from typing import Optional

from .theme import COLORS, FONTS, PADDING


class LogPanel(ctk.CTkFrame):
    """Bottom log panel with timestamped entries."""

    def __init__(self, parent, height: int = 140):
        super().__init__(
            parent,
            height=height,
            fg_color=COLORS["bg_dark"],
            corner_radius=0
        )
        self.pack_propagate(False)

        self._build_ui()

    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self, fg_color="transparent", height=28)
        header.pack(fill="x", padx=PADDING["md"], pady=(PADDING["xs"], 0))
        header.pack_propagate(False)

        ctk.CTkLabel(
            header, text="LOG",
            font=FONTS["small_bold"],
            text_color=COLORS["text_muted"]
        ).pack(side="left")

        ctk.CTkButton(
            header, text="Clear",
            width=50, height=22,
            font=("Segoe UI", 9),
            fg_color="transparent",
            hover_color=COLORS["bg_elevated"],
            text_color=COLORS["text_muted"],
            command=self.clear
        ).pack(side="right")

        # Log text area
        self._log_text = ctk.CTkTextbox(
            self,
            font=FONTS["mono_small"],
            fg_color=COLORS["bg_dark"],
            text_color=COLORS["text_secondary"],
            border_width=0,
            corner_radius=0,
            wrap="word",
            activate_scrollbars=True
        )
        self._log_text.pack(fill="both", expand=True, padx=PADDING["md"], pady=(0, PADDING["xs"]))
        self._log_text.configure(state="disabled")

    def log(self, message: str, level: str = "INFO"):
        """
        Add a log entry.
        Args:
            message: Log message text
            level: One of INFO, SUCCESS, WARNING, ERROR, DEBUG
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        prefix_colors = {
            "INFO": COLORS["info"],
            "SUCCESS": COLORS["success"],
            "WARNING": COLORS["warning"],
            "ERROR": COLORS["error"],
            "DEBUG": COLORS["text_muted"],
        }

        self._log_text.configure(state="normal")
        self._log_text.insert("end", f"[{timestamp}] [{level}] {message}\n")
        self._log_text.see("end")
        self._log_text.configure(state="disabled")

    def info(self, message: str):
        self.log(message, "INFO")

    def success(self, message: str):
        self.log(message, "SUCCESS")

    def warning(self, message: str):
        self.log(message, "WARNING")

    def error(self, message: str):
        self.log(message, "ERROR")

    def debug(self, message: str):
        self.log(message, "DEBUG")

    def clear(self):
        self._log_text.configure(state="normal")
        self._log_text.delete("1.0", "end")
        self._log_text.configure(state="disabled")
