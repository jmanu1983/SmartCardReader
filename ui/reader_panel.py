"""
Reader Selection Panel (Sidebar).
Displays available PC/SC readers, card status, and connection controls.
"""

import customtkinter as ctk
from typing import Callable, Optional

from .theme import COLORS, FONTS, PADDING, DIMENSIONS


class ReaderPanel(ctk.CTkFrame):
    """Left sidebar panel for reader selection and status display."""

    def __init__(self, parent, on_reader_selected: Callable,
                 on_connect: Callable, on_disconnect: Callable,
                 on_refresh: Callable):
        super().__init__(
            parent,
            width=DIMENSIONS["sidebar_width"],
            corner_radius=0,
            fg_color=COLORS["sidebar_bg"]
        )
        self.pack_propagate(False)

        self._on_reader_selected = on_reader_selected
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._on_refresh = on_refresh

        self._selected_index = -1
        self._reader_buttons = []

        self._build_ui()

    def _build_ui(self):
        """Build the sidebar UI."""
        # ─── App Title ──────────────────────────────────────────────
        title_frame = ctk.CTkFrame(self, fg_color="transparent")
        title_frame.pack(fill="x", padx=PADDING["lg"], pady=(PADDING["xl"], PADDING["md"]))

        ctk.CTkLabel(
            title_frame,
            text="Smart Card",
            font=FONTS["heading"],
            text_color=COLORS["accent_blue"],
            anchor="w"
        ).pack(fill="x")

        ctk.CTkLabel(
            title_frame,
            text="Reader",
            font=("Segoe UI", 24, "bold"),
            text_color=COLORS["text_bright"],
            anchor="w"
        ).pack(fill="x")

        # ─── Separator ──────────────────────────────────────────────
        ctk.CTkFrame(
            self, height=1,
            fg_color=COLORS["border"]
        ).pack(fill="x", padx=PADDING["lg"], pady=PADDING["md"])

        # ─── Readers Section ────────────────────────────────────────
        readers_header = ctk.CTkFrame(self, fg_color="transparent")
        readers_header.pack(fill="x", padx=PADDING["lg"], pady=(PADDING["sm"], PADDING["xs"]))

        ctk.CTkLabel(
            readers_header,
            text="READERS",
            font=FONTS["small_bold"],
            text_color=COLORS["text_muted"]
        ).pack(side="left")

        self._refresh_btn = ctk.CTkButton(
            readers_header,
            text="Refresh",
            width=70,
            height=28,
            font=FONTS["small"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_blue"],
            text_color=COLORS["text_secondary"],
            corner_radius=6,
            command=self._on_refresh
        )
        self._refresh_btn.pack(side="right")

        # Scrollable reader list
        self._reader_list = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            scrollbar_button_color=COLORS["bg_elevated"],
            scrollbar_button_hover_color=COLORS["accent_blue"],
        )
        self._reader_list.pack(fill="both", expand=True, padx=PADDING["sm"], pady=PADDING["xs"])

        # No readers label
        self._no_readers_label = ctk.CTkLabel(
            self._reader_list,
            text="No readers found.\nConnect a reader and\nclick Refresh.",
            font=FONTS["small"],
            text_color=COLORS["text_muted"],
            justify="center"
        )
        self._no_readers_label.pack(pady=PADDING["xl"])

        # ─── Connection Controls ────────────────────────────────────
        controls_frame = ctk.CTkFrame(self, fg_color="transparent")
        controls_frame.pack(fill="x", padx=PADDING["lg"], pady=PADDING["sm"])

        self._connect_btn = ctk.CTkButton(
            controls_frame,
            text="Connect",
            height=DIMENSIONS["button_height"],
            font=FONTS["button"],
            fg_color=COLORS["accent_blue"],
            hover_color="#5D8AF0",
            text_color=COLORS["text_bright"],
            corner_radius=DIMENSIONS["corner_radius"],
            command=self._on_connect
        )
        self._connect_btn.pack(fill="x", pady=(0, PADDING["xs"]))

        self._disconnect_btn = ctk.CTkButton(
            controls_frame,
            text="Disconnect",
            height=DIMENSIONS["button_height"],
            font=FONTS["button"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_red"],
            text_color=COLORS["text_secondary"],
            corner_radius=DIMENSIONS["corner_radius"],
            command=self._on_disconnect
        )
        self._disconnect_btn.pack(fill="x")

        # ─── Status Section ─────────────────────────────────────────
        ctk.CTkFrame(
            self, height=1,
            fg_color=COLORS["border"]
        ).pack(fill="x", padx=PADDING["lg"], pady=PADDING["md"])

        status_frame = ctk.CTkFrame(self, fg_color="transparent")
        status_frame.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["lg"]))

        ctk.CTkLabel(
            status_frame,
            text="STATUS",
            font=FONTS["small_bold"],
            text_color=COLORS["text_muted"]
        ).pack(anchor="w")

        self._status_indicator = ctk.CTkFrame(
            status_frame,
            fg_color=COLORS["bg_card"],
            corner_radius=DIMENSIONS["corner_radius"]
        )
        self._status_indicator.pack(fill="x", pady=(PADDING["xs"], 0))

        indicator_inner = ctk.CTkFrame(self._status_indicator, fg_color="transparent")
        indicator_inner.pack(fill="x", padx=PADDING["md"], pady=PADDING["sm"])

        self._status_dot = ctk.CTkLabel(
            indicator_inner,
            text="●",
            font=("Segoe UI", 14),
            text_color=COLORS["status_disconnected"],
            width=20
        )
        self._status_dot.pack(side="left")

        self._status_label = ctk.CTkLabel(
            indicator_inner,
            text="Disconnected",
            font=FONTS["small_bold"],
            text_color=COLORS["text_secondary"]
        )
        self._status_label.pack(side="left", padx=(PADDING["xs"], 0))

        # Card type info
        self._card_type_label = ctk.CTkLabel(
            status_frame,
            text="",
            font=FONTS["small"],
            text_color=COLORS["accent_cyan"],
            anchor="w"
        )
        self._card_type_label.pack(fill="x", pady=(PADDING["xs"], 0))

    def update_readers(self, reader_names: list):
        """Update the reader list."""
        # Clear existing
        for btn in self._reader_buttons:
            btn.destroy()
        self._reader_buttons.clear()

        if not reader_names:
            self._no_readers_label.pack(pady=PADDING["xl"])
            return

        self._no_readers_label.pack_forget()

        for i, name in enumerate(reader_names):
            btn = ctk.CTkButton(
                self._reader_list,
                text=name,
                font=FONTS["small"],
                fg_color="transparent" if i != self._selected_index else COLORS["sidebar_selected"],
                hover_color=COLORS["sidebar_hover"],
                text_color=COLORS["text_primary"] if i != self._selected_index else COLORS["accent_blue"],
                anchor="w",
                height=40,
                corner_radius=6,
                command=lambda idx=i: self._select_reader(idx)
            )
            btn.pack(fill="x", pady=1)
            self._reader_buttons.append(btn)

    def _select_reader(self, index: int):
        """Handle reader selection."""
        self._selected_index = index

        # Update button states
        for i, btn in enumerate(self._reader_buttons):
            if i == index:
                btn.configure(
                    fg_color=COLORS["sidebar_selected"],
                    text_color=COLORS["accent_blue"]
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=COLORS["text_primary"]
                )

        self._on_reader_selected(index)

    def set_status(self, connected: bool, text: str = "", card_type: str = ""):
        """Update the connection status display."""
        if connected:
            self._status_dot.configure(text_color=COLORS["status_connected"])
            self._status_label.configure(
                text=text or "Connected",
                text_color=COLORS["status_connected"]
            )
        else:
            self._status_dot.configure(text_color=COLORS["status_disconnected"])
            self._status_label.configure(
                text=text or "Disconnected",
                text_color=COLORS["text_secondary"]
            )

        self._card_type_label.configure(text=card_type)
