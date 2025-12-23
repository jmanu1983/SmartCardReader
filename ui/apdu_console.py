"""
APDU Console View.
Interactive console for sending raw APDU commands and viewing responses.
Supports command history and hex dump formatting.
"""

import customtkinter as ctk
from typing import Callable, List

from .theme import COLORS, FONTS, PADDING, DIMENSIONS
from core.apdu import bytes_to_hex, hex_to_bytes, format_hex_dump


class APDUConsole(ctk.CTkFrame):
    """Raw APDU console tab."""

    def __init__(self, parent, on_transmit: Callable):
        """
        Args:
            on_transmit: Callback(raw_apdu_bytes) -> APDUResponse
        """
        super().__init__(parent, fg_color="transparent")
        self._on_transmit = on_transmit
        self._history: List[str] = []
        self._history_idx = -1
        self._build_ui()

    def _build_ui(self):
        # ─── Console Output ─────────────────────────────────────────
        self._console = ctk.CTkTextbox(
            self,
            font=FONTS["mono"],
            fg_color=COLORS["bg_dark"],
            text_color=COLORS["text_primary"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=DIMENSIONS["corner_radius"],
            wrap="word"
        )
        self._console.pack(fill="both", expand=True, padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        # Welcome message
        self._console.insert("end", "═══════════════════════════════════════════════════\n")
        self._console.insert("end", "  APDU Console - Smart Card Reader\n")
        self._console.insert("end", "  Enter hex APDU commands below.\n")
        self._console.insert("end", "  Example: 00 A4 04 00 07 A0000000030000 00\n")
        self._console.insert("end", "  Use UP/DOWN arrows for command history.\n")
        self._console.insert("end", "═══════════════════════════════════════════════════\n\n")
        self._console.configure(state="disabled")

        # ─── Input Area ─────────────────────────────────────────────
        input_frame = ctk.CTkFrame(self, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        input_frame.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        input_inner = ctk.CTkFrame(input_frame, fg_color="transparent")
        input_inner.pack(fill="x", padx=PADDING["md"], pady=PADDING["md"])

        # Command input
        cmd_row = ctk.CTkFrame(input_inner, fg_color="transparent")
        cmd_row.pack(fill="x")

        ctk.CTkLabel(
            cmd_row, text="APDU >>",
            font=FONTS["mono"],
            text_color=COLORS["accent_green"],
            width=70
        ).pack(side="left")

        self._input = ctk.CTkEntry(
            cmd_row,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border_focus"],
            text_color=COLORS["text_bright"],
            placeholder_text="Enter hex APDU (e.g., 00 A4 04 00 07 D2760000850101 00)",
            border_width=2
        )
        self._input.pack(side="left", fill="x", expand=True, padx=PADDING["sm"])
        self._input.bind("<Return>", self._on_send)
        self._input.bind("<Up>", self._history_up)
        self._input.bind("<Down>", self._history_down)

        ctk.CTkButton(
            cmd_row, text="Send",
            width=80, height=36,
            font=FONTS["button"],
            fg_color=COLORS["accent_blue"],
            hover_color="#5D8AF0",
            command=self._on_send
        ).pack(side="left", padx=(PADDING["xs"], 0))

        # Quick buttons row
        quick_row = ctk.CTkFrame(input_inner, fg_color="transparent")
        quick_row.pack(fill="x", pady=(PADDING["sm"], 0))

        quick_commands = [
            ("GET UID", "FF CA 00 00 00"),
            ("GET ATR", "FF 00 48 00 00"),
            ("SELECT ISD", "00 A4 04 00 08 A000000003000000 00"),
            ("NDEF App", "00 A4 04 00 07 D2760000850101 00"),
            ("DESFire Version", "90 60 00 00 00"),
            ("DESFire Apps", "90 6A 00 00 00"),
        ]

        for label, cmd in quick_commands:
            ctk.CTkButton(
                quick_row, text=label,
                width=0, height=28,
                font=FONTS["small"],
                fg_color=COLORS["bg_elevated"],
                hover_color=COLORS["accent_blue"],
                text_color=COLORS["text_secondary"],
                command=lambda c=cmd: self._quick_send(c)
            ).pack(side="left", padx=(0, PADDING["xs"]))

        # Utility buttons
        util_row = ctk.CTkFrame(input_inner, fg_color="transparent")
        util_row.pack(fill="x", pady=(PADDING["xs"], 0))

        ctk.CTkButton(
            util_row, text="Clear Console",
            width=110, height=28,
            font=FONTS["small"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_red"],
            text_color=COLORS["text_secondary"],
            command=self._clear
        ).pack(side="left", padx=(0, PADDING["xs"]))

        ctk.CTkButton(
            util_row, text="Copy Output",
            width=100, height=28,
            font=FONTS["small"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_green"],
            text_color=COLORS["text_secondary"],
            command=self._copy_output
        ).pack(side="left")

    def _on_send(self, event=None):
        """Send the APDU command."""
        cmd = self._input.get().strip()
        if not cmd:
            return

        # Add to history
        self._history.append(cmd)
        self._history_idx = len(self._history)

        # Clear input
        self._input.delete(0, "end")

        # Parse and send
        try:
            apdu_bytes = hex_to_bytes(cmd)
            if len(apdu_bytes) < 4:
                self._write_output(f"[ERROR] APDU too short (minimum 4 bytes)\n", COLORS["accent_red"])
                return

            self._write_output(f">> {bytes_to_hex(apdu_bytes)}\n", COLORS["accent_cyan"])

            response = self._on_transmit(apdu_bytes)
            if response:
                sw_color = COLORS["accent_green"] if response.is_success else COLORS["accent_red"]
                self._write_output(f"<< SW: {response.sw:04X} ({response.status_text})\n", sw_color)
                if response.data:
                    self._write_output(f"   Data ({len(response.data)} bytes): {bytes_to_hex(response.data)}\n",
                                       COLORS["text_primary"])
                    if len(response.data) > 16:
                        self._write_output(format_hex_dump(response.data) + "\n", COLORS["text_secondary"])
                self._write_output("\n")
            else:
                self._write_output("[ERROR] No response from card\n\n", COLORS["accent_red"])

        except ValueError as e:
            self._write_output(f"[ERROR] Invalid hex: {e}\n\n", COLORS["accent_red"])

    def _quick_send(self, cmd: str):
        """Send a quick command."""
        self._input.delete(0, "end")
        self._input.insert(0, cmd)
        self._on_send()

    def _history_up(self, event=None):
        """Navigate command history up."""
        if self._history and self._history_idx > 0:
            self._history_idx -= 1
            self._input.delete(0, "end")
            self._input.insert(0, self._history[self._history_idx])

    def _history_down(self, event=None):
        """Navigate command history down."""
        if self._history_idx < len(self._history) - 1:
            self._history_idx += 1
            self._input.delete(0, "end")
            self._input.insert(0, self._history[self._history_idx])
        else:
            self._history_idx = len(self._history)
            self._input.delete(0, "end")

    def _write_output(self, text: str, color: str = None):
        """Write text to the console output."""
        self._console.configure(state="normal")
        self._console.insert("end", text)
        self._console.see("end")
        self._console.configure(state="disabled")

    def _clear(self):
        """Clear the console."""
        self._console.configure(state="normal")
        self._console.delete("1.0", "end")
        self._console.configure(state="disabled")

    def _copy_output(self):
        """Copy console output to clipboard."""
        self._console.configure(state="normal")
        content = self._console.get("1.0", "end")
        self._console.configure(state="disabled")
        self.clipboard_clear()
        self.clipboard_append(content)
