"""
Key Diversification View.
Interface for computing diversified keys using various methods (AN10922, etc.).
"""

import customtkinter as ctk
from typing import Callable

from .theme import COLORS, FONTS, PADDING, DIMENSIONS
from core.apdu import bytes_to_hex, hex_to_bytes
from core.diversification import (
    DiversificationMethod,
    diversify_key_an10922_aes128,
    diversify_key_an10922_2k3des,
    diversify_key_custom,
    format_diversification_info,
    CRYPTO_AVAILABLE,
)


class DiversificationView(ctk.CTkFrame):
    """Key diversification tool tab."""

    def __init__(self, parent, on_get_uid: Callable):
        """
        Args:
            on_get_uid: Callback to get current card UID from reader.
        """
        super().__init__(parent, fg_color="transparent")
        self._on_get_uid = on_get_uid
        self._build_ui()

    def _build_ui(self):
        scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            scrollbar_button_color=COLORS["bg_elevated"],
            scrollbar_button_hover_color=COLORS["accent_blue"]
        )
        scroll.pack(fill="both", expand=True, padx=PADDING["lg"], pady=PADDING["md"])

        # ─── Method Selection ───────────────────────────────────────
        method_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        method_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            method_frame, text="Key Diversification",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        method_row = ctk.CTkFrame(method_frame, fg_color="transparent")
        method_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            method_row, text="Method:",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._method_var = ctk.StringVar(value=DiversificationMethod.AN10922_AES128)
        self._method_menu = ctk.CTkOptionMenu(
            method_row,
            values=[
                DiversificationMethod.AN10922_AES128,
                DiversificationMethod.AN10922_2K3DES,
                DiversificationMethod.CUSTOM_AES,
            ],
            variable=self._method_var,
            width=200, height=32,
            font=FONTS["small"],
            fg_color=COLORS["bg_input"],
            button_color=COLORS["accent_blue"],
            button_hover_color="#5D8AF0",
            dropdown_fg_color=COLORS["bg_elevated"],
            dropdown_hover_color=COLORS["accent_blue"],
            text_color=COLORS["text_primary"]
        )
        self._method_menu.pack(side="left", padx=PADDING["sm"])

        # ─── Input Parameters ───────────────────────────────────────
        params_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        params_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            params_frame, text="Input Parameters",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        # Master Key
        key_row = ctk.CTkFrame(params_frame, fg_color="transparent")
        key_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            key_row, text="Master Key (hex):",
            font=FONTS["label"], text_color=COLORS["text_secondary"],
            width=140, anchor="w"
        ).pack(side="left")

        self._master_key_entry = ctk.CTkEntry(
            key_row, width=400,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="00000000000000000000000000000000"
        )
        self._master_key_entry.pack(side="left", padx=PADDING["sm"], fill="x", expand=True)

        # UID
        uid_row = ctk.CTkFrame(params_frame, fg_color="transparent")
        uid_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            uid_row, text="UID (hex):",
            font=FONTS["label"], text_color=COLORS["text_secondary"],
            width=140, anchor="w"
        ).pack(side="left")

        self._uid_entry = ctk.CTkEntry(
            uid_row, width=250,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="04 AA BB CC DD EE FF"
        )
        self._uid_entry.pack(side="left", padx=PADDING["sm"])

        ctk.CTkButton(
            uid_row, text="Read from Card",
            width=130, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_cyan"],
            hover_color="#5DB8E8",
            text_color=COLORS["bg_dark"],
            command=self._read_uid_from_card
        ).pack(side="left", padx=(PADDING["xs"], 0))

        # AID
        aid_row = ctk.CTkFrame(params_frame, fg_color="transparent")
        aid_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            aid_row, text="AID (hex, optional):",
            font=FONTS["label"], text_color=COLORS["text_secondary"],
            width=140, anchor="w"
        ).pack(side="left")

        self._div_aid_entry = ctk.CTkEntry(
            aid_row, width=120,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="010000"
        )
        self._div_aid_entry.pack(side="left", padx=PADDING["sm"])

        # System Identifier
        sysid_row = ctk.CTkFrame(params_frame, fg_color="transparent")
        sysid_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            sysid_row, text="System ID (hex):",
            font=FONTS["label"], text_color=COLORS["text_secondary"],
            width=140, anchor="w"
        ).pack(side="left")

        self._sysid_entry = ctk.CTkEntry(
            sysid_row, width=250,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="Optional system identifier"
        )
        self._sysid_entry.pack(side="left", padx=PADDING["sm"])

        # Custom diversification data
        custom_row = ctk.CTkFrame(params_frame, fg_color="transparent")
        custom_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            custom_row, text="Custom Data (hex):",
            font=FONTS["label"], text_color=COLORS["text_secondary"],
            width=140, anchor="w"
        ).pack(side="left")

        self._custom_data_entry = ctk.CTkEntry(
            custom_row, width=400,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="For custom diversification method"
        )
        self._custom_data_entry.pack(side="left", padx=PADDING["sm"], fill="x", expand=True)

        # ─── Calculate Button ───────────────────────────────────────
        btn_row = ctk.CTkFrame(scroll, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkButton(
            btn_row, text="Calculate Diversified Key",
            width=250, height=44,
            font=FONTS["button"],
            fg_color=COLORS["accent_green"],
            hover_color="#7DBE4A",
            text_color=COLORS["bg_dark"],
            corner_radius=DIMENSIONS["corner_radius"],
            command=self._calculate
        ).pack(side="left")

        ctk.CTkButton(
            btn_row, text="Clear",
            width=80, height=44,
            font=FONTS["button"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_red"],
            text_color=COLORS["text_secondary"],
            corner_radius=DIMENSIONS["corner_radius"],
            command=self._clear_output
        ).pack(side="left", padx=PADDING["sm"])

        # ─── Result ─────────────────────────────────────────────────
        result_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        result_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            result_frame, text="Result",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        # Diversified key display
        key_result_row = ctk.CTkFrame(result_frame, fg_color="transparent")
        key_result_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            key_result_row, text="Diversified Key:",
            font=FONTS["label"], text_color=COLORS["text_secondary"],
            width=140, anchor="w"
        ).pack(side="left")

        self._result_key = ctk.CTkEntry(
            key_result_row,
            font=FONTS["mono_large"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["accent_green"],
            text_color=COLORS["accent_green"],
            border_width=2,
            state="disabled"
        )
        self._result_key.pack(side="left", fill="x", expand=True, padx=PADDING["sm"])

        # Detailed output
        self._output = ctk.CTkTextbox(
            result_frame,
            height=200,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            text_color=COLORS["text_primary"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=6
        )
        self._output.pack(fill="x", padx=PADDING["lg"], pady=(PADDING["xs"], PADDING["md"]))

        # ─── Info ───────────────────────────────────────────────────
        if not CRYPTO_AVAILABLE:
            warning = ctk.CTkLabel(
                scroll,
                text="Warning: pycryptodome not installed. Diversification unavailable.\n"
                     "Install with: pip install pycryptodome",
                font=FONTS["small"],
                text_color=COLORS["accent_red"],
                justify="left"
            )
            warning.pack(fill="x", pady=PADDING["md"])

    def _read_uid_from_card(self):
        """Read UID from the connected card."""
        uid = self._on_get_uid()
        if uid:
            self._uid_entry.delete(0, "end")
            self._uid_entry.insert(0, bytes_to_hex(uid))
        else:
            self._append_output("[INFO] No UID available. Connect a card first.")

    def _calculate(self):
        """Perform key diversification."""
        if not CRYPTO_AVAILABLE:
            self._append_output("[ERROR] pycryptodome not installed")
            return

        method = self._method_var.get()

        # Parse inputs
        try:
            master_key_hex = self._master_key_entry.get().strip().replace(" ", "")
            if not master_key_hex:
                master_key_hex = "00" * 16
            master_key = hex_to_bytes(master_key_hex)

            uid_hex = self._uid_entry.get().strip().replace(" ", "")
            uid = hex_to_bytes(uid_hex) if uid_hex else []

            aid_hex = self._div_aid_entry.get().strip().replace(" ", "")
            aid = hex_to_bytes(aid_hex) if aid_hex else None

            sysid_hex = self._sysid_entry.get().strip().replace(" ", "")
            system_id = hex_to_bytes(sysid_hex) if sysid_hex else None

            custom_hex = self._custom_data_entry.get().strip().replace(" ", "")
            custom_data = hex_to_bytes(custom_hex) if custom_hex else None

        except Exception as e:
            self._append_output(f"[ERROR] Invalid input: {e}")
            return

        try:
            if method == DiversificationMethod.AN10922_AES128:
                if len(master_key) != 16:
                    self._append_output("[ERROR] AES master key must be 16 bytes")
                    return
                result = diversify_key_an10922_aes128(master_key, uid, aid, system_id)

            elif method == DiversificationMethod.AN10922_2K3DES:
                if len(master_key) != 16:
                    self._append_output("[ERROR] 2K3DES master key must be 16 bytes")
                    return
                result = diversify_key_an10922_2k3des(master_key, uid, aid, system_id)

            elif method == DiversificationMethod.CUSTOM_AES:
                data = custom_data if custom_data else uid
                if not data:
                    self._append_output("[ERROR] Please provide diversification data")
                    return
                result = diversify_key_custom(master_key, data, method)

            else:
                self._append_output(f"[ERROR] Unknown method: {method}")
                return

            # Display result
            result_hex = bytes_to_hex(result)
            self._result_key.configure(state="normal")
            self._result_key.delete(0, "end")
            self._result_key.insert(0, result_hex)
            self._result_key.configure(state="disabled")

            info = format_diversification_info(master_key, uid, aid, system_id, method, result)
            self._append_output(f"--- Diversification Result ---\n{info}\n")

        except Exception as e:
            self._append_output(f"[ERROR] Diversification failed: {e}")

    def _append_output(self, text: str):
        self._output.configure(state="normal")
        self._output.insert("end", text + "\n")
        self._output.see("end")

    def _clear_output(self):
        self._output.configure(state="normal")
        self._output.delete("1.0", "end")
        self._result_key.configure(state="normal")
        self._result_key.delete(0, "end")
        self._result_key.configure(state="disabled")
