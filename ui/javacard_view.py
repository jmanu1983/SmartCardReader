"""
JavaCard Operations View.
Provides interface for JavaCard applet selection, APDU exchange,
and GlobalPlatform operations.
"""

import customtkinter as ctk
from typing import Callable

from .theme import COLORS, FONTS, PADDING, DIMENSIONS
from core.apdu import bytes_to_hex, hex_to_bytes, format_hex_dump
from core.javacard import KNOWN_AIDS


class JavaCardView(ctk.CTkFrame):
    """JavaCard operations tab."""

    def __init__(self, parent, on_command: Callable):
        super().__init__(parent, fg_color="transparent")
        self._on_command = on_command
        self._build_ui()

    def _build_ui(self):
        scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            scrollbar_button_color=COLORS["bg_elevated"],
            scrollbar_button_hover_color=COLORS["accent_blue"]
        )
        scroll.pack(fill="both", expand=True, padx=PADDING["lg"], pady=PADDING["md"])

        # ─── Applet Selection ───────────────────────────────────────
        select_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        select_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            select_frame, text="Applet Selection",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        # Known AIDs dropdown
        aids_row = ctk.CTkFrame(select_frame, fg_color="transparent")
        aids_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            aids_row, text="Known AIDs:",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        aid_names = list(KNOWN_AIDS.keys())
        self._known_aid_var = ctk.StringVar(value=aid_names[0] if aid_names else "")
        self._known_aid_menu = ctk.CTkOptionMenu(
            aids_row,
            values=aid_names,
            variable=self._known_aid_var,
            width=250, height=32,
            font=FONTS["small"],
            fg_color=COLORS["bg_input"],
            button_color=COLORS["accent_blue"],
            button_hover_color="#5D8AF0",
            dropdown_fg_color=COLORS["bg_elevated"],
            dropdown_hover_color=COLORS["accent_blue"],
            text_color=COLORS["text_primary"],
            command=self._on_known_aid_selected
        )
        self._known_aid_menu.pack(side="left", padx=PADDING["sm"])

        # Custom AID entry
        custom_row = ctk.CTkFrame(select_frame, fg_color="transparent")
        custom_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            custom_row, text="AID (hex):",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._aid_entry = ctk.CTkEntry(
            custom_row, width=350,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="A000000003000000"
        )
        self._aid_entry.pack(side="left", padx=PADDING["sm"], fill="x", expand=True)

        ctk.CTkButton(
            custom_row, text="SELECT",
            width=100, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_blue"],
            hover_color="#5D8AF0",
            command=self._select_applet
        ).pack(side="left", padx=(PADDING["xs"], 0))

        # Quick actions
        quick_row = ctk.CTkFrame(select_frame, fg_color="transparent")
        quick_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        ctk.CTkButton(
            quick_row, text="Probe Known AIDs",
            width=150, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_green"],
            hover_color="#7DBE4A",
            text_color=COLORS["bg_dark"],
            command=self._probe_aids
        ).pack(side="left", padx=(0, PADDING["xs"]))

        ctk.CTkButton(
            quick_row, text="Get CPLC Data",
            width=130, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_cyan"],
            hover_color="#5DB8E8",
            text_color=COLORS["bg_dark"],
            command=self._get_cplc
        ).pack(side="left", padx=(0, PADDING["xs"]))

        ctk.CTkButton(
            quick_row, text="Read NDEF",
            width=110, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_purple"],
            hover_color="#9A7AE8",
            text_color=COLORS["bg_dark"],
            command=self._read_ndef
        ).pack(side="left", padx=(0, PADDING["xs"]))

        # ─── Custom APDU ────────────────────────────────────────────
        apdu_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        apdu_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            apdu_frame, text="Send APDU",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        # APDU fields
        fields_row = ctk.CTkFrame(apdu_frame, fg_color="transparent")
        fields_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        for label, width, placeholder, attr in [
            ("CLA", 50, "00", "_cla_entry"),
            ("INS", 50, "A4", "_ins_entry"),
            ("P1", 50, "04", "_p1_entry"),
            ("P2", 50, "00", "_p2_entry"),
        ]:
            ctk.CTkLabel(
                fields_row, text=label,
                font=FONTS["small"], text_color=COLORS["text_muted"]
            ).pack(side="left", padx=(PADDING["xs"], 2))
            entry = ctk.CTkEntry(
                fields_row, width=width,
                font=FONTS["mono"],
                fg_color=COLORS["bg_input"],
                border_color=COLORS["border"],
                text_color=COLORS["text_primary"],
                placeholder_text=placeholder
            )
            entry.pack(side="left", padx=(0, PADDING["xs"]))
            setattr(self, attr, entry)

        data_row = ctk.CTkFrame(apdu_frame, fg_color="transparent")
        data_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            data_row, text="Data (hex):",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._data_entry = ctk.CTkEntry(
            data_row, width=300,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="Optional data bytes"
        )
        self._data_entry.pack(side="left", padx=PADDING["sm"], fill="x", expand=True)

        le_row = ctk.CTkFrame(apdu_frame, fg_color="transparent")
        le_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            le_row, text="Le:",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._le_entry = ctk.CTkEntry(
            le_row, width=50,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="00"
        )
        self._le_entry.pack(side="left", padx=PADDING["sm"])

        ctk.CTkButton(
            le_row, text="Send APDU",
            width=120, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_orange"],
            hover_color="#E08844",
            text_color=COLORS["bg_dark"],
            command=self._send_apdu
        ).pack(side="left", padx=(PADDING["lg"], 0))

        # ─── Raw APDU ──────────────────────────────────────────────
        raw_frame = ctk.CTkFrame(apdu_frame, fg_color="transparent")
        raw_frame.pack(fill="x", padx=PADDING["lg"], pady=(PADDING["xs"], PADDING["md"]))

        ctk.CTkLabel(
            raw_frame, text="Raw APDU:",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._raw_apdu_entry = ctk.CTkEntry(
            raw_frame, width=400,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="00 A4 04 00 07 A0000000030000 00"
        )
        self._raw_apdu_entry.pack(side="left", padx=PADDING["sm"], fill="x", expand=True)

        ctk.CTkButton(
            raw_frame, text="Send Raw",
            width=100, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_orange"],
            hover_color="#E08844",
            text_color=COLORS["bg_dark"],
            command=self._send_raw_apdu
        ).pack(side="left")

        # ─── Output ─────────────────────────────────────────────────
        output_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        output_frame.pack(fill="x", pady=(0, PADDING["md"]))

        output_header = ctk.CTkFrame(output_frame, fg_color="transparent")
        output_header.pack(fill="x", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        ctk.CTkLabel(
            output_header, text="Output",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(side="left")

        ctk.CTkButton(
            output_header, text="Clear",
            width=60, height=28,
            font=FONTS["small"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_red"],
            text_color=COLORS["text_secondary"],
            command=self._clear_output
        ).pack(side="right")

        self._output = ctk.CTkTextbox(
            output_frame,
            height=250,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            text_color=COLORS["text_primary"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=6
        )
        self._output.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

    def _append_output(self, text: str):
        self._output.configure(state="normal")
        self._output.insert("end", text + "\n")
        self._output.see("end")

    def _clear_output(self):
        self._output.configure(state="normal")
        self._output.delete("1.0", "end")

    def _on_known_aid_selected(self, name: str):
        """Fill in the AID from known AIDs list."""
        aid = KNOWN_AIDS.get(name, "")
        self._aid_entry.delete(0, "end")
        self._aid_entry.insert(0, aid)

    def _select_applet(self):
        aid_hex = self._aid_entry.get().strip().replace(" ", "")
        if not aid_hex:
            self._append_output("[ERROR] Please enter an AID")
            return

        result = self._on_command("jc_select", aid=aid_hex)
        if result:
            success, response, msg = result
            if success:
                self._append_output(f"[OK] {msg}")
                if response.data:
                    self._append_output(f"  Response: {bytes_to_hex(response.data)}")
            else:
                self._append_output(f"[FAIL] {msg} (SW={response.sw:04X})")

    def _probe_aids(self):
        self._append_output("--- Probing Known AIDs ---")
        result = self._on_command("jc_probe")
        if result:
            if len(result) > 0:
                for app in result:
                    self._append_output(f"  [FOUND] {app['name']}: {app['aid']}")
                    if app.get('response_data'):
                        self._append_output(f"    Data: {app['response_data']}")
            else:
                self._append_output("  No known applets found")
        else:
            self._append_output("[FAIL] Probe failed")

    def _get_cplc(self):
        self._append_output("--- CPLC Data ---")
        result = self._on_command("jc_cplc")
        if result:
            for key, val in result.items():
                self._append_output(f"  {key}: {val}")
        else:
            self._append_output("[FAIL] Could not get CPLC data")

    def _read_ndef(self):
        self._append_output("--- NDEF Data ---")
        result = self._on_command("jc_ndef")
        if result:
            self._append_output(f"  NDEF: {result}")
        else:
            self._append_output("[FAIL] No NDEF data found")

    def _send_apdu(self):
        try:
            cla = int(self._cla_entry.get().strip() or "00", 16)
            ins = int(self._ins_entry.get().strip() or "A4", 16)
            p1 = int(self._p1_entry.get().strip() or "00", 16)
            p2 = int(self._p2_entry.get().strip() or "00", 16)

            data_hex = self._data_entry.get().strip().replace(" ", "")
            data = hex_to_bytes(data_hex) if data_hex else None

            le_str = self._le_entry.get().strip()
            le = int(le_str, 16) if le_str else None

            result = self._on_command("jc_apdu", cla=cla, ins=ins, p1=p1, p2=p2, data=data, le=le)
            if result:
                self._append_output(f">> {cla:02X} {ins:02X} {p1:02X} {p2:02X}" +
                                    (f" [{bytes_to_hex(data)}]" if data else "") +
                                    (f" Le={le:02X}" if le is not None else ""))
                self._append_output(f"<< SW={result.sw:04X} ({result.status_text})")
                if result.data:
                    self._append_output(f"   Data: {bytes_to_hex(result.data)}")
                    if len(result.data) > 16:
                        self._append_output(format_hex_dump(result.data))
            else:
                self._append_output("[FAIL] No response")

        except ValueError as e:
            self._append_output(f"[ERROR] Invalid input: {e}")

    def _send_raw_apdu(self):
        raw = self._raw_apdu_entry.get().strip()
        if not raw:
            self._append_output("[ERROR] Please enter an APDU")
            return

        try:
            result = self._on_command("jc_raw", apdu=raw)
            if result:
                self._append_output(f">> {raw}")
                self._append_output(f"<< SW={result.sw:04X} ({result.status_text})")
                if result.data:
                    self._append_output(f"   Data: {bytes_to_hex(result.data)}")
            else:
                self._append_output("[FAIL] No response")
        except Exception as e:
            self._append_output(f"[ERROR] {e}")
