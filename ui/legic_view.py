"""
LEGIC Operations View.
Interface for reading LEGIC Prime and LEGIC Advant cards.
Includes card info, memory reading, and reader compatibility guide.
"""

import customtkinter as ctk
from typing import Callable

from .theme import COLORS, FONTS, PADDING, DIMENSIONS
from core.apdu import bytes_to_hex, hex_to_bytes, format_hex_dump
from core.legic import (
    LegicHandler, LegicCardType,
    LEGIC_PRIME_INFO, LEGIC_ADVANT_INFO, COMPATIBLE_READERS,
)


class LegicView(ctk.CTkFrame):
    """LEGIC operations tab."""

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

        # ─── Important Notice ───────────────────────────────────────
        notice_frame = ctk.CTkFrame(scroll, fg_color="#2D1F1F", corner_radius=DIMENSIONS["corner_radius"])
        notice_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            notice_frame, text="Important : Lecteurs LEGIC",
            font=FONTS["body_bold"], text_color=COLORS["accent_orange"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        ctk.CTkLabel(
            notice_frame,
            text=(
                "Les cartes LEGIC ne peuvent PAS etre lues avec des lecteurs NFC/MIFARE standard\n"
                "(ACR122U, OMNIKEY, etc.). Vous avez besoin d'un lecteur avec puce LEGIC intégrée,\n"
                "comme la série Elatec TWN4 MultiTech LEGIC."
            ),
            font=FONTS["small"],
            text_color=COLORS["accent_yellow"],
            justify="left"
        ).pack(anchor="w", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        # ─── Card Operations ────────────────────────────────────────
        ops_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        ops_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            ops_frame, text="LEGIC Card Operations",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        btn_row = ctk.CTkFrame(ops_frame, fg_color="transparent")
        btn_row.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        for text, cmd, color in [
            ("Read Card Info", "legic_info", COLORS["accent_green"]),
            ("Get UID", "legic_uid", COLORS["accent_blue"]),
            ("Detect Card Type", "legic_detect", COLORS["accent_cyan"]),
            ("Get ATS", "legic_ats", COLORS["accent_purple"]),
        ]:
            ctk.CTkButton(
                btn_row, text=text,
                width=140, height=34,
                font=FONTS["small_bold"],
                fg_color=color,
                hover_color=COLORS["bg_elevated"],
                text_color=COLORS["bg_dark"],
                command=lambda c=cmd: self._run_command(c)
            ).pack(side="left", padx=(0, PADDING["xs"]))

        # ─── Memory Read ────────────────────────────────────────────
        mem_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        mem_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            mem_frame, text="Memory Read",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        mem_controls = ctk.CTkFrame(mem_frame, fg_color="transparent")
        mem_controls.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            mem_controls, text="Offset:",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._offset_entry = ctk.CTkEntry(
            mem_controls, width=80,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="0"
        )
        self._offset_entry.pack(side="left", padx=PADDING["sm"])

        ctk.CTkLabel(
            mem_controls, text="Length:",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._length_entry = ctk.CTkEntry(
            mem_controls, width=80,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="16"
        )
        self._length_entry.pack(side="left", padx=PADDING["sm"])

        ctk.CTkButton(
            mem_controls, text="Read Memory",
            width=120, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_blue"],
            hover_color="#5D8AF0",
            command=self._read_memory
        ).pack(side="left", padx=(PADDING["sm"], 0))

        ctk.CTkButton(
            mem_controls, text="Dump 256 bytes",
            width=130, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_orange"],
            text_color=COLORS["text_secondary"],
            command=self._dump_memory
        ).pack(side="left", padx=(PADDING["xs"], 0))

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
            height=200,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            text_color=COLORS["text_primary"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=6
        )
        self._output.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        # ─── Compatible Readers Guide ───────────────────────────────
        readers_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        readers_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            readers_frame, text="Lecteurs Compatibles LEGIC",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        for reader in COMPATIBLE_READERS:
            reader_card = ctk.CTkFrame(readers_frame, fg_color=COLORS["bg_elevated"], corner_radius=6)
            reader_card.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["sm"]))

            inner = ctk.CTkFrame(reader_card, fg_color="transparent")
            inner.pack(fill="x", padx=PADDING["md"], pady=PADDING["sm"])

            ctk.CTkLabel(
                inner, text=reader["name"],
                font=FONTS["body_bold"], text_color=COLORS["accent_cyan"],
                anchor="w"
            ).pack(fill="x")

            details = (
                f"Code: {reader['order_code']}  |  "
                f"LEGIC: {reader['legic_support']}  |  "
                f"Interface: {reader['interface']}"
            )
            ctk.CTkLabel(
                inner, text=details,
                font=FONTS["small"], text_color=COLORS["text_secondary"],
                anchor="w"
            ).pack(fill="x")

            ctk.CTkLabel(
                inner, text=f"Autres: {reader['other_techs']}",
                font=FONTS["small"], text_color=COLORS["text_muted"],
                anchor="w"
            ).pack(fill="x")

        # Spacer after readers
        ctk.CTkFrame(readers_frame, height=PADDING["sm"], fg_color="transparent").pack()

        # ─── Technology Reference ───────────────────────────────────
        tech_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        tech_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            tech_frame, text="Référence Technologie LEGIC",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        # Prime section
        prime_card = ctk.CTkFrame(tech_frame, fg_color=COLORS["bg_elevated"], corner_radius=6)
        prime_card.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["sm"]))
        prime_inner = ctk.CTkFrame(prime_card, fg_color="transparent")
        prime_inner.pack(fill="x", padx=PADDING["md"], pady=PADDING["sm"])

        ctk.CTkLabel(
            prime_inner, text="LEGIC Prime",
            font=FONTS["body_bold"], text_color=COLORS["accent_orange"],
            anchor="w"
        ).pack(fill="x")
        ctk.CTkLabel(
            prime_inner,
            text=(
                "Protocole propriétaire  |  13.56 MHz\n"
                "Cartes: MIM22 (22 oct), MIM256 (256 oct), MIM1024 (1024 oct)\n"
                "Sécurité: Master Token, chiffrement propriétaire\n"
                "Mémoire: Segments (max 8), accès par Master Token"
            ),
            font=FONTS["small"], text_color=COLORS["text_secondary"],
            anchor="w", justify="left"
        ).pack(fill="x")

        # Advant section
        advant_card = ctk.CTkFrame(tech_frame, fg_color=COLORS["bg_elevated"], corner_radius=6)
        advant_card.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["sm"]))
        advant_inner = ctk.CTkFrame(advant_card, fg_color="transparent")
        advant_inner.pack(fill="x", padx=PADDING["md"], pady=PADDING["sm"])

        ctk.CTkLabel(
            advant_inner, text="LEGIC Advant",
            font=FONTS["body_bold"], text_color=COLORS["accent_green"],
            anchor="w"
        ).pack(fill="x")
        ctk.CTkLabel(
            advant_inner,
            text=(
                "ISO 14443 compatible  |  13.56 MHz\n"
                "Cartes: ATC256, ATC1024, ATC2048, ATC4096, CTC4096 (dual)\n"
                "Sécurité: Authentification mutuelle, chiffrement AES-128\n"
                "Mémoire: Stamp/File system (max 7 fichiers)"
            ),
            font=FONTS["small"], text_color=COLORS["text_secondary"],
            anchor="w", justify="left"
        ).pack(fill="x")

        # Spacer
        ctk.CTkFrame(tech_frame, height=PADDING["sm"], fg_color="transparent").pack()

    def _run_command(self, command: str):
        """Execute a LEGIC command."""
        result = self._on_command(command)

        if command == "legic_info" and result:
            self._append_output("--- LEGIC Card Info ---")
            self._append_output(f"  Technology: {result.get('technology', '?')}")
            self._append_output(f"  Card Type: {result.get('card_type', '?')}")
            if result.get('uid_hex'):
                self._append_output(f"  UID: {result['uid_hex']}")
            if result.get('family'):
                self._append_output(f"  Family: {result['family']}")
            if result.get('ats'):
                self._append_output(f"  ATS: {result['ats']}")

            mem = result.get('memory_info', {})
            if mem:
                self._append_output("  Memory:")
                for k, v in mem.items():
                    self._append_output(f"    {k}: {v}")

            features = result.get('features', [])
            if features:
                self._append_output(f"  Features: {', '.join(features)}")

            if result.get('first_bytes'):
                self._append_output(f"  First bytes: {result['first_bytes']}")

        elif command == "legic_uid" and result:
            self._append_output(f"UID: {bytes_to_hex(result)}")

        elif command == "legic_detect" and result:
            self._append_output(f"Detected: {result}")

        elif command == "legic_ats" and result:
            self._append_output(f"ATS: {bytes_to_hex(result)}")

        elif result is None:
            self._append_output("[FAIL] No response - is a LEGIC-compatible reader connected?")

    def _read_memory(self):
        """Read memory at specified offset and length."""
        try:
            offset = int(self._offset_entry.get().strip() or "0")
            length = int(self._length_entry.get().strip() or "16")
        except ValueError:
            self._append_output("[ERROR] Invalid offset or length")
            return

        result = self._on_command("legic_read", offset=offset, length=length)
        if result:
            self._append_output(f"--- Memory @ offset {offset}, {len(result)} bytes ---")
            self._append_output(format_hex_dump(result))
        else:
            self._append_output(f"[FAIL] Could not read memory at offset {offset}")

    def _dump_memory(self):
        """Dump first 256 bytes of card memory."""
        self._append_output("--- Memory Dump (256 bytes) ---")
        all_data = []
        for offset in range(0, 256, 16):
            result = self._on_command("legic_read", offset=offset, length=16)
            if result:
                all_data.extend(result)
            else:
                self._append_output(f"[STOP] Read failed at offset {offset}")
                break

        if all_data:
            self._append_output(format_hex_dump(all_data))
            self._append_output(f"\nTotal: {len(all_data)} bytes read")

    def _append_output(self, text: str):
        self._output.configure(state="normal")
        self._output.insert("end", text + "\n")
        self._output.see("end")

    def _clear_output(self):
        self._output.configure(state="normal")
        self._output.delete("1.0", "end")
