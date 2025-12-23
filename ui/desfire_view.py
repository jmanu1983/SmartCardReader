"""
DESFire Operations View.
Provides interface for DESFire EV1/EV2/EV3 operations:
authentication, application browsing, file reading.
"""

import threading
import customtkinter as ctk
from typing import Callable, Optional

from .theme import COLORS, FONTS, PADDING, DIMENSIONS
from core.apdu import bytes_to_hex, hex_to_bytes, format_hex_dump


class DESFireView(ctk.CTkFrame):
    """DESFire operations tab."""

    def __init__(self, parent, on_command: Callable):
        """
        Args:
            on_command: Callback(command_name, **kwargs) -> result
        """
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

        # ─── Application Selection ──────────────────────────────────
        app_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        app_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            app_frame, text="Application Selection",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        app_controls = ctk.CTkFrame(app_frame, fg_color="transparent")
        app_controls.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            app_controls, text="AID (hex):",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._aid_entry = ctk.CTkEntry(
            app_controls, width=120,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="000000"
        )
        self._aid_entry.pack(side="left", padx=PADDING["sm"])

        ctk.CTkButton(
            app_controls, text="Select App",
            width=100, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_blue"],
            hover_color="#5D8AF0",
            command=self._select_app
        ).pack(side="left", padx=(PADDING["xs"], 0))

        ctk.CTkButton(
            app_controls, text="List Apps",
            width=100, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_cyan"],
            text_color=COLORS["text_secondary"],
            command=self._list_apps
        ).pack(side="left", padx=(PADDING["xs"], 0))

        ctk.CTkButton(
            app_controls, text="PICC Level",
            width=100, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_purple"],
            text_color=COLORS["text_secondary"],
            command=self._select_picc
        ).pack(side="left", padx=(PADDING["xs"], 0))

        # ─── Authentication ─────────────────────────────────────────
        auth_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        auth_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            auth_frame, text="Authentication",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        auth_row1 = ctk.CTkFrame(auth_frame, fg_color="transparent")
        auth_row1.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            auth_row1, text="Key Type:",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._key_type_var = ctk.StringVar(value="AES-128")
        self._key_type_menu = ctk.CTkOptionMenu(
            auth_row1,
            values=["DES", "2K3DES", "3K3DES", "AES-128"],
            variable=self._key_type_var,
            width=120, height=32,
            font=FONTS["small"],
            fg_color=COLORS["bg_input"],
            button_color=COLORS["accent_blue"],
            button_hover_color="#5D8AF0",
            dropdown_fg_color=COLORS["bg_elevated"],
            dropdown_hover_color=COLORS["accent_blue"],
            text_color=COLORS["text_primary"]
        )
        self._key_type_menu.pack(side="left", padx=PADDING["sm"])

        ctk.CTkLabel(
            auth_row1, text="Key No:",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left", padx=(PADDING["sm"], 0))

        self._key_no_entry = ctk.CTkEntry(
            auth_row1, width=50,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="0"
        )
        self._key_no_entry.pack(side="left", padx=PADDING["xs"])

        auth_row2 = ctk.CTkFrame(auth_frame, fg_color="transparent")
        auth_row2.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkLabel(
            auth_row2, text="Key (hex):",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left")

        self._key_entry = ctk.CTkEntry(
            auth_row2, width=400,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="00000000000000000000000000000000"
        )
        self._key_entry.pack(side="left", padx=PADDING["sm"], fill="x", expand=True)

        ctk.CTkButton(
            auth_row2, text="Authenticate",
            width=120, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_green"],
            hover_color="#7DBE4A",
            text_color=COLORS["bg_dark"],
            command=self._authenticate
        ).pack(side="left", padx=(PADDING["xs"], 0))

        # Auth status
        self._auth_status = ctk.CTkLabel(
            auth_frame, text="",
            font=FONTS["small"],
            text_color=COLORS["text_muted"]
        )
        self._auth_status.pack(anchor="w", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        # ─── File Operations ────────────────────────────────────────
        file_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        file_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            file_frame, text="File Operations",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        file_controls = ctk.CTkFrame(file_frame, fg_color="transparent")
        file_controls.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["xs"]))

        ctk.CTkButton(
            file_controls, text="List Files",
            width=100, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_cyan"],
            text_color=COLORS["text_secondary"],
            command=self._list_files
        ).pack(side="left", padx=(0, PADDING["xs"]))

        ctk.CTkLabel(
            file_controls, text="File No:",
            font=FONTS["label"], text_color=COLORS["text_secondary"]
        ).pack(side="left", padx=(PADDING["sm"], 0))

        self._file_no_entry = ctk.CTkEntry(
            file_controls, width=50,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="0"
        )
        self._file_no_entry.pack(side="left", padx=PADDING["xs"])

        ctk.CTkButton(
            file_controls, text="File Settings",
            width=110, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_orange"],
            text_color=COLORS["text_secondary"],
            command=self._get_file_settings
        ).pack(side="left", padx=(PADDING["xs"], 0))

        ctk.CTkButton(
            file_controls, text="Read Data",
            width=100, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["accent_blue"],
            hover_color="#5D8AF0",
            command=self._read_file
        ).pack(side="left", padx=(PADDING["xs"], 0))

        ctk.CTkButton(
            file_controls, text="Read Value",
            width=100, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_green"],
            text_color=COLORS["text_secondary"],
            command=self._read_value
        ).pack(side="left", padx=(PADDING["xs"], 0))

        ctk.CTkButton(
            file_controls, text="Read Records",
            width=110, height=32,
            font=FONTS["small_bold"],
            fg_color=COLORS["bg_elevated"],
            hover_color=COLORS["accent_purple"],
            text_color=COLORS["text_secondary"],
            command=self._read_records
        ).pack(side="left", padx=(PADDING["xs"], 0))

        # ─── Quick Actions ──────────────────────────────────────────
        quick_frame = ctk.CTkFrame(scroll, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])
        quick_frame.pack(fill="x", pady=(0, PADDING["md"]))

        ctk.CTkLabel(
            quick_frame, text="Quick Actions",
            font=FONTS["body_bold"], text_color=COLORS["accent_blue"]
        ).pack(anchor="w", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        quick_buttons = ctk.CTkFrame(quick_frame, fg_color="transparent")
        quick_buttons.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        for text, cmd, color in [
            ("Full Card Scan", self._full_scan, COLORS["accent_green"]),
            ("Get Version", self._get_version, COLORS["accent_blue"]),
            ("Get Key Settings", self._get_key_settings, COLORS["accent_cyan"]),
            ("Free Memory", self._get_free_memory, COLORS["accent_purple"]),
        ]:
            ctk.CTkButton(
                quick_buttons, text=text,
                width=140, height=32,
                font=FONTS["small_bold"],
                fg_color=color,
                hover_color=COLORS["bg_elevated"],
                text_color=COLORS["bg_dark"],
                command=cmd
            ).pack(side="left", padx=(0, PADDING["xs"]))

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
            height=300,
            font=FONTS["mono"],
            fg_color=COLORS["bg_input"],
            text_color=COLORS["text_primary"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=6
        )
        self._output.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

    def _append_output(self, text: str, tag: str = ""):
        """Append text to the output area."""
        self._output.configure(state="normal")
        self._output.insert("end", text + "\n")
        self._output.see("end")

    def _clear_output(self):
        self._output.configure(state="normal")
        self._output.delete("1.0", "end")

    def _select_app(self):
        aid_hex = self._aid_entry.get().strip().replace(" ", "")
        if not aid_hex:
            aid_hex = "000000"
        try:
            aid = hex_to_bytes(aid_hex)
            if len(aid) != 3:
                self._append_output("[ERROR] AID must be 3 bytes (6 hex chars)")
                return
            result = self._on_command("select_app", aid=aid)
            if result:
                self._append_output(f"[OK] Selected application: {bytes_to_hex(aid)}")
            else:
                self._append_output(f"[FAIL] Could not select application: {bytes_to_hex(aid)}")
        except Exception as e:
            self._append_output(f"[ERROR] {e}")

    def _list_apps(self):
        result = self._on_command("list_apps")
        if result is not None:
            self._append_output(f"--- Applications ({len(result)}) ---")
            for aid in result:
                self._append_output(f"  AID: {bytes_to_hex(aid)}")
        else:
            self._append_output("[FAIL] Could not list applications")

    def _select_picc(self):
        result = self._on_command("select_picc")
        if result:
            self._append_output("[OK] Selected PICC level (AID 000000)")
        else:
            self._append_output("[FAIL] Could not select PICC")

    def _authenticate(self):
        key_type = self._key_type_var.get()
        key_hex = self._key_entry.get().strip().replace(" ", "")
        key_no_str = self._key_no_entry.get().strip()

        try:
            key_no = int(key_no_str) if key_no_str else 0
        except ValueError:
            self._append_output("[ERROR] Invalid key number")
            return

        if not key_hex:
            # Default keys
            defaults = {
                "DES": "00" * 8,
                "2K3DES": "00" * 16,
                "3K3DES": "00" * 24,
                "AES-128": "00" * 16,
            }
            key_hex = defaults.get(key_type, "00" * 16)

        try:
            key = hex_to_bytes(key_hex)
        except Exception:
            self._append_output("[ERROR] Invalid key hex")
            return

        self._append_output(f"Authenticating with {key_type}, Key #{key_no}...")
        self._auth_status.configure(text="Authenticating...", text_color=COLORS["accent_yellow"])

        result = self._on_command("authenticate", key_type=key_type, key_no=key_no, key=key)

        if result and result[0]:
            self._append_output(f"[OK] {result[1]}")
            self._auth_status.configure(text="Authenticated", text_color=COLORS["accent_green"])
        else:
            msg = result[1] if result else "Authentication failed"
            self._append_output(f"[FAIL] {msg}")
            self._auth_status.configure(text=msg, text_color=COLORS["accent_red"])

    def _list_files(self):
        result = self._on_command("list_files")
        if result is not None:
            self._append_output(f"--- Files ({len(result)}) ---")
            for fid in result:
                self._append_output(f"  File ID: {fid}")
        else:
            self._append_output("[FAIL] Could not list files")

    def _get_file_settings(self):
        try:
            file_no = int(self._file_no_entry.get().strip() or "0")
        except ValueError:
            self._append_output("[ERROR] Invalid file number")
            return

        result = self._on_command("file_settings", file_no=file_no)
        if result:
            self._append_output(f"--- File {file_no} Settings ---")
            for key, val in result.to_dict().items():
                self._append_output(f"  {key}: {val}")
        else:
            self._append_output(f"[FAIL] Could not get settings for file {file_no}")

    def _read_file(self):
        try:
            file_no = int(self._file_no_entry.get().strip() or "0")
        except ValueError:
            self._append_output("[ERROR] Invalid file number")
            return

        result = self._on_command("read_data", file_no=file_no)
        if result is not None:
            self._append_output(f"--- File {file_no} Data ({len(result)} bytes) ---")
            self._append_output(format_hex_dump(result))
        else:
            self._append_output(f"[FAIL] Could not read file {file_no}")

    def _read_value(self):
        try:
            file_no = int(self._file_no_entry.get().strip() or "0")
        except ValueError:
            self._append_output("[ERROR] Invalid file number")
            return

        result = self._on_command("get_value", file_no=file_no)
        if result is not None:
            self._append_output(f"--- File {file_no} Value ---")
            self._append_output(f"  Value: {result}")
        else:
            self._append_output(f"[FAIL] Could not read value from file {file_no}")

    def _read_records(self):
        try:
            file_no = int(self._file_no_entry.get().strip() or "0")
        except ValueError:
            self._append_output("[ERROR] Invalid file number")
            return

        result = self._on_command("read_records", file_no=file_no)
        if result is not None:
            self._append_output(f"--- File {file_no} Records ({len(result)} bytes) ---")
            self._append_output(format_hex_dump(result))
        else:
            self._append_output(f"[FAIL] Could not read records from file {file_no}")

    def _full_scan(self):
        self._append_output("--- Starting Full Card Scan ---")
        result = self._on_command("full_scan")
        if result and result.get("success"):
            self._append_output(self._format_scan_result(result))
        else:
            error = result.get("error", "Scan failed") if result else "Scan failed"
            self._append_output(f"[FAIL] {error}")

    def _get_version(self):
        result = self._on_command("get_version")
        if result:
            info = result.to_dict()
            self._append_output("--- Card Version ---")
            self._append_output(f"  Type: {info.get('Card Type', '?')}")
            self._append_output(f"  UID: {info.get('UID', '?')}")
        else:
            self._append_output("[FAIL] Could not get version")

    def _get_key_settings(self):
        result = self._on_command("key_settings")
        if result:
            self._append_output("--- Key Settings ---")
            for key, val in result.items():
                self._append_output(f"  {key}: {val}")
        else:
            self._append_output("[FAIL] Could not get key settings")

    def _get_free_memory(self):
        result = self._on_command("free_memory")
        if result is not None:
            self._append_output(f"Free memory: {result} bytes")
        else:
            self._append_output("[FAIL] Could not get free memory")

    def _format_scan_result(self, result: dict) -> str:
        """Format a full scan result into readable text."""
        lines = []

        version = result.get("version", {})
        lines.append(f"  Card Type: {version.get('Card Type', '?')}")
        lines.append(f"  UID: {version.get('UID', '?')}")

        if "free_memory" in result:
            lines.append(f"  Free Memory: {result['free_memory']}")

        apps = result.get("applications", [])
        lines.append(f"  Applications: {len(apps)}")
        for app in apps:
            lines.append(f"    AID: {app.get('AID', '?')}")
            files = app.get("files", {})
            for fid, finfo in files.items():
                lines.append(f"      File {fid}: {finfo.get('File Type', '?')}")
                if "Size" in finfo:
                    lines.append(f"        Size: {finfo['Size']}")

        return "\n".join(lines)
