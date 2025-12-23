"""
Card Information View.
Displays general card information: ATR, card type, version details.
"""

import customtkinter as ctk
from typing import Dict, Optional

from .theme import COLORS, FONTS, PADDING, DIMENSIONS


class InfoRow(ctk.CTkFrame):
    """A single key-value row for displaying card info."""

    def __init__(self, parent, label: str, value: str = "",
                 value_color: str = None, mono: bool = False):
        super().__init__(parent, fg_color="transparent", height=28)
        self.pack_propagate(False)

        ctk.CTkLabel(
            self,
            text=label,
            font=FONTS["small_bold"],
            text_color=COLORS["text_muted"],
            width=160,
            anchor="w"
        ).pack(side="left")

        self._value_label = ctk.CTkLabel(
            self,
            text=value,
            font=FONTS["mono_small"] if mono else FONTS["small"],
            text_color=value_color or COLORS["text_primary"],
            anchor="w"
        )
        self._value_label.pack(side="left", fill="x", expand=True)

    def set_value(self, value: str, color: str = None):
        self._value_label.configure(
            text=value,
            text_color=color or COLORS["text_primary"]
        )


class InfoSection(ctk.CTkFrame):
    """A section with a header and rows of information."""

    def __init__(self, parent, title: str):
        super().__init__(parent, fg_color=COLORS["bg_card"], corner_radius=DIMENSIONS["corner_radius"])

        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=PADDING["lg"], pady=(PADDING["md"], PADDING["xs"]))

        ctk.CTkLabel(
            header,
            text=title,
            font=FONTS["body_bold"],
            text_color=COLORS["accent_blue"]
        ).pack(anchor="w")

        # Content area
        self._content = ctk.CTkFrame(self, fg_color="transparent")
        self._content.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

        self._rows: Dict[str, InfoRow] = {}

    def add_row(self, key: str, value: str = "", value_color: str = None, mono: bool = False) -> InfoRow:
        row = InfoRow(self._content, key, value, value_color, mono)
        row.pack(fill="x", pady=1)
        self._rows[key] = row
        return row

    def set_value(self, key: str, value: str, color: str = None):
        if key in self._rows:
            self._rows[key].set_value(value, color)

    def clear(self):
        for row in self._rows.values():
            row.set_value("")
        

class CardInfoView(ctk.CTkFrame):
    """Card information display tab."""

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")

        self._build_ui()

    def _build_ui(self):
        """Build the card info view."""
        # Scrollable content
        scroll = ctk.CTkScrollableFrame(
            self,
            fg_color="transparent",
            scrollbar_button_color=COLORS["bg_elevated"],
            scrollbar_button_hover_color=COLORS["accent_blue"]
        )
        scroll.pack(fill="both", expand=True, padx=PADDING["lg"], pady=PADDING["md"])

        # ─── ATR Section ────────────────────────────────────────────
        self._atr_section = InfoSection(scroll, "ATR (Answer To Reset)")
        self._atr_section.pack(fill="x", pady=(0, PADDING["md"]))
        self._atr_section.add_row("ATR", mono=True)
        self._atr_section.add_row("Card Type")
        self._atr_section.add_row("Subtype")
        self._atr_section.add_row("Protocol")
        self._atr_section.add_row("Historical Bytes", mono=True)

        # ─── DESFire Version Section ────────────────────────────────
        self._version_section = InfoSection(scroll, "DESFire Version Info")
        self._version_section.pack(fill="x", pady=(0, PADDING["md"]))
        self._version_section.add_row("Card Type")
        self._version_section.add_row("UID", mono=True)
        self._version_section.add_row("Storage Size")
        self._version_section.add_row("Free Memory")

        # ─── Hardware Section ───────────────────────────────────────
        self._hw_section = InfoSection(scroll, "Hardware Info")
        self._hw_section.pack(fill="x", pady=(0, PADDING["md"]))
        self._hw_section.add_row("Vendor")
        self._hw_section.add_row("Type / Subtype")
        self._hw_section.add_row("Version")
        self._hw_section.add_row("Storage")
        self._hw_section.add_row("Protocol")

        # ─── Software Section ───────────────────────────────────────
        self._sw_section = InfoSection(scroll, "Software Info")
        self._sw_section.pack(fill="x", pady=(0, PADDING["md"]))
        self._sw_section.add_row("Vendor")
        self._sw_section.add_row("Type / Subtype")
        self._sw_section.add_row("Version")
        self._sw_section.add_row("Storage")
        self._sw_section.add_row("Protocol")

        # ─── Production Section ─────────────────────────────────────
        self._prod_section = InfoSection(scroll, "Production Info")
        self._prod_section.pack(fill="x", pady=(0, PADDING["md"]))
        self._prod_section.add_row("Batch No.", mono=True)
        self._prod_section.add_row("Production Week")
        self._prod_section.add_row("Production Year")

        # ─── Applications Overview ──────────────────────────────────
        self._apps_section = InfoSection(scroll, "Applications")
        self._apps_section.pack(fill="x", pady=(0, PADDING["md"]))
        self._apps_section.add_row("Count")
        self._apps_text = ctk.CTkTextbox(
            self._apps_section,
            height=120,
            font=FONTS["mono_small"],
            fg_color=COLORS["bg_input"],
            text_color=COLORS["text_primary"],
            border_color=COLORS["border"],
            border_width=1,
            corner_radius=6
        )
        self._apps_text.pack(fill="x", padx=PADDING["lg"], pady=(0, PADDING["md"]))

    def update_atr_info(self, atr_info):
        """Update ATR section from ATRInfo object."""
        info = atr_info.to_dict()
        self._atr_section.set_value("ATR", info.get("ATR", ""), COLORS["accent_cyan"])
        self._atr_section.set_value("Card Type", info.get("Card Type", ""))
        self._atr_section.set_value("Subtype", info.get("Card Subtype", ""))
        self._atr_section.set_value("Protocol", info.get("Protocol", ""))
        self._atr_section.set_value("Historical Bytes", info.get("Historical Bytes", ""))

    def update_desfire_info(self, version_info, free_memory=None):
        """Update DESFire version sections from DESFireVersionInfo."""
        if not version_info:
            return

        info = version_info.to_dict()

        # Version section
        self._version_section.set_value("Card Type", info.get("Card Type", ""), COLORS["accent_green"])
        self._version_section.set_value("UID", version_info.uid_hex, COLORS["accent_cyan"])
        self._version_section.set_value("Storage Size", version_info.storage_size)
        if free_memory is not None:
            self._version_section.set_value("Free Memory", f"{free_memory} bytes")

        # Hardware
        hw = info.get("Hardware", {})
        self._hw_section.set_value("Vendor", hw.get("Vendor", ""))
        self._hw_section.set_value("Type / Subtype", f"{hw.get('Type', '')} / {hw.get('Subtype', '')}")
        self._hw_section.set_value("Version", hw.get("Version", ""))
        self._hw_section.set_value("Storage", hw.get("Storage", ""))
        self._hw_section.set_value("Protocol", hw.get("Protocol", ""))

        # Software
        sw = info.get("Software", {})
        self._sw_section.set_value("Vendor", sw.get("Vendor", ""))
        self._sw_section.set_value("Type / Subtype", f"{sw.get('Type', '')} / {sw.get('Subtype', '')}")
        self._sw_section.set_value("Version", sw.get("Version", ""))
        self._sw_section.set_value("Storage", sw.get("Storage", ""))
        self._sw_section.set_value("Protocol", sw.get("Protocol", ""))

        # Production
        prod = info.get("Production", {})
        self._prod_section.set_value("Batch No.", str(prod.get("Batch", "")))
        self._prod_section.set_value("Production Week", str(prod.get("Week", "")))
        self._prod_section.set_value("Production Year", str(prod.get("Year", "")))

    def update_applications(self, apps_list):
        """Update the applications section."""
        if apps_list is None:
            self._apps_section.set_value("Count", "N/A")
            return

        self._apps_section.set_value("Count", str(len(apps_list)), COLORS["accent_blue"])

        self._apps_text.configure(state="normal")
        self._apps_text.delete("1.0", "end")

        for app in apps_list:
            aid_str = app.get("AID", "?")
            self._apps_text.insert("end", f"AID: {aid_str}\n")

            ks = app.get("key_settings")
            if ks:
                self._apps_text.insert("end", f"  Key Type: {ks.get('Key Type', '?')}")
                self._apps_text.insert("end", f"  Max Keys: {ks.get('Max Keys', '?')}\n")

            files = app.get("files", {})
            if files:
                self._apps_text.insert("end", f"  Files: {list(files.keys())}\n")
                for fid, finfo in files.items():
                    self._apps_text.insert("end", f"    File {fid}: {finfo.get('File Type', '?')}")
                    if "Size" in finfo:
                        self._apps_text.insert("end", f" ({finfo['Size']})")
                    self._apps_text.insert("end", "\n")
            self._apps_text.insert("end", "\n")

        self._apps_text.configure(state="disabled")

    def clear(self):
        """Clear all displayed information."""
        self._atr_section.clear()
        self._version_section.clear()
        self._hw_section.clear()
        self._sw_section.clear()
        self._prod_section.clear()
        self._apps_section.clear()
        self._apps_text.configure(state="normal")
        self._apps_text.delete("1.0", "end")
        self._apps_text.configure(state="disabled")
