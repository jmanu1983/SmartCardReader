"""
Main Application Window.
Orchestrates all UI components and connects them to the core modules.
"""

import threading
import customtkinter as ctk
from typing import Optional

from .theme import COLORS, FONTS, PADDING, DIMENSIONS
from .reader_panel import ReaderPanel
from .card_info_view import CardInfoView
from .desfire_view import DESFireView
from .javacard_view import JavaCardView
from .diversification_view import DiversificationView
from .legic_view import LegicView
from .apdu_console import APDUConsole
from .log_panel import LogPanel

from core.reader_manager import ReaderManager
from core.atr_parser import ATRInfo
from core.desfire import DESFireProtocol
from core.javacard import JavaCardHandler
from core.legic import LegicHandler
from core.apdu import bytes_to_hex, hex_to_bytes


class SmartCardApp(ctk.CTk):
    """Main application window."""

    def __init__(self):
        super().__init__()

        # Window config
        self.title("Smart Card Reader — by jmanu1983")
        self.geometry("1280x850")
        self.minsize(1024, 700)

        # Theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.configure(fg_color=COLORS["bg_main"])

        # Core modules
        self._reader_mgr = ReaderManager()
        self._desfire: Optional[DESFireProtocol] = None
        self._javacard: Optional[JavaCardHandler] = None
        self._legic: Optional[LegicHandler] = None
        self._current_atr: Optional[ATRInfo] = None
        self._current_uid: list = []

        # Build UI
        self._build_ui()

        # Initial reader scan
        self.after(500, self._refresh_readers)

        # Start monitoring
        self._reader_mgr.start_monitoring(
            on_card_inserted=self._on_card_event,
            on_card_removed=self._on_card_event,
            on_readers_changed=self._on_reader_change
        )

        # Cleanup on close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self):
        """Build the main application layout."""
        # Main container
        main_container = ctk.CTkFrame(self, fg_color="transparent")
        main_container.pack(fill="both", expand=True)

        # ─── Sidebar (Reader Panel) ────────────────────────────────
        self._reader_panel = ReaderPanel(
            main_container,
            on_reader_selected=self._on_reader_selected,
            on_connect=self._connect_card,
            on_disconnect=self._disconnect_card,
            on_refresh=self._refresh_readers
        )
        self._reader_panel.pack(side="left", fill="y")

        # ─── Right Content Area ─────────────────────────────────────
        right_area = ctk.CTkFrame(main_container, fg_color="transparent")
        right_area.pack(side="left", fill="both", expand=True)

        # ─── Tabview ────────────────────────────────────────────────
        self._tabview = ctk.CTkTabview(
            right_area,
            fg_color=COLORS["bg_main"],
            segmented_button_fg_color=COLORS["bg_elevated"],
            segmented_button_selected_color=COLORS["accent_blue"],
            segmented_button_selected_hover_color="#5D8AF0",
            segmented_button_unselected_color=COLORS["bg_elevated"],
            segmented_button_unselected_hover_color=COLORS["sidebar_hover"],
            text_color=COLORS["text_bright"],
            text_color_disabled=COLORS["text_muted"],
            corner_radius=DIMENSIONS["corner_radius"]
        )
        self._tabview.pack(fill="both", expand=True, padx=PADDING["sm"], pady=(PADDING["sm"], 0))

        # Create tabs
        tab_card = self._tabview.add("Card Info")
        tab_desfire = self._tabview.add("DESFire")
        tab_javacard = self._tabview.add("JavaCard")
        tab_legic = self._tabview.add("LEGIC")
        tab_diversification = self._tabview.add("Diversification")
        tab_console = self._tabview.add("APDU Console")

        # Tab content
        self._card_info_view = CardInfoView(tab_card)
        self._card_info_view.pack(fill="both", expand=True)

        self._desfire_view = DESFireView(tab_desfire, self._handle_desfire_command)
        self._desfire_view.pack(fill="both", expand=True)

        self._javacard_view = JavaCardView(tab_javacard, self._handle_javacard_command)
        self._javacard_view.pack(fill="both", expand=True)

        self._legic_view = LegicView(tab_legic, self._handle_legic_command)
        self._legic_view.pack(fill="both", expand=True)

        self._diversification_view = DiversificationView(
            tab_diversification, self._get_current_uid
        )
        self._diversification_view.pack(fill="both", expand=True)

        self._apdu_console = APDUConsole(tab_console, self._transmit_raw)
        self._apdu_console.pack(fill="both", expand=True)

        # ─── Log Panel ──────────────────────────────────────────────
        self._log = LogPanel(right_area)
        self._log.pack(fill="x", side="bottom")

        self._log.info("Smart Card Reader started")
        if not self._reader_mgr.is_available:
            self._log.error("pyscard not found! Install with: pip install pyscard")

    # ─── Reader Management ──────────────────────────────────────────────

    def _refresh_readers(self):
        """Refresh the reader list."""
        readers = self._reader_mgr.refresh_readers()
        names = [r.name for r in readers]
        self._reader_panel.update_readers(names)
        self._log.info(f"Found {len(readers)} reader(s)")

    def _on_reader_selected(self, index: int):
        """Handle reader selection."""
        reader = self._reader_mgr.select_reader(index)
        if reader:
            self._log.info(f"Selected: {reader.name}")

    def _on_card_event(self, cards):
        """Handle card insertion/removal events."""
        self.after(100, self._refresh_readers)

    def _on_reader_change(self, added, removed):
        """Handle reader addition/removal."""
        self.after(100, self._refresh_readers)

    def _connect_card(self):
        """Connect to the card on the selected reader."""
        success, msg = self._reader_mgr.connect()
        if success:
            self._log.success(f"Connected: {msg}")

            # Get ATR
            atr = self._reader_mgr.get_atr()
            if atr:
                self._current_atr = ATRInfo(atr)
                self._log.info(f"ATR: {self._current_atr.hex}")
                self._log.info(f"Card: {self._current_atr}")

                # Update card info view
                self._card_info_view.update_atr_info(self._current_atr)

                # Initialize protocol handlers
                self._desfire = DESFireProtocol(self._reader_mgr.transmit)
                self._javacard = JavaCardHandler(self._reader_mgr.transmit)
                self._legic = LegicHandler(self._reader_mgr.transmit)

                # Auto-detect DESFire
                if self._current_atr.card_family in ("desfire", "mifare", "iso14443a"):
                    self._auto_read_desfire()

                self._reader_panel.set_status(True, "Connected", str(self._current_atr.card_type))
            else:
                self._reader_panel.set_status(True, "Connected")
        else:
            self._log.error(f"Connection failed: {msg}")
            self._reader_panel.set_status(False, msg)

    def _disconnect_card(self):
        """Disconnect from the card."""
        self._reader_mgr.disconnect()
        self._desfire = None
        self._javacard = None
        self._legic = None
        self._current_atr = None
        self._current_uid = []
        self._reader_panel.set_status(False)
        self._card_info_view.clear()
        self._log.info("Disconnected")

    def _auto_read_desfire(self):
        """Automatically read DESFire card info after connection."""
        if not self._desfire:
            return

        def _read():
            try:
                version = self._desfire.get_version()
                if version:
                    self._current_uid = version.uid
                    free_mem = self._desfire.get_free_memory()
                    aids = self._desfire.get_application_ids()

                    apps_info = []
                    if aids:
                        for aid in aids:
                            app = {"AID": bytes_to_hex(aid)}
                            if self._desfire.select_application(aid):
                                ks = self._desfire.get_key_settings()
                                if ks:
                                    app["key_settings"] = ks
                                fids = self._desfire.get_file_ids()
                                if fids:
                                    app["files"] = {}
                                    for fid in fids:
                                        fs = self._desfire.get_file_settings(fid)
                                        if fs:
                                            app["files"][fid] = fs.to_dict()
                            apps_info.append(app)
                        self._desfire.select_picc()

                    # Update UI on main thread
                    self.after(0, lambda: self._update_desfire_ui(version, free_mem, apps_info))
            except Exception as e:
                self.after(0, lambda: self._log.error(f"Auto-read failed: {e}"))

        threading.Thread(target=_read, daemon=True).start()

    def _update_desfire_ui(self, version, free_mem, apps):
        """Update UI with DESFire info (called on main thread)."""
        self._card_info_view.update_desfire_info(version, free_mem)
        self._card_info_view.update_applications(apps)
        self._log.success(f"Card: {version.card_type} | UID: {version.uid_hex}")
        self._reader_panel.set_status(True, "Connected", version.card_type)

    # ─── DESFire Command Handler ────────────────────────────────────────

    def _handle_desfire_command(self, command: str, **kwargs):
        """Handle commands from the DESFire view."""
        if not self._desfire:
            self._log.error("Not connected to a DESFire card")
            return None

        try:
            if command == "get_version":
                result = self._desfire.get_version()
                if result:
                    self._current_uid = result.uid
                return result

            elif command == "list_apps":
                return self._desfire.get_application_ids()

            elif command == "select_app":
                return self._desfire.select_application(kwargs["aid"])

            elif command == "select_picc":
                return self._desfire.select_picc()

            elif command == "authenticate":
                key_type = kwargs["key_type"]
                key_no = kwargs["key_no"]
                key = kwargs["key"]

                if key_type == "DES":
                    return self._desfire.authenticate_legacy(key_no, key[:8])
                elif key_type == "2K3DES":
                    return self._desfire.authenticate_legacy(key_no, key[:16])
                elif key_type == "3K3DES":
                    return self._desfire.authenticate_iso(key_no, key[:24])
                elif key_type == "AES-128":
                    return self._desfire.authenticate_aes(key_no, key[:16])

            elif command == "list_files":
                return self._desfire.get_file_ids()

            elif command == "file_settings":
                return self._desfire.get_file_settings(kwargs["file_no"])

            elif command == "read_data":
                return self._desfire.read_data(kwargs["file_no"])

            elif command == "get_value":
                return self._desfire.get_value(kwargs["file_no"])

            elif command == "read_records":
                return self._desfire.read_records(kwargs["file_no"])

            elif command == "key_settings":
                return self._desfire.get_key_settings()

            elif command == "free_memory":
                return self._desfire.get_free_memory()

            elif command == "full_scan":
                return self._desfire.scan_card()

        except Exception as e:
            self._log.error(f"DESFire command error: {e}")
            return None

    # ─── JavaCard Command Handler ───────────────────────────────────────

    def _handle_javacard_command(self, command: str, **kwargs):
        """Handle commands from the JavaCard view."""
        if not self._javacard:
            self._log.error("Not connected to a card")
            return None

        try:
            if command == "jc_select":
                return self._javacard.select_applet(kwargs["aid"])

            elif command == "jc_probe":
                return self._javacard.probe_known_aids()

            elif command == "jc_cplc":
                return self._javacard.get_cplc()

            elif command == "jc_ndef":
                return self._javacard.read_ndef()

            elif command == "jc_apdu":
                return self._javacard.send_apdu(
                    kwargs["cla"], kwargs["ins"],
                    kwargs["p1"], kwargs["p2"],
                    kwargs.get("data"), kwargs.get("le")
                )

            elif command == "jc_raw":
                return self._javacard.send_raw_apdu(kwargs["apdu"])

        except Exception as e:
            self._log.error(f"JavaCard command error: {e}")
            return None

    # ─── LEGIC Command Handler ──────────────────────────────────────────

    def _handle_legic_command(self, command: str, **kwargs):
        """Handle commands from the LEGIC view."""
        if not self._legic:
            self._log.error("Not connected to a card")
            return None

        try:
            if command == "legic_info":
                result = self._legic.get_card_info()
                if result.get("uid"):
                    self._log.info(f"LEGIC UID: {result.get('uid_hex', '?')}")
                return result

            elif command == "legic_uid":
                return self._legic.get_uid()

            elif command == "legic_detect":
                atr = self._reader_mgr.get_atr() or []
                return self._legic.detect_card_type(atr)

            elif command == "legic_ats":
                return self._legic.get_ats()

            elif command == "legic_read":
                return self._legic.read_memory(
                    kwargs.get("offset", 0),
                    kwargs.get("length", 16)
                )

        except Exception as e:
            self._log.error(f"LEGIC command error: {e}")
            return None

    # ─── Utility ────────────────────────────────────────────────────────

    def _transmit_raw(self, raw_apdu: list):
        """Transmit raw APDU bytes (for console)."""
        return self._reader_mgr.transmit_raw(raw_apdu)

    def _get_current_uid(self) -> list:
        """Get the current card UID (for diversification view)."""
        if self._current_uid:
            return self._current_uid
        # Try to read from card
        if self._desfire:
            version = self._desfire.get_version()
            if version:
                self._current_uid = version.uid
                return self._current_uid
        return []

    def _on_close(self):
        """Clean up on window close."""
        self._reader_mgr.cleanup()
        self.destroy()
