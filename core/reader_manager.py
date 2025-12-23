"""
PC/SC Reader Manager.
Handles smart card reader enumeration, connection management,
card monitoring, and APDU transmission.
"""

import threading
import time
from typing import Callable, List, Optional, Tuple

from .apdu import APDUCommand, APDUResponse, bytes_to_hex

# Try to import pyscard
try:
    from smartcard.System import readers as list_readers
    from smartcard.CardConnection import CardConnection
    from smartcard.CardMonitoring import CardMonitor, CardObserver
    from smartcard.ReaderMonitoring import ReaderMonitor, ReaderObserver
    from smartcard.Exceptions import (
        CardConnectionException,
        NoCardException,
        NoReadersException,
    )
    from smartcard.util import toHexString
    PYSCARD_AVAILABLE = True
except ImportError:
    PYSCARD_AVAILABLE = False


class SmartCardReader:
    """Represents a connected smart card reader."""

    def __init__(self, name: str, reader_obj=None):
        self.name = name
        self._reader = reader_obj
        self._connection: Optional[CardConnection] = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    def connect(self, protocol=None) -> Tuple[bool, str]:
        """Connect to a card in this reader."""
        if not PYSCARD_AVAILABLE:
            return False, "pyscard not installed"

        try:
            self._connection = self._reader.createConnection()
            if protocol:
                self._connection.connect(protocol)
            else:
                self._connection.connect()
            self._connected = True
            return True, "Connected"
        except NoCardException:
            return False, "No card present"
        except CardConnectionException as e:
            return False, f"Connection failed: {e}"
        except Exception as e:
            return False, f"Error: {e}"

    def disconnect(self):
        """Disconnect from the card."""
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
        self._connected = False
        self._connection = None

    def get_atr(self) -> Optional[List[int]]:
        """Get the ATR of the connected card."""
        if self._connection and self._connected:
            try:
                return list(self._connection.getATR())
            except Exception:
                return None
        return None

    def transmit(self, apdu: APDUCommand) -> Optional[APDUResponse]:
        """Send an APDU command and get the response."""
        if not self._connection or not self._connected:
            return None

        try:
            data, sw1, sw2 = self._connection.transmit(apdu.to_bytes())
            return APDUResponse(list(data), sw1, sw2)
        except CardConnectionException:
            self._connected = False
            return None
        except Exception:
            return None

    def transmit_raw(self, raw_apdu: List[int]) -> Optional[APDUResponse]:
        """Send raw APDU bytes and get the response."""
        if not self._connection or not self._connected:
            return None

        try:
            data, sw1, sw2 = self._connection.transmit(raw_apdu)
            return APDUResponse(list(data), sw1, sw2)
        except CardConnectionException:
            self._connected = False
            return None
        except Exception:
            return None


class ReaderManager:
    """Manages smart card readers and card monitoring."""

    def __init__(self):
        self._readers: List[SmartCardReader] = []
        self._active_reader: Optional[SmartCardReader] = None
        self._card_monitor: Optional[CardMonitor] = None
        self._reader_monitor: Optional[ReaderMonitor] = None
        self._on_readers_changed: Optional[Callable] = None
        self._on_card_inserted: Optional[Callable] = None
        self._on_card_removed: Optional[Callable] = None
        self._monitoring = False

    @property
    def is_available(self) -> bool:
        """Check if pyscard is available."""
        return PYSCARD_AVAILABLE

    @property
    def readers(self) -> List[SmartCardReader]:
        return self._readers

    @property
    def active_reader(self) -> Optional[SmartCardReader]:
        return self._active_reader

    def refresh_readers(self) -> List[SmartCardReader]:
        """Refresh the list of available readers."""
        if not PYSCARD_AVAILABLE:
            return []

        try:
            raw_readers = list_readers()
            self._readers = [
                SmartCardReader(str(r), r) for r in raw_readers
            ]
        except NoReadersException:
            self._readers = []
        except Exception:
            self._readers = []

        return self._readers

    def select_reader(self, index: int) -> Optional[SmartCardReader]:
        """Select a reader by index."""
        if 0 <= index < len(self._readers):
            # Disconnect previous reader
            if self._active_reader and self._active_reader.is_connected:
                self._active_reader.disconnect()
            self._active_reader = self._readers[index]
            return self._active_reader
        return None

    def select_reader_by_name(self, name: str) -> Optional[SmartCardReader]:
        """Select a reader by name."""
        for i, reader in enumerate(self._readers):
            if reader.name == name:
                return self.select_reader(i)
        return None

    def connect(self) -> Tuple[bool, str]:
        """Connect to a card on the active reader."""
        if not self._active_reader:
            return False, "No reader selected"
        return self._active_reader.connect()

    def disconnect(self):
        """Disconnect from the active reader's card."""
        if self._active_reader:
            self._active_reader.disconnect()

    def get_atr(self) -> Optional[List[int]]:
        """Get ATR from the active reader."""
        if self._active_reader:
            return self._active_reader.get_atr()
        return None

    def transmit(self, apdu: APDUCommand) -> Optional[APDUResponse]:
        """Transmit an APDU through the active reader."""
        if self._active_reader:
            return self._active_reader.transmit(apdu)
        return None

    def transmit_raw(self, raw_apdu: List[int]) -> Optional[APDUResponse]:
        """Transmit raw APDU bytes through the active reader."""
        if self._active_reader:
            return self._active_reader.transmit_raw(raw_apdu)
        return None

    def start_monitoring(self,
                         on_readers_changed: Optional[Callable] = None,
                         on_card_inserted: Optional[Callable] = None,
                         on_card_removed: Optional[Callable] = None):
        """Start monitoring for reader and card changes."""
        if not PYSCARD_AVAILABLE or self._monitoring:
            return

        self._on_readers_changed = on_readers_changed
        self._on_card_inserted = on_card_inserted
        self._on_card_removed = on_card_removed

        try:
            # Card monitor
            self._card_monitor = CardMonitor()
            observer = _CardObserverCallback(
                on_inserted=self._handle_card_inserted,
                on_removed=self._handle_card_removed
            )
            self._card_monitor.addObserver(observer)

            # Reader monitor
            self._reader_monitor = ReaderMonitor()
            reader_observer = _ReaderObserverCallback(
                on_changed=self._handle_readers_changed
            )
            self._reader_monitor.addObserver(reader_observer)

            self._monitoring = True
        except Exception:
            pass

    def stop_monitoring(self):
        """Stop monitoring."""
        self._monitoring = False
        try:
            if self._card_monitor:
                self._card_monitor.deleteObservers()
                self._card_monitor = None
            if self._reader_monitor:
                self._reader_monitor.deleteObservers()
                self._reader_monitor = None
        except Exception:
            pass

    def _handle_card_inserted(self, cards):
        if self._on_card_inserted:
            self._on_card_inserted(cards)

    def _handle_card_removed(self, cards):
        if self._on_card_removed:
            self._on_card_removed(cards)

    def _handle_readers_changed(self, added, removed):
        self.refresh_readers()
        if self._on_readers_changed:
            self._on_readers_changed(added, removed)

    def cleanup(self):
        """Clean up all connections and monitors."""
        self.stop_monitoring()
        if self._active_reader:
            self._active_reader.disconnect()


# ─── Internal Observer Callbacks ────────────────────────────────────────────

class _CardObserverCallback(CardObserver if PYSCARD_AVAILABLE else object):
    """Card insertion/removal observer."""

    def __init__(self, on_inserted=None, on_removed=None):
        if PYSCARD_AVAILABLE:
            super().__init__()
        self._on_inserted = on_inserted
        self._on_removed = on_removed

    def update(self, observable, actions):
        added_cards, removed_cards = actions
        if added_cards and self._on_inserted:
            self._on_inserted(added_cards)
        if removed_cards and self._on_removed:
            self._on_removed(removed_cards)


class _ReaderObserverCallback(ReaderObserver if PYSCARD_AVAILABLE else object):
    """Reader addition/removal observer."""

    def __init__(self, on_changed=None):
        if PYSCARD_AVAILABLE:
            super().__init__()
        self._on_changed = on_changed

    def update(self, observable, actions):
        added_readers, removed_readers = actions
        if self._on_changed:
            self._on_changed(added_readers, removed_readers)
