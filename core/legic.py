"""
LEGIC card technology handler.
Supports LEGIC Prime (MIM256, MIM1024) and LEGIC Advant (ATC) cards.

IMPORTANT: LEGIC is a proprietary technology by LEGIC Identsystems (Switzerland).
Reading LEGIC cards requires a LEGIC-compatible reader such as:
  - Elatec TWN4 MultiTech LEGIC
  - Elatec TWN4 MultiTech 3 LEGIC M
  - Readers with LEGIC SM-6300/SM-6310 reader IC

Standard NFC/MIFARE readers (ACR122U, OMNIKEY 5321, etc.) CANNOT read LEGIC cards.
"""

from typing import Dict, List, Optional, Tuple
from .apdu import APDUCommand, APDUResponse, bytes_to_hex, hex_to_bytes


# ─── LEGIC Card Types ───────────────────────────────────────────────────────

class LegicCardType:
    """LEGIC card type identifiers."""
    PRIME_MIM22 = "LEGIC Prime MIM22"
    PRIME_MIM256 = "LEGIC Prime MIM256"
    PRIME_MIM1024 = "LEGIC Prime MIM1024"
    ADVANT_ATC256 = "LEGIC Advant ATC256"
    ADVANT_ATC1024 = "LEGIC Advant ATC1024"
    ADVANT_ATC2048 = "LEGIC Advant ATC2048"
    ADVANT_ATC4096 = "LEGIC Advant ATC4096"
    ADVANT_CTC4096 = "LEGIC Advant CTC4096"
    UNKNOWN = "LEGIC Unknown"


# LEGIC Prime memory layout
LEGIC_PRIME_INFO = {
    LegicCardType.PRIME_MIM22: {
        "memory_bytes": 22,
        "segments": 0,
        "description": "LEGIC Prime MIM22 - 22 bytes, read-only UID token",
        "features": ["UID only", "No segments", "Read-only"],
    },
    LegicCardType.PRIME_MIM256: {
        "memory_bytes": 256,
        "segments": "Up to 8",
        "description": "LEGIC Prime MIM256 - 256 bytes, segmented memory",
        "features": ["Segmented memory", "Master Token auth", "Read/Write"],
    },
    LegicCardType.PRIME_MIM1024: {
        "memory_bytes": 1024,
        "segments": "Up to 8",
        "description": "LEGIC Prime MIM1024 - 1024 bytes, segmented memory",
        "features": ["Segmented memory", "Master Token auth", "Read/Write", "Extended storage"],
    },
}

# LEGIC Advant memory layout
LEGIC_ADVANT_INFO = {
    LegicCardType.ADVANT_ATC256: {
        "memory_bytes": 256,
        "stamp_files": "Up to 7",
        "description": "LEGIC Advant ATC256 - 256 bytes, 13.56 MHz contactless",
        "features": ["Stamp/File system", "Mutual auth", "AES encryption", "ISO 14443"],
    },
    LegicCardType.ADVANT_ATC1024: {
        "memory_bytes": 1024,
        "stamp_files": "Up to 7",
        "description": "LEGIC Advant ATC1024 - 1024 bytes",
        "features": ["Stamp/File system", "Mutual auth", "AES encryption", "ISO 14443"],
    },
    LegicCardType.ADVANT_ATC2048: {
        "memory_bytes": 2048,
        "stamp_files": "Up to 7",
        "description": "LEGIC Advant ATC2048 - 2048 bytes",
        "features": ["Stamp/File system", "Mutual auth", "AES encryption", "ISO 14443"],
    },
    LegicCardType.ADVANT_ATC4096: {
        "memory_bytes": 4096,
        "stamp_files": "Up to 7",
        "description": "LEGIC Advant ATC4096 - 4096 bytes",
        "features": ["Stamp/File system", "Mutual auth", "AES encryption", "ISO 14443"],
    },
    LegicCardType.ADVANT_CTC4096: {
        "memory_bytes": 4096,
        "stamp_files": "Up to 7",
        "description": "LEGIC Advant CTC4096 - 4096 bytes, dual interface (contact + contactless)",
        "features": ["Stamp/File system", "Mutual auth", "AES encryption", "ISO 14443", "ISO 7816 contact"],
    },
}


# ─── Compatible Readers ─────────────────────────────────────────────────────

COMPATIBLE_READERS = [
    {
        "name": "Elatec TWN4 MultiTech 3 LEGIC M",
        "order_code": "T43O-B7C0",
        "frequencies": "125 kHz + 13.56 MHz",
        "interface": "USB (PC/SC 2.01, CCID)",
        "legic_support": "Prime + Advant",
        "other_techs": "MIFARE, DESFire, ISO14443A/B, ISO15693, NFC, HID iCLASS",
    },
    {
        "name": "Elatec TWN4 MultiTech LEGIC",
        "order_code": "T4DT-FB2BEL-P",
        "frequencies": "125 kHz + 13.56 MHz",
        "interface": "USB (PC/SC 2.01, CCID, HID Keyboard)",
        "legic_support": "Prime + Advant",
        "other_techs": "MIFARE, DESFire, ISO14443A/B, ISO15693, NFC, EM4x",
    },
    {
        "name": "Elatec TWN4 MultiTech 2 LEGIC",
        "order_code": "T4BT-FB2BEL",
        "frequencies": "125 kHz + 13.56 MHz",
        "interface": "USB (PC/SC 2.01, CCID)",
        "legic_support": "Prime + Advant",
        "other_techs": "MIFARE, DESFire, ISO14443A/B, ISO15693, NFC",
    },
]


# ─── LEGIC Protocol Handler ─────────────────────────────────────────────────

class LegicHandler:
    """
    LEGIC card handler.
    Communicates with LEGIC cards through LEGIC-compatible PC/SC readers.

    Note: LEGIC communication through PC/SC typically uses transparent
    APDU commands specific to the reader firmware (e.g., Elatec TWN4).
    The actual LEGIC protocol is handled by the reader's LEGIC IC.
    """

    def __init__(self, transmit_func):
        """
        Args:
            transmit_func: Function that takes APDUCommand and returns APDUResponse.
        """
        self._transmit = transmit_func
        self._card_type = None
        self._uid = None

    @property
    def card_type(self) -> Optional[str]:
        return self._card_type

    @property
    def uid(self) -> Optional[List[int]]:
        return self._uid

    def get_uid(self) -> Optional[List[int]]:
        """
        Get the LEGIC card UID.
        Uses the standard PC/SC GET UID command (works with most readers).
        """
        # Standard PC/SC pseudo-APDU to get UID
        cmd = APDUCommand(0xFF, 0xCA, 0x00, 0x00, le=0x00)
        response = self._transmit(cmd)
        if response and response.sw == 0x9000 and response.data:
            self._uid = response.data
            return response.data
        return None

    def get_ats(self) -> Optional[List[int]]:
        """
        Get the Answer To Select (ATS) for ISO 14443-4 cards.
        LEGIC Advant cards support ISO 14443 and may return ATS.
        """
        cmd = APDUCommand(0xFF, 0xCA, 0x01, 0x00, le=0x00)
        response = self._transmit(cmd)
        if response and response.sw == 0x9000 and response.data:
            return response.data
        return None

    def detect_card_type(self, atr_bytes: List[int]) -> str:
        """
        Detect LEGIC card type from ATR and card responses.
        The ATR alone may not identify LEGIC specifically; the reader
        firmware typically identifies the card type.
        """
        uid = self.get_uid()

        if uid:
            uid_len = len(uid)
            # LEGIC Prime has specific UID patterns
            # LEGIC Prime MIM22/MIM256/MIM1024: typically shorter UIDs
            # LEGIC Advant: 7-byte UIDs common

            if uid_len == 4:
                # Could be LEGIC Prime
                self._card_type = LegicCardType.PRIME_MIM256
            elif uid_len == 7:
                # Likely LEGIC Advant
                self._card_type = LegicCardType.ADVANT_ATC1024
            else:
                self._card_type = LegicCardType.UNKNOWN
        else:
            self._card_type = LegicCardType.UNKNOWN

        return self._card_type

    def read_memory(self, offset: int = 0, length: int = 16) -> Optional[List[int]]:
        """
        Read card memory at the given offset.
        Uses transparent read commands via PC/SC.

        Note: Actual LEGIC memory reading depends on the reader firmware
        and whether authentication has been performed.
        """
        # Standard read binary (works for some reader configurations)
        p1 = (offset >> 8) & 0xFF
        p2 = offset & 0xFF
        cmd = APDUCommand(0xFF, 0xB0, p1, p2, le=length)
        response = self._transmit(cmd)
        if response and response.sw == 0x9000:
            return response.data

        # Alternative: Use UPDATE/READ with CLA=0xFF (reader-specific)
        cmd = APDUCommand(0xFF, 0xB0, p1, p2, le=min(length, 0xFF))
        response = self._transmit(cmd)
        if response and response.sw == 0x9000:
            return response.data

        return None

    def write_memory(self, offset: int, data: List[int]) -> bool:
        """
        Write data to card memory at the given offset.
        Requires appropriate authentication/authorization.
        """
        p1 = (offset >> 8) & 0xFF
        p2 = offset & 0xFF
        cmd = APDUCommand(0xFF, 0xD6, p1, p2, data=data)
        response = self._transmit(cmd)
        return response is not None and response.sw == 0x9000

    def get_card_info(self) -> Dict:
        """
        Get comprehensive LEGIC card information.
        Returns a dictionary with all available card data.
        """
        info = {
            "technology": "LEGIC",
            "card_type": "Unknown",
            "uid": None,
            "uid_hex": None,
            "memory_info": {},
            "features": [],
        }

        # Get UID
        uid = self.get_uid()
        if uid:
            info["uid"] = uid
            info["uid_hex"] = bytes_to_hex(uid)

        # Detect card type
        card_type = self._card_type or LegicCardType.UNKNOWN
        info["card_type"] = card_type

        # Get memory info
        if card_type in LEGIC_PRIME_INFO:
            mem_info = LEGIC_PRIME_INFO[card_type]
            info["memory_info"] = {
                "Memory Size": f"{mem_info['memory_bytes']} bytes",
                "Max Segments": mem_info["segments"],
                "Description": mem_info["description"],
            }
            info["features"] = mem_info["features"]
            info["family"] = "LEGIC Prime"

        elif card_type in LEGIC_ADVANT_INFO:
            mem_info = LEGIC_ADVANT_INFO[card_type]
            info["memory_info"] = {
                "Memory Size": f"{mem_info['memory_bytes']} bytes",
                "Max Stamp Files": mem_info["stamp_files"],
                "Description": mem_info["description"],
            }
            info["features"] = mem_info["features"]
            info["family"] = "LEGIC Advant"

        # Try to read first bytes
        first_bytes = self.read_memory(0, 16)
        if first_bytes:
            info["first_bytes"] = bytes_to_hex(first_bytes)

        # Get ATS for Advant cards
        ats = self.get_ats()
        if ats:
            info["ats"] = bytes_to_hex(ats)

        return info

    @staticmethod
    def get_compatible_readers() -> List[Dict]:
        """Return list of LEGIC-compatible readers."""
        return COMPATIBLE_READERS

    @staticmethod
    def get_technology_info() -> Dict:
        """Return general information about LEGIC technology."""
        return {
            "name": "LEGIC",
            "manufacturer": "LEGIC Identsystems AG (Switzerland)",
            "frequency": "13.56 MHz",
            "standards": ["Proprietary (Prime)", "ISO 14443 (Advant)"],
            "card_families": {
                "LEGIC Prime": {
                    "description": "Proprietary contactless technology",
                    "cards": ["MIM22 (22 bytes)", "MIM256 (256 bytes)", "MIM1024 (1024 bytes)"],
                    "security": "Master Token authentication, proprietary encryption",
                    "frequency": "13.56 MHz",
                    "note": "Fully proprietary protocol - requires LEGIC reader IC",
                },
                "LEGIC Advant": {
                    "description": "Modern contactless technology with ISO 14443 support",
                    "cards": [
                        "ATC256 (256 bytes)", "ATC1024 (1024 bytes)",
                        "ATC2048 (2048 bytes)", "ATC4096 (4096 bytes)",
                        "CTC4096 (4096 bytes, dual interface)",
                    ],
                    "security": "Mutual authentication, AES-128 encryption",
                    "frequency": "13.56 MHz",
                    "note": "ISO 14443 compliant but with proprietary data structure (Stamps/Files)",
                },
            },
            "important_note": (
                "LEGIC cards CANNOT be read with standard NFC/MIFARE readers "
                "(ACR122U, OMNIKEY, etc.). You need a reader with a LEGIC reader IC, "
                "such as the Elatec TWN4 MultiTech LEGIC series."
            ),
        }
