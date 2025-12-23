"""
ATR (Answer To Reset) parser.
Identifies card types from ATR bytes following ISO 7816-3.
"""

from typing import Dict, List, Optional
from .apdu import bytes_to_hex


# Known ATR patterns for common card types
ATR_DATABASE = {
    # DESFire
    "3B 81 80 01 80 80": {
        "type": "DESFire",
        "subtype": "MIFARE DESFire",
        "family": "desfire"
    },
    "3B 81 80 01 80 80 00": {
        "type": "DESFire",
        "subtype": "MIFARE DESFire (contactless)",
        "family": "desfire"
    },

    # DESFire EV1
    "3B 81 80 01 80 80": {
        "type": "DESFire EV1",
        "subtype": "MIFARE DESFire EV1",
        "family": "desfire"
    },

    # Generic NXP contactless
    "3B 8F 80 01 80 4F 0C A0 00 00 03 06": {
        "type": "NXP MIFARE",
        "subtype": "MIFARE (ISO 14443-4)",
        "family": "mifare"
    },

    # JCOP cards
    "3B F8 13 00 00 81 31 FE 45 4A 43 4F 50 76 32 34 31": {
        "type": "JavaCard",
        "subtype": "NXP JCOP v2.4.1",
        "family": "javacard"
    },

    # Gemalto
    "3B 7D 94 00 00 80 31 80 65 B0 83 11 00 AC 83 00 90 00": {
        "type": "JavaCard",
        "subtype": "Gemalto IDPrime",
        "family": "javacard"
    },

    # Generic contact cards
    "3B 9F 95 81 31 FE 9F 00 65 46 53 05 10 06 71 DF 00 00 00 00 00 00 0F": {
        "type": "JavaCard",
        "subtype": "Feitian JavaCard",
        "family": "javacard"
    },
}

# ATR prefix patterns for broader matching
ATR_PREFIX_PATTERNS = [
    # DESFire contactless (common pattern via PC/SC reader)
    {
        "prefix": [0x3B, 0x81, 0x80, 0x01, 0x80, 0x80],
        "type": "MIFARE DESFire",
        "subtype": "DESFire (contactless)",
        "family": "desfire"
    },
    # ISO 14443-4 Type A - DESFire pattern
    {
        "prefix": [0x3B, 0x8],
        "mask": [0xFF, 0xF0],
        "type": "ISO 14443 Type A",
        "subtype": "Contactless card",
        "family": "iso14443a"
    },
    # ACS ACR122U reader specific
    {
        "prefix": [0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06],
        "type": "NXP MIFARE",
        "subtype": "Via PC/SC v2 (ACS reader)",
        "family": "mifare"
    },
    # T=0 contact cards
    {
        "prefix": [0x3B, 0x9],
        "mask": [0xFF, 0xF0],
        "type": "Contact Smart Card",
        "subtype": "T=0 protocol",
        "family": "contact"
    },
    # T=1 contact cards
    {
        "prefix": [0x3B, 0xF],
        "mask": [0xFF, 0xF0],
        "type": "Contact Smart Card",
        "subtype": "T=1 protocol",
        "family": "contact"
    },
    # JavaCard / JCOP patterns
    {
        "prefix": [0x3B, 0xF8, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x45, 0x4A, 0x43, 0x4F, 0x50],
        "type": "JavaCard",
        "subtype": "NXP JCOP",
        "family": "javacard"
    },
    # YubiKey
    {
        "prefix": [0x3B, 0xFD, 0x13, 0x00, 0x00, 0x81, 0x31, 0xFE, 0x15, 0x80],
        "type": "JavaCard",
        "subtype": "YubiKey",
        "family": "javacard"
    },
]


class ATRInfo:
    """Parsed ATR information."""

    def __init__(self, atr_bytes: List[int]):
        self.raw = atr_bytes
        self.hex = bytes_to_hex(atr_bytes)
        self.card_type = "Unknown"
        self.card_subtype = "Unknown card"
        self.card_family = "unknown"
        self.protocol = "Unknown"
        self.historical_bytes: List[int] = []
        self._parse()

    def _parse(self):
        """Parse ATR bytes."""
        if not self.raw:
            return

        # Initial character TS
        ts = self.raw[0]
        if ts == 0x3B:
            self.protocol = "Direct convention"
        elif ts == 0x3F:
            self.protocol = "Inverse convention"

        # Format byte T0
        if len(self.raw) > 1:
            t0 = self.raw[1]
            num_historical = t0 & 0x0F

            # Extract historical bytes (simplified)
            offset = 2
            # Skip interface bytes (Yi present based on T0)
            y = t0 >> 4
            while y:
                if y & 0x1: offset += 1  # TAi
                if y & 0x2: offset += 1  # TBi
                if y & 0x4: offset += 1  # TCi
                if y & 0x8:
                    if offset < len(self.raw):
                        y = self.raw[offset] >> 4
                        offset += 1
                    else:
                        break
                else:
                    break

            if offset < len(self.raw):
                end = min(offset + num_historical, len(self.raw))
                self.historical_bytes = self.raw[offset:end]

        # Try exact match first
        atr_hex = self.hex
        for pattern, info in ATR_DATABASE.items():
            if atr_hex.startswith(pattern):
                self.card_type = info["type"]
                self.card_subtype = info["subtype"]
                self.card_family = info["family"]
                return

        # Try prefix patterns
        for pattern in ATR_PREFIX_PATTERNS:
            prefix = pattern["prefix"]
            mask = pattern.get("mask")

            if len(self.raw) >= len(prefix):
                match = True
                for i, p in enumerate(prefix):
                    m = mask[i] if mask and i < len(mask) else 0xFF
                    if (self.raw[i] & m) != (p & m):
                        match = False
                        break

                if match:
                    self.card_type = pattern["type"]
                    self.card_subtype = pattern["subtype"]
                    self.card_family = pattern["family"]
                    return

    def to_dict(self) -> Dict:
        """Return ATR info as dictionary."""
        return {
            "ATR": self.hex,
            "Card Type": self.card_type,
            "Card Subtype": self.card_subtype,
            "Protocol": self.protocol,
            "Historical Bytes": bytes_to_hex(self.historical_bytes) if self.historical_bytes else "None",
        }

    def __str__(self):
        return f"{self.card_type} - {self.card_subtype} [{self.hex}]"
