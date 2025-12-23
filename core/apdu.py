"""
APDU (Application Protocol Data Unit) utilities.
Handles command construction, response parsing, and hex formatting
for ISO 7816-4 and DESFire wrapped APDUs.
"""

from typing import List, Optional, Tuple


class APDUCommand:
    """Represents an ISO 7816-4 APDU command."""

    def __init__(self, cla: int, ins: int, p1: int, p2: int,
                 data: Optional[List[int]] = None, le: Optional[int] = None):
        self.cla = cla
        self.ins = ins
        self.p1 = p1
        self.p2 = p2
        self.data = data or []
        self.le = le

    def to_bytes(self) -> List[int]:
        """Convert to byte list for transmission."""
        cmd = [self.cla, self.ins, self.p1, self.p2]
        if self.data:
            cmd.append(len(self.data))
            cmd.extend(self.data)
        if self.le is not None:
            cmd.append(self.le)
        return cmd

    def __repr__(self):
        return f"APDU({bytes_to_hex(self.to_bytes())})"


class APDUResponse:
    """Represents an APDU response."""

    def __init__(self, data: List[int], sw1: int, sw2: int):
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2

    @property
    def sw(self) -> int:
        return (self.sw1 << 8) | self.sw2

    @property
    def is_success(self) -> bool:
        """Check if response indicates success."""
        return self.sw in (0x9000, 0x9100)

    @property
    def has_more_data(self) -> bool:
        """Check if there's more data to fetch (DESFire AF)."""
        return self.sw == 0x91AF

    @property
    def status_text(self) -> str:
        """Human-readable status."""
        status_map = {
            0x9000: "Success",
            0x9100: "Success (DESFire)",
            0x91AF: "Additional frame expected",
            0x9101: "No changes",
            0x910E: "Out of EEPROM",
            0x911C: "Illegal command code",
            0x911E: "Integrity error",
            0x9140: "No such key",
            0x917E: "Length error",
            0x919D: "Permission denied",
            0x919E: "Parameter error",
            0x91A0: "Application not found",
            0x91A1: "Application integrity error",
            0x91AE: "Authentication error",
            0x91BE: "Boundary error",
            0x91C1: "Card integrity error",
            0x91CA: "Command aborted",
            0x91CD: "Card disabled",
            0x91CE: "Count error",
            0x91DE: "Duplicate error",
            0x91EE: "EEPROM error",
            0x91F0: "File not found",
            0x91F1: "File integrity error",
            0x6A82: "Application/File not found",
            0x6A86: "Incorrect P1/P2",
            0x6D00: "Instruction not supported",
            0x6E00: "Class not supported",
        }
        return status_map.get(self.sw, f"Unknown (0x{self.sw:04X})")

    def __repr__(self):
        return f"Response(data={bytes_to_hex(self.data)}, SW={self.sw:04X})"


def desfire_command(cmd_code: int, data: Optional[List[int]] = None) -> APDUCommand:
    """Create a DESFire wrapped APDU command (CLA=0x90)."""
    return APDUCommand(
        cla=0x90,
        ins=cmd_code,
        p1=0x00,
        p2=0x00,
        data=data,
        le=0x00
    )


def iso_select(aid: List[int]) -> APDUCommand:
    """Create ISO 7816-4 SELECT command."""
    return APDUCommand(
        cla=0x00,
        ins=0xA4,
        p1=0x04,
        p2=0x00,
        data=aid,
        le=0x00
    )


def iso_read_binary(offset: int = 0, length: int = 0) -> APDUCommand:
    """Create ISO 7816-4 READ BINARY command."""
    return APDUCommand(
        cla=0x00,
        ins=0xB0,
        p1=(offset >> 8) & 0xFF,
        p2=offset & 0xFF,
        le=length
    )


def iso_get_data(tag_p1: int = 0x00, tag_p2: int = 0x00) -> APDUCommand:
    """Create ISO 7816-4 GET DATA command."""
    return APDUCommand(
        cla=0x00,
        ins=0xCA,
        p1=tag_p1,
        p2=tag_p2,
        le=0x00
    )


# ─── Hex Utilities ──────────────────────────────────────────────────────────

def bytes_to_hex(data: List[int], separator: str = " ") -> str:
    """Convert byte list to hex string."""
    return separator.join(f"{b:02X}" for b in data)


def hex_to_bytes(hex_string: str) -> List[int]:
    """Convert hex string to byte list."""
    hex_string = hex_string.replace(" ", "").replace(":", "").replace("-", "")
    if len(hex_string) % 2 != 0:
        hex_string = "0" + hex_string
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]


def format_hex_dump(data: List[int], bytes_per_line: int = 16) -> str:
    """Format data as a hex dump with ASCII representation."""
    lines = []
    for offset in range(0, len(data), bytes_per_line):
        chunk = data[offset:offset + bytes_per_line]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        lines.append(f"{offset:04X}  {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


def parse_tlv(data: List[int]) -> list:
    """Parse TLV (Tag-Length-Value) encoded data."""
    result = []
    i = 0
    while i < len(data):
        # Tag
        tag = data[i]
        i += 1
        if (tag & 0x1F) == 0x1F:  # Multi-byte tag
            tag = (tag << 8) | data[i]
            i += 1

        if i >= len(data):
            break

        # Length
        length = data[i]
        i += 1
        if length == 0x81:
            length = data[i]
            i += 1
        elif length == 0x82:
            length = (data[i] << 8) | data[i+1]
            i += 2

        # Value
        value = data[i:i+length]
        i += length

        result.append({"tag": tag, "length": length, "value": value})

    return result
