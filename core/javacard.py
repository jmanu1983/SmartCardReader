"""
JavaCard / GlobalPlatform handler.
Supports applet selection, APDU exchange, and common JavaCard operations.
"""

from typing import Dict, List, Optional, Tuple

from .apdu import (
    APDUCommand, APDUResponse, bytes_to_hex, hex_to_bytes,
    iso_select, parse_tlv
)


# ─── Well-known AIDs ────────────────────────────────────────────────────────

KNOWN_AIDS = {
    "GlobalPlatform ISD": "A000000003000000",
    "GlobalPlatform SSD": "A0000000035350",
    "VISA Credit/Debit": "A0000000031010",
    "Mastercard Credit/Debit": "A0000000041010",
    "Mastercard Maestro": "A0000000043060",
    "VISA Electron": "A0000000032010",
    "American Express": "A000000025010104",
    "JCB": "A0000000651010",
    "Discover/DinersClub": "A0000001523010",
    "NDEF Type 4 Tag": "D2760000850101",
    "PIV": "A000000308000010000100",
    "OpenPGP": "D27600012401",
    "FIDO U2F": "A0000006472F0001",
    "FIDO2 CTAP": "A000000647200001",
    "YubiKey OTP": "A000000527200101",
    "YubiKey Management": "A000000527471117",
}

# Common GlobalPlatform commands
GP_GET_STATUS = APDUCommand(0x80, 0xF2, 0x40, 0x00, [0x4F, 0x00], 0x00)
GP_GET_DATA_IIN = APDUCommand(0x80, 0xCA, 0x00, 0x42, le=0x00)
GP_GET_DATA_CIN = APDUCommand(0x80, 0xCA, 0x00, 0x45, le=0x00)
GP_GET_DATA_CPLC = APDUCommand(0x80, 0xCA, 0x9F, 0x7F, le=0x00)


class JavaCardHandler:
    """
    JavaCard protocol handler.
    Supports applet selection, APDU exchange, and GlobalPlatform operations.
    """

    def __init__(self, transmit_func):
        """
        Args:
            transmit_func: Function that takes APDUCommand and returns APDUResponse.
        """
        self._transmit = transmit_func
        self._selected_aid = None

    @property
    def selected_aid(self) -> Optional[str]:
        return self._selected_aid

    def select_applet(self, aid_hex: str) -> Tuple[bool, APDUResponse, str]:
        """
        Select a JavaCard applet by AID.
        Args:
            aid_hex: Hex string of the AID (e.g., "A000000003000000")
        Returns:
            (success, response, message)
        """
        aid_bytes = hex_to_bytes(aid_hex)
        cmd = iso_select(aid_bytes)
        response = self._transmit(cmd)

        if not response:
            return False, APDUResponse([], 0x6F, 0x00), "No response from card"

        if response.sw == 0x9000:
            self._selected_aid = aid_hex
            return True, response, "Applet selected successfully"
        elif response.sw == 0x6A82:
            return False, response, "Applet not found"
        elif response.sw == 0x6A86:
            return False, response, "Incorrect parameters"
        elif response.sw == 0x6985:
            return False, response, "Conditions not satisfied"
        else:
            return False, response, f"Selection failed: SW={response.sw:04X}"

    def send_apdu(self, cla: int, ins: int, p1: int, p2: int,
                  data: Optional[List[int]] = None,
                  le: Optional[int] = None) -> Optional[APDUResponse]:
        """Send a custom APDU command."""
        cmd = APDUCommand(cla, ins, p1, p2, data, le)
        return self._transmit(cmd)

    def send_raw_apdu(self, apdu_hex: str) -> Optional[APDUResponse]:
        """Send a raw APDU from hex string."""
        apdu_bytes = hex_to_bytes(apdu_hex)
        if len(apdu_bytes) < 4:
            return None

        cla = apdu_bytes[0]
        ins = apdu_bytes[1]
        p1 = apdu_bytes[2]
        p2 = apdu_bytes[3]

        data = None
        le = None

        if len(apdu_bytes) > 5:
            lc = apdu_bytes[4]
            data = apdu_bytes[5:5+lc]
            if len(apdu_bytes) > 5 + lc:
                le = apdu_bytes[5 + lc]
        elif len(apdu_bytes) == 5:
            le = apdu_bytes[4]

        cmd = APDUCommand(cla, ins, p1, p2, data, le)
        return self._transmit(cmd)

    # ─── GlobalPlatform Operations ──────────────────────────────────────

    def get_cplc(self) -> Optional[Dict]:
        """Get Card Production Life Cycle (CPLC) data."""
        response = self._transmit(GP_GET_DATA_CPLC)
        if not response or response.sw != 0x9000:
            return None

        data = response.data
        if len(data) < 42:
            return None

        # Skip TLV header if present
        offset = 0
        if data[0] == 0x9F and data[1] == 0x7F:
            offset = 3  # Tag (2) + Length (1)

        d = data[offset:]
        if len(d) < 42:
            return None

        return {
            "IC Fabricator": bytes_to_hex(d[0:2]),
            "IC Type": bytes_to_hex(d[2:4]),
            "OS ID": bytes_to_hex(d[4:6]),
            "OS Release Date": bytes_to_hex(d[6:8]),
            "OS Release Level": bytes_to_hex(d[8:10]),
            "IC Fabrication Date": bytes_to_hex(d[10:12]),
            "IC Serial Number": bytes_to_hex(d[12:16]),
            "IC Batch ID": bytes_to_hex(d[16:18]),
            "IC Module Fabricator": bytes_to_hex(d[18:20]),
            "IC Module Packaging Date": bytes_to_hex(d[20:22]),
            "ICC Manufacturer": bytes_to_hex(d[22:24]),
            "IC Embedding Date": bytes_to_hex(d[24:26]),
            "Pre-personalizer": bytes_to_hex(d[26:28]),
            "Pre-personalization Date": bytes_to_hex(d[28:30]),
            "Pre-personalization Equipment": bytes_to_hex(d[30:34]),
            "Personalizer": bytes_to_hex(d[34:36]),
            "Personalization Date": bytes_to_hex(d[36:38]),
            "Personalization Equipment": bytes_to_hex(d[38:42]),
        }

    def get_card_data(self) -> Dict:
        """Get general card data (IIN, CIN, CPLC)."""
        result = {}

        # Try to select ISD first
        isd_selected, _, _ = self.select_applet("A000000003000000")

        # IIN
        response = self._transmit(GP_GET_DATA_IIN)
        if response and response.sw == 0x9000:
            result["IIN"] = bytes_to_hex(response.data)

        # CIN
        response = self._transmit(GP_GET_DATA_CIN)
        if response and response.sw == 0x9000:
            result["CIN"] = bytes_to_hex(response.data)

        # CPLC
        cplc = self.get_cplc()
        if cplc:
            result["CPLC"] = cplc

        return result

    def probe_known_aids(self) -> List[Dict]:
        """
        Probe for well-known applets on the card.
        Returns a list of found applets with their names and AIDs.
        """
        found = []
        for name, aid in KNOWN_AIDS.items():
            success, response, msg = self.select_applet(aid)
            if success:
                found.append({
                    "name": name,
                    "aid": aid,
                    "response_data": bytes_to_hex(response.data) if response.data else "",
                })
        return found

    def read_ndef(self) -> Optional[str]:
        """
        Try to read NDEF data from an NFC Forum Type 4 Tag.
        Returns the NDEF message as hex string.
        """
        # Select NDEF application
        success, _, _ = self.select_applet("D2760000850101")
        if not success:
            return None

        # Select CC (Capability Container) file
        cmd = APDUCommand(0x00, 0xA4, 0x00, 0x0C, [0xE1, 0x03])
        response = self._transmit(cmd)
        if not response or response.sw != 0x9000:
            return None

        # Read CC
        cmd = APDUCommand(0x00, 0xB0, 0x00, 0x00, le=0x0F)
        response = self._transmit(cmd)
        if not response or response.sw != 0x9000 or len(response.data) < 15:
            return None

        # Get NDEF file ID from CC
        ndef_file_id = response.data[9:11]

        # Select NDEF file
        cmd = APDUCommand(0x00, 0xA4, 0x00, 0x0C, ndef_file_id)
        response = self._transmit(cmd)
        if not response or response.sw != 0x9000:
            return None

        # Read NDEF length
        cmd = APDUCommand(0x00, 0xB0, 0x00, 0x00, le=0x02)
        response = self._transmit(cmd)
        if not response or response.sw != 0x9000 or len(response.data) < 2:
            return None

        ndef_len = (response.data[0] << 8) | response.data[1]
        if ndef_len == 0:
            return None

        # Read NDEF message
        cmd = APDUCommand(0x00, 0xB0, 0x00, 0x02, le=min(ndef_len, 0xFE))
        response = self._transmit(cmd)
        if response and response.sw == 0x9000:
            return bytes_to_hex(response.data)

        return None
