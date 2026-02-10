"""
MIFARE DESFire EV1/EV2/EV3 protocol implementation.
Supports card interrogation, application management, file operations,
and authentication with DES, 3DES, 3K3DES, and AES keys.
"""

import binascii
import os
import struct
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

from .apdu import APDUCommand, APDUResponse, bytes_to_hex, desfire_command

try:
    from Crypto.Cipher import DES, DES3, AES
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ─── DESFire Command Codes ──────────────────────────────────────────────────

class DESFireCmd(IntEnum):
    """DESFire native command codes."""
    # Security
    AUTHENTICATE_LEGACY = 0x0A
    AUTHENTICATE_ISO = 0x1A
    AUTHENTICATE_AES = 0xAA
    AUTHENTICATE_EV2_FIRST = 0x71
    AUTHENTICATE_EV2_NON_FIRST = 0x77
    CHANGE_KEY_SETTINGS = 0x54
    GET_KEY_SETTINGS = 0x45
    CHANGE_KEY = 0xC4
    GET_KEY_VERSION = 0x64

    # PICC level
    CREATE_APPLICATION = 0xCA
    DELETE_APPLICATION = 0xDA
    GET_APPLICATION_IDS = 0x6A
    GET_DF_NAMES = 0x6D
    SELECT_APPLICATION = 0x5A
    FORMAT_PICC = 0xFC
    GET_VERSION = 0x60
    GET_CARD_UID = 0x51
    FREE_MEMORY = 0x6E

    # Application level
    GET_FILE_IDS = 0x6F
    GET_FILE_SETTINGS = 0xF5
    CHANGE_FILE_SETTINGS = 0x5F
    CREATE_STD_DATA_FILE = 0xCD
    CREATE_BACKUP_FILE = 0xCB
    CREATE_VALUE_FILE = 0xCC
    CREATE_LINEAR_RECORD_FILE = 0xC1
    CREATE_CYCLIC_RECORD_FILE = 0xC0
    DELETE_FILE = 0xDF

    # Data operations
    READ_DATA = 0xBD
    WRITE_DATA = 0x3D
    GET_VALUE = 0x6C
    CREDIT = 0x0C
    DEBIT = 0xDC
    LIMITED_CREDIT = 0x1C
    READ_RECORDS = 0xBB
    WRITE_RECORD = 0x3B
    CLEAR_RECORD_FILE = 0xEB
    COMMIT_TRANSACTION = 0xC7
    ABORT_TRANSACTION = 0xA7

    # Additional frame
    ADDITIONAL_FRAME = 0xAF


class DESFireKeyType(IntEnum):
    """DESFire authentication key types."""
    DES = 0
    TDES_2K = 1
    TDES_3K = 2
    AES_128 = 3


class DESFireFileType(IntEnum):
    """DESFire file types."""
    STANDARD_DATA = 0x00
    BACKUP_DATA = 0x01
    VALUE = 0x02
    LINEAR_RECORD = 0x03
    CYCLIC_RECORD = 0x04
    TRANSACTION_MAC = 0x05


class DESFireCommMode(IntEnum):
    """DESFire communication modes."""
    PLAIN = 0x00
    MACED = 0x01
    ENCRYPTED = 0x03


# ─── DESFire Version Info ───────────────────────────────────────────────────

STORAGE_SIZES = {
    0x16: "2 KB",
    0x18: "4 KB",
    0x1A: "8 KB",
    0x1C: "16 KB",
    0x1E: "32 KB",
}

DESFIRE_TYPES = {
    0x01: "DESFire EV1",
    0x12: "DESFire EV2",
    0x13: "DESFire EV3",
    0x30: "DESFire Light",
    0x33: "NTAG 424 DNA",
}


class DESFireVersionInfo:
    """Parsed DESFire version information."""

    def __init__(self):
        self.hw_vendor = 0
        self.hw_type = 0
        self.hw_subtype = 0
        self.hw_major = 0
        self.hw_minor = 0
        self.hw_storage = 0
        self.hw_protocol = 0

        self.sw_vendor = 0
        self.sw_type = 0
        self.sw_subtype = 0
        self.sw_major = 0
        self.sw_minor = 0
        self.sw_storage = 0
        self.sw_protocol = 0

        self.uid = []
        self.batch_no = []
        self.production_week = 0
        self.production_year = 0

    @property
    def card_type(self) -> str:
        """Human-readable card type."""
        return DESFIRE_TYPES.get(self.sw_major, f"DESFire (v{self.sw_major}.{self.sw_minor})")

    @property
    def storage_size(self) -> str:
        return STORAGE_SIZES.get(self.hw_storage, f"Unknown (0x{self.hw_storage:02X})")

    @property
    def uid_hex(self) -> str:
        return bytes_to_hex(self.uid)

    def to_dict(self) -> Dict:
        """Return version info as dictionary."""
        return {
            "Card Type": self.card_type,
            "UID": self.uid_hex,
            "Hardware": {
                "Vendor": f"0x{self.hw_vendor:02X}" + (" (NXP)" if self.hw_vendor == 0x04 else ""),
                "Type": f"0x{self.hw_type:02X}",
                "Subtype": f"0x{self.hw_subtype:02X}",
                "Version": f"{self.hw_major}.{self.hw_minor}",
                "Storage": self.storage_size,
                "Protocol": f"0x{self.hw_protocol:02X}",
            },
            "Software": {
                "Vendor": f"0x{self.sw_vendor:02X}" + (" (NXP)" if self.sw_vendor == 0x04 else ""),
                "Type": f"0x{self.sw_type:02X}",
                "Subtype": f"0x{self.sw_subtype:02X}",
                "Version": f"{self.sw_major}.{self.sw_minor}",
                "Storage": STORAGE_SIZES.get(self.sw_storage, f"0x{self.sw_storage:02X}"),
                "Protocol": f"0x{self.sw_protocol:02X}",
            },
            "Production": {
                "Batch": bytes_to_hex(self.batch_no),
                "Week": self.production_week,
                "Year": 2000 + self.production_year if self.production_year else "?",
            },
        }


class DESFireFileSettings:
    """Parsed DESFire file settings."""

    def __init__(self, data: List[int]):
        self.raw = data
        self.file_type = DESFireFileType(data[0]) if data else DESFireFileType.STANDARD_DATA
        self.comm_mode = DESFireCommMode(data[1]) if len(data) > 1 else DESFireCommMode.PLAIN
        self.access_rights = (data[2] | (data[3] << 8)) if len(data) > 3 else 0

        # Access rights breakdown
        self.read_access = (self.access_rights >> 12) & 0x0F
        self.write_access = (self.access_rights >> 8) & 0x0F
        self.rw_access = (self.access_rights >> 4) & 0x0F
        self.change_access = self.access_rights & 0x0F

        self.size = 0
        self.max_records = 0
        self.current_records = 0
        self.lower_limit = 0
        self.upper_limit = 0
        self.value = 0

        if self.file_type in (DESFireFileType.STANDARD_DATA, DESFireFileType.BACKUP_DATA):
            if len(data) >= 7:
                self.size = data[4] | (data[5] << 8) | (data[6] << 16)
        elif self.file_type == DESFireFileType.VALUE:
            if len(data) >= 17:
                self.lower_limit = int.from_bytes(data[4:8], 'little', signed=True)
                self.upper_limit = int.from_bytes(data[8:12], 'little', signed=True)
                self.value = int.from_bytes(data[12:16], 'little', signed=True)
        elif self.file_type in (DESFireFileType.LINEAR_RECORD, DESFireFileType.CYCLIC_RECORD):
            if len(data) >= 13:
                record_size = data[4] | (data[5] << 8) | (data[6] << 16)
                self.size = record_size
                self.max_records = data[7] | (data[8] << 8) | (data[9] << 16)
                self.current_records = data[10] | (data[11] << 8) | (data[12] << 16)

    def _access_key_str(self, key_num: int) -> str:
        if key_num == 0x0E:
            return "Free"
        elif key_num == 0x0F:
            return "Denied"
        return f"Key {key_num}"

    def to_dict(self) -> Dict:
        result = {
            "File Type": self.file_type.name,
            "Communication": self.comm_mode.name,
            "Read Access": self._access_key_str(self.read_access),
            "Write Access": self._access_key_str(self.write_access),
            "Read/Write Access": self._access_key_str(self.rw_access),
            "Change Access": self._access_key_str(self.change_access),
        }

        if self.file_type in (DESFireFileType.STANDARD_DATA, DESFireFileType.BACKUP_DATA):
            result["Size"] = f"{self.size} bytes"
        elif self.file_type == DESFireFileType.VALUE:
            result["Lower Limit"] = self.lower_limit
            result["Upper Limit"] = self.upper_limit
            result["Value"] = self.value
        elif self.file_type in (DESFireFileType.LINEAR_RECORD, DESFireFileType.CYCLIC_RECORD):
            result["Record Size"] = f"{self.size} bytes"
            result["Max Records"] = self.max_records
            result["Current Records"] = self.current_records

        return result


# ─── DESFire Protocol Handler ───────────────────────────────────────────────

class DESFireProtocol:
    """
    DESFire EV1/EV2/EV3 protocol handler.
    Provides methods for card interrogation, authentication, and data access.
    """

    def __init__(self, transmit_func):
        """
        Args:
            transmit_func: Function that takes APDUCommand and returns APDUResponse.
        """
        self._transmit = transmit_func
        self._session_key = None
        self._authenticated = False
        self._auth_key_type = None
        self._cmac_iv = bytes(16)  # CMAC IV, reset after auth

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def session_key(self) -> Optional[list]:
        return self._session_key

    # ─── Crypto Helpers ──────────────────────────────────────────────

    @staticmethod
    def _generate_cmac_subkeys(key: bytes) -> tuple:
        """Generate CMAC subkeys K1, K2 for AES-128."""
        cipher = AES.new(key, AES.MODE_ECB)
        L = cipher.encrypt(b'\x00' * 16)
        # K1
        K1 = bytearray(16)
        overflow = 0
        for i in range(15, -1, -1):
            K1[i] = ((L[i] << 1) & 0xFF) | overflow
            overflow = 1 if (L[i] & 0x80) else 0
        if L[0] & 0x80:
            K1[15] ^= 0x87
        K1 = bytes(K1)
        # K2
        K2 = bytearray(16)
        overflow = 0
        for i in range(15, -1, -1):
            K2[i] = ((K1[i] << 1) & 0xFF) | overflow
            overflow = 1 if (K1[i] & 0x80) else 0
        if K1[0] & 0x80:
            K2[15] ^= 0x87
        K2 = bytes(K2)
        return K1, K2

    def _calculate_cmac(self, data: list) -> bytes:
        """
        Calculate AES-CMAC over data using session key and current IV.
        Updates self._cmac_iv with the result.
        """
        if not self._session_key or not CRYPTO_AVAILABLE:
            return self._cmac_iv

        key = bytes(self._session_key)
        K1, K2 = self._generate_cmac_subkeys(key)
        block_size = 16

        message = bytes(data)
        n_blocks = max(1, (len(message) + block_size - 1) // block_size)
        last_complete = (len(message) > 0) and (len(message) % block_size == 0)

        if last_complete:
            padded = bytearray(message)
            for i in range(block_size):
                padded[-(block_size - i)] ^= K1[i]
        else:
            padded = bytearray(message) + bytearray([0x80])
            while len(padded) % block_size != 0:
                padded.append(0x00)
            for i in range(block_size):
                padded[-(block_size - i)] ^= K2[i]

        padded = bytes(padded)
        cipher = AES.new(key, AES.MODE_CBC, iv=self._cmac_iv)
        encrypted = cipher.encrypt(padded)
        self._cmac_iv = encrypted[-block_size:]
        return self._cmac_iv

    def _try_decrypt_aes(self, encrypted_data: bytes, iv: bytes, expected_size: int) -> Optional[List[int]]:
        """
        Attempt AES-CBC decryption with given IV and verify CRC32.
        Returns decrypted data if CRC matches, None otherwise.
        """
        key = bytes(self._session_key)
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        plaintext = list(cipher.decrypt(encrypted_data))

        if expected_size > 0 and expected_size <= len(plaintext) - 4:
            real_data = plaintext[:expected_size]
            crc_bytes = plaintext[expected_size:expected_size + 4]
            stored_crc = struct.unpack('<I', bytes(crc_bytes))[0]

            # DESFire CRC32 is computed over: status_byte(0x00) + plaintext_data
            crc_input = bytes([0x00]) + bytes(real_data)
            computed_crc = binascii.crc32(crc_input) & 0xFFFFFFFF
            if computed_crc == stored_crc:
                return real_data

            # Some implementations compute CRC without the status byte
            computed_crc2 = binascii.crc32(bytes(real_data)) & 0xFFFFFFFF
            if computed_crc2 == stored_crc:
                return real_data

        return None

    def _decrypt_aes_response(self, encrypted_data: List[int], expected_size: int) -> List[int]:
        """
        Decrypt an AES-encrypted DESFire response.
        Tries multiple IV strategies to handle CMAC tracking uncertainty.
        Returns the decrypted plaintext data (without CRC and padding).
        """
        if not self._session_key or not CRYPTO_AVAILABLE:
            return encrypted_data

        key = bytes(self._session_key)
        ct = bytes(encrypted_data)

        # Strategy 1: Try with current CMAC IV
        result = self._try_decrypt_aes(ct, self._cmac_iv, expected_size)
        if result is not None:
            self._cmac_iv = ct[-16:]
            return result

        # Strategy 2: Try with IV = all zeros (fresh after auth)
        result = self._try_decrypt_aes(ct, bytes(16), expected_size)
        if result is not None:
            self._cmac_iv = ct[-16:]
            return result

        # Strategy 3: Try with IV = last ciphertext block of auth exchange
        # (some implementations carry IV from auth)

        # Strategy 4: Fallback - decrypt with IV=0 and return data even without CRC verification
        cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
        plaintext = list(cipher.decrypt(ct))
        self._cmac_iv = ct[-16:]

        if expected_size > 0 and expected_size <= len(plaintext):
            return plaintext[:expected_size]

        # Last resort: try to strip padding (0x80 00... scheme)
        for i in range(len(plaintext) - 1, max(0, len(plaintext) - 20), -1):
            if plaintext[i] == 0x80:
                if i >= 4:
                    return plaintext[:i - 4]
                break
            elif plaintext[i] != 0x00:
                break

        return plaintext[:max(0, len(plaintext) - 16)]

    def _decrypt_des_response(self, encrypted_data: List[int], expected_size: int) -> List[int]:
        """
        Decrypt a DES/3DES-encrypted DESFire response.
        """
        if not self._session_key or not CRYPTO_AVAILABLE:
            return encrypted_data

        key = bytes(self._session_key)
        ct = bytes(encrypted_data)
        block_size = 8

        if len(key) == 8:
            cipher = DES.new(key, DES.MODE_CBC, iv=self._cmac_iv[:8])
        else:
            cipher = DES3.new(key, DES3.MODE_CBC, iv=self._cmac_iv[:8])

        plaintext = list(cipher.decrypt(ct))
        self._cmac_iv = bytearray(16)
        self._cmac_iv[:8] = ct[-8:]

        if expected_size > 0 and expected_size <= len(plaintext) - 2:
            return plaintext[:expected_size]

        return plaintext

    def _send(self, cmd_code: int, data: Optional[List[int]] = None) -> APDUResponse:
        """Send a DESFire command and handle multi-frame responses."""
        apdu = desfire_command(cmd_code, data)
        response = self._transmit(apdu)
        if not response:
            return APDUResponse([], 0x91, 0xCA)  # Command aborted

        # Handle additional frames
        full_data = list(response.data)
        while response.has_more_data:
            apdu = desfire_command(DESFireCmd.ADDITIONAL_FRAME)
            response = self._transmit(apdu)
            if response:
                full_data.extend(response.data)
            else:
                break

        return APDUResponse(full_data, response.sw1, response.sw2)

    # ─── PICC Level Commands ─────────────────────────────────────────────

    def get_version(self) -> Optional[DESFireVersionInfo]:
        """Get card version information (hardware, software, production)."""
        response = self._send(DESFireCmd.GET_VERSION)
        if not response or len(response.data) < 28:
            return None

        info = DESFireVersionInfo()
        d = response.data

        # Hardware info (bytes 0-6)
        info.hw_vendor = d[0]
        info.hw_type = d[1]
        info.hw_subtype = d[2]
        info.hw_major = d[3]
        info.hw_minor = d[4]
        info.hw_storage = d[5]
        info.hw_protocol = d[6]

        # Software info (bytes 7-13)
        info.sw_vendor = d[7]
        info.sw_type = d[8]
        info.sw_subtype = d[9]
        info.sw_major = d[10]
        info.sw_minor = d[11]
        info.sw_storage = d[12]
        info.sw_protocol = d[13]

        # Production info (bytes 14-27)
        info.uid = d[14:21]
        info.batch_no = d[21:26]
        info.production_week = d[26]
        info.production_year = d[27]

        return info

    def get_free_memory(self) -> Optional[int]:
        """Get free memory on the card (in bytes)."""
        response = self._send(DESFireCmd.FREE_MEMORY)
        if response and response.is_success and len(response.data) >= 3:
            return response.data[0] | (response.data[1] << 8) | (response.data[2] << 16)
        return None

    def get_card_uid(self) -> Optional[List[int]]:
        """Get real UID (requires authentication)."""
        response = self._send(DESFireCmd.GET_CARD_UID)
        if response and response.is_success:
            return response.data
        return None

    # ─── Application Commands ────────────────────────────────────────────

    def get_application_ids(self) -> Optional[List[List[int]]]:
        """Get list of application IDs on the card."""
        response = self._send(DESFireCmd.GET_APPLICATION_IDS)
        if response and response.is_success:
            aids = []
            for i in range(0, len(response.data), 3):
                if i + 3 <= len(response.data):
                    aids.append(response.data[i:i+3])
            return aids
        return None

    def get_df_names(self) -> Optional[List[Dict]]:
        """Get DF names (DESFire EV1+)."""
        response = self._send(DESFireCmd.GET_DF_NAMES)
        if response and response.is_success:
            names = []
            data = response.data
            i = 0
            while i < len(data):
                if i + 3 <= len(data):
                    aid = data[i:i+3]
                    i += 3
                    fid = data[i:i+2] if i + 2 <= len(data) else []
                    i += 2
                    # ISO DF name follows
                    name_len = 0
                    name = []
                    while i + name_len < len(data) and data[i + name_len] != 0:
                        name.append(data[i + name_len])
                        name_len += 1
                    i += name_len
                    names.append({
                        "AID": bytes_to_hex(aid),
                        "FID": bytes_to_hex(fid),
                        "Name": bytes(name).decode('ascii', errors='replace') if name else "",
                    })
                else:
                    break
            return names
        return None

    def select_application(self, aid: List[int]) -> bool:
        """Select a DESFire application by AID (3 bytes)."""
        response = self._send(DESFireCmd.SELECT_APPLICATION, aid)
        self._authenticated = False
        self._session_key = None
        return response is not None and response.is_success

    def select_picc(self) -> bool:
        """Select PICC level (AID 000000)."""
        return self.select_application([0x00, 0x00, 0x00])

    # ─── Key Management ──────────────────────────────────────────────────

    def get_key_settings(self) -> Optional[Dict]:
        """Get key settings of the currently selected application."""
        response = self._send(DESFireCmd.GET_KEY_SETTINGS)
        if response and response.is_success and len(response.data) >= 2:
            settings = response.data[0]
            max_keys = response.data[1]

            key_type_code = (max_keys >> 6) & 0x03
            key_types = {0: "DES/2K3DES", 1: "3K3DES", 2: "AES-128"}

            return {
                "Settings Byte": f"0x{settings:02X}",
                "Allow Change Master Key": bool(settings & 0x01),
                "Allow Directory Without Master Key": bool(settings & 0x02),
                "Allow Create/Delete Without Master Key": bool(settings & 0x04),
                "Master Key Changeable": bool(settings & 0x08),
                "Max Keys": max_keys & 0x3F,
                "Key Type": key_types.get(key_type_code, f"Unknown ({key_type_code})"),
            }
        return None

    def get_key_version(self, key_no: int) -> Optional[int]:
        """Get the version of a specific key."""
        response = self._send(DESFireCmd.GET_KEY_VERSION, [key_no])
        if response and response.is_success and len(response.data) >= 1:
            return response.data[0]
        return None

    # ─── File Commands ───────────────────────────────────────────────────

    def get_file_ids(self) -> Optional[List[int]]:
        """Get list of file IDs in the current application."""
        response = self._send(DESFireCmd.GET_FILE_IDS)
        if response and response.is_success:
            return list(response.data)
        return None

    def get_file_settings(self, file_no: int) -> Optional[DESFireFileSettings]:
        """Get settings for a specific file."""
        response = self._send(DESFireCmd.GET_FILE_SETTINGS, [file_no])
        if response and response.is_success and response.data:
            return DESFireFileSettings(response.data)
        return None

    def read_data(self, file_no: int, offset: int = 0, length: int = 0) -> Optional[List[int]]:
        """Read data from a standard or backup data file.
        Automatically decrypts if authenticated and file uses encrypted comm."""

        # Get file settings FIRST (before CMAC calculation, as this affects IV)
        need_decrypt = False
        expected_size = 0
        if self._authenticated and self._session_key and CRYPTO_AVAILABLE:
            fs = self.get_file_settings(file_no)
            if fs and fs.comm_mode == DESFireCommMode.ENCRYPTED:
                need_decrypt = True
                expected_size = fs.size if length == 0 else length
            # Reset IV before read command since get_file_settings disrupted it
            self._cmac_iv = bytes(16)

        cmd_data = [
            file_no,
            offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
            length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF,
        ]

        # Update CMAC IV with the ReadData command
        if self._authenticated and self._session_key and CRYPTO_AVAILABLE:
            cmac_data = [DESFireCmd.READ_DATA] + cmd_data
            self._calculate_cmac(cmac_data)

        response = self._send(DESFireCmd.READ_DATA, cmd_data)
        if not response or not response.is_success:
            return None

        # Decrypt if needed
        if need_decrypt:
            if self._auth_key_type == DESFireKeyType.AES_128:
                return self._decrypt_aes_response(response.data, expected_size)
            elif self._auth_key_type in (DESFireKeyType.DES, DESFireKeyType.TDES_2K):
                return self._decrypt_des_response(response.data, expected_size)

        return response.data

    def read_data_raw(self, file_no: int, offset: int = 0, length: int = 0) -> Optional[List[int]]:
        """Read raw (encrypted) data without decryption."""
        data = [
            file_no,
            offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
            length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF,
        ]
        response = self._send(DESFireCmd.READ_DATA, data)
        if response and response.is_success:
            return response.data
        return None

    def get_value(self, file_no: int) -> Optional[int]:
        """Read a value file."""
        if self._authenticated and self._session_key and CRYPTO_AVAILABLE:
            cmac_data = [DESFireCmd.GET_VALUE, file_no]
            self._calculate_cmac(cmac_data)

        response = self._send(DESFireCmd.GET_VALUE, [file_no])
        if response and response.is_success and len(response.data) >= 4:
            data = response.data
            # Decrypt if needed
            if self._authenticated and self._session_key and CRYPTO_AVAILABLE:
                if self._auth_key_type == DESFireKeyType.AES_128:
                    data = self._decrypt_aes_response(response.data, 4)
                elif self._auth_key_type in (DESFireKeyType.DES, DESFireKeyType.TDES_2K):
                    data = self._decrypt_des_response(response.data, 4)
            if len(data) >= 4:
                return int.from_bytes(bytes(data[:4]), 'little', signed=True)
        return None

    def read_records(self, file_no: int, offset: int = 0, count: int = 0) -> Optional[List[int]]:
        """Read records from a record file."""
        cmd_data = [
            file_no,
            offset & 0xFF, (offset >> 8) & 0xFF, (offset >> 16) & 0xFF,
            count & 0xFF, (count >> 8) & 0xFF, (count >> 16) & 0xFF,
        ]

        if self._authenticated and self._session_key and CRYPTO_AVAILABLE:
            cmac_data = [DESFireCmd.READ_RECORDS] + cmd_data
            self._calculate_cmac(cmac_data)

        response = self._send(DESFireCmd.READ_RECORDS, cmd_data)
        if response and response.is_success:
            if self._authenticated and self._session_key and CRYPTO_AVAILABLE:
                fs = self.get_file_settings(file_no)
                if fs and fs.comm_mode == DESFireCommMode.ENCRYPTED:
                    expected = fs.size * fs.current_records if fs.current_records > 0 else 0
                    if self._auth_key_type == DESFireKeyType.AES_128:
                        return self._decrypt_aes_response(response.data, expected)
            return response.data
        return None

    # ─── Authentication ──────────────────────────────────────────────────

    def authenticate_legacy(self, key_no: int, key: List[int]) -> Tuple[bool, str]:
        """
        DESFire legacy authentication (DES/2K3DES).
        Args:
            key_no: Key number (0-13)
            key: Key bytes (8 bytes for DES, 16 bytes for 2K3DES)
        Returns:
            (success, message)
        """
        if not CRYPTO_AVAILABLE:
            return False, "pycryptodome not installed"

        # Step 1: Send auth command
        apdu = desfire_command(DESFireCmd.AUTHENTICATE_LEGACY, [key_no])
        response = self._transmit(apdu)
        if not response or response.sw != 0x91AF:
            return False, f"Auth init failed: {response.status_text if response else 'No response'}"

        enc_rnd_b = response.data
        if len(enc_rnd_b) < 8:
            return False, "Invalid challenge length"

        # Step 2: Decrypt RndB
        if len(key) == 8:
            cipher = DES.new(bytes(key), DES.MODE_CBC, iv=b'\x00' * 8)
        else:
            cipher = DES3.new(bytes(key), DES3.MODE_CBC, iv=b'\x00' * 8)

        rnd_b = list(cipher.decrypt(bytes(enc_rnd_b)))

        # Rotate RndB left by 1 byte
        rnd_b_rot = rnd_b[1:] + rnd_b[:1]

        # Generate RndA
        rnd_a = list(os.urandom(8))

        # Step 3: Encrypt RndA + RndB'
        plain = rnd_a + rnd_b_rot
        if len(key) == 8:
            cipher = DES.new(bytes(key), DES.MODE_CBC, iv=bytes(enc_rnd_b))
        else:
            cipher = DES3.new(bytes(key), DES3.MODE_CBC, iv=bytes(enc_rnd_b))

        enc_both = list(cipher.encrypt(bytes(plain)))

        # Step 4: Send encrypted response
        apdu = desfire_command(DESFireCmd.ADDITIONAL_FRAME, enc_both)
        response = self._transmit(apdu)
        if not response or not response.is_success:
            return False, f"Auth failed: {response.status_text if response else 'No response'}"

        # Step 5: Verify RndA'
        if len(key) == 8:
            cipher = DES.new(bytes(key), DES.MODE_CBC, iv=bytes(enc_both[-8:]))
        else:
            cipher = DES3.new(bytes(key), DES3.MODE_CBC, iv=bytes(enc_both[-8:]))

        dec_rnd_a = list(cipher.decrypt(bytes(response.data)))
        rnd_a_rot = rnd_a[1:] + rnd_a[:1]

        if dec_rnd_a != rnd_a_rot:
            self._authenticated = False
            return False, "Authentication verification failed"

        # Generate session key
        if len(key) == 8:
            self._session_key = rnd_a[:4] + rnd_b[:4]
        else:
            self._session_key = rnd_a[:4] + rnd_b[:4] + rnd_a[4:8] + rnd_b[4:8]

        self._authenticated = True
        self._auth_key_type = DESFireKeyType.DES if len(key) == 8 else DESFireKeyType.TDES_2K
        self._cmac_iv = bytes(16)
        return True, "Authentication successful"

    def authenticate_aes(self, key_no: int, key: List[int]) -> Tuple[bool, str]:
        """
        DESFire AES authentication (EV1+).
        Args:
            key_no: Key number (0-13)
            key: 16-byte AES-128 key
        Returns:
            (success, message)
        """
        if not CRYPTO_AVAILABLE:
            return False, "pycryptodome not installed"

        if len(key) != 16:
            return False, "AES key must be 16 bytes"

        # Step 1: Send auth command
        apdu = desfire_command(DESFireCmd.AUTHENTICATE_AES, [key_no])
        response = self._transmit(apdu)
        if not response or response.sw != 0x91AF:
            return False, f"Auth init failed: {response.status_text if response else 'No response'}"

        enc_rnd_b = response.data
        if len(enc_rnd_b) < 16:
            return False, "Invalid challenge length"

        # Step 2: Decrypt RndB
        iv = bytes(16)
        cipher = AES.new(bytes(key), AES.MODE_CBC, iv=iv)
        rnd_b = list(cipher.decrypt(bytes(enc_rnd_b)))

        # Rotate RndB left by 1 byte
        rnd_b_rot = rnd_b[1:] + rnd_b[:1]

        # Generate RndA (16 bytes for AES)
        rnd_a = list(os.urandom(16))

        # Step 3: Encrypt RndA + RndB'
        plain = rnd_a + rnd_b_rot
        iv = bytes(enc_rnd_b)
        cipher = AES.new(bytes(key), AES.MODE_CBC, iv=iv)
        enc_both = list(cipher.encrypt(bytes(plain)))

        # Step 4: Send encrypted response
        apdu = desfire_command(DESFireCmd.ADDITIONAL_FRAME, enc_both)
        response = self._transmit(apdu)
        if not response or not response.is_success:
            return False, f"Auth failed: {response.status_text if response else 'No response'}"

        # Step 5: Verify RndA'
        iv = bytes(enc_both[-16:])
        cipher = AES.new(bytes(key), AES.MODE_CBC, iv=iv)
        dec_rnd_a = list(cipher.decrypt(bytes(response.data)))
        rnd_a_rot = rnd_a[1:] + rnd_a[:1]

        if dec_rnd_a != rnd_a_rot:
            self._authenticated = False
            return False, "Authentication verification failed"

        # Generate session key: RndA[0:4] + RndB[0:4] + RndA[12:16] + RndB[12:16]
        self._session_key = rnd_a[:4] + rnd_b[:4] + rnd_a[12:16] + rnd_b[12:16]
        self._authenticated = True
        self._auth_key_type = DESFireKeyType.AES_128
        self._cmac_iv = bytes(16)  # Reset IV after successful auth
        return True, "AES authentication successful"

    def authenticate_iso(self, key_no: int, key: List[int]) -> Tuple[bool, str]:
        """
        DESFire ISO authentication (3K3DES).
        Args:
            key_no: Key number (0-13)
            key: 24-byte 3K3DES key
        Returns:
            (success, message)
        """
        if not CRYPTO_AVAILABLE:
            return False, "pycryptodome not installed"

        if len(key) != 24:
            return False, "3K3DES key must be 24 bytes"

        # Step 1: Send auth command
        apdu = desfire_command(DESFireCmd.AUTHENTICATE_ISO, [key_no])
        response = self._transmit(apdu)
        if not response or response.sw != 0x91AF:
            return False, f"Auth init failed: {response.status_text if response else 'No response'}"

        enc_rnd_b = response.data
        if len(enc_rnd_b) < 16:
            return False, "Invalid challenge length"

        # Step 2: Decrypt RndB
        iv = bytes(8)
        cipher = DES3.new(bytes(key), DES3.MODE_CBC, iv=iv)
        rnd_b = list(cipher.decrypt(bytes(enc_rnd_b)))

        # Rotate RndB left by 1 byte
        rnd_b_rot = rnd_b[1:] + rnd_b[:1]

        # Generate RndA (16 bytes)
        rnd_a = list(os.urandom(16))

        # Step 3: Encrypt RndA + RndB'
        plain = rnd_a + rnd_b_rot
        iv = bytes(enc_rnd_b[-8:])
        cipher = DES3.new(bytes(key), DES3.MODE_CBC, iv=iv)
        enc_both = list(cipher.encrypt(bytes(plain)))

        # Step 4: Send encrypted response
        apdu = desfire_command(DESFireCmd.ADDITIONAL_FRAME, enc_both)
        response = self._transmit(apdu)
        if not response or not response.is_success:
            return False, f"Auth failed: {response.status_text if response else 'No response'}"

        # Step 5: Verify RndA'
        iv = bytes(enc_both[-8:])
        cipher = DES3.new(bytes(key), DES3.MODE_CBC, iv=iv)
        dec_rnd_a = list(cipher.decrypt(bytes(response.data)))
        rnd_a_rot = rnd_a[1:] + rnd_a[:1]

        if dec_rnd_a != rnd_a_rot:
            self._authenticated = False
            return False, "Authentication verification failed"

        # Session key for 3K3DES
        self._session_key = (rnd_a[:4] + rnd_b[:4] +
                             rnd_a[6:10] + rnd_b[6:10] +
                             rnd_a[12:16] + rnd_b[12:16])
        self._authenticated = True
        self._auth_key_type = DESFireKeyType.TDES_3K
        self._cmac_iv = bytes(16)
        return True, "ISO (3K3DES) authentication successful"

    # ─── Utility ─────────────────────────────────────────────────────────

    def scan_card(self) -> Dict:
        """
        Perform a full card scan: version, applications, files.
        Returns a dictionary with all card information.
        """
        result = {"success": False}

        # Get version
        version = self.get_version()
        if not version:
            result["error"] = "Failed to get card version"
            return result

        result["version"] = version.to_dict()
        result["success"] = True

        # Free memory
        free_mem = self.get_free_memory()
        if free_mem is not None:
            result["free_memory"] = f"{free_mem} bytes"

        # Get applications
        aids = self.get_application_ids()
        if aids is not None:
            result["applications"] = []
            for aid in aids:
                app_info = {"AID": bytes_to_hex(aid)}

                # Select app and get details
                if self.select_application(aid):
                    key_settings = self.get_key_settings()
                    if key_settings:
                        app_info["key_settings"] = key_settings

                    file_ids = self.get_file_ids()
                    if file_ids is not None:
                        app_info["files"] = {}
                        for fid in file_ids:
                            fs = self.get_file_settings(fid)
                            if fs:
                                app_info["files"][fid] = fs.to_dict()

                result["applications"].append(app_info)

            # Return to PICC level
            self.select_picc()

        return result
