"""
Key diversification algorithms for NXP smart cards.
Implements AN10922 (AES-128 CMAC and 3DES CMAC based diversification)
and AN10957 diversification methods.
"""

import struct
from typing import List, Optional

try:
    from Crypto.Cipher import AES, DES3
    from Crypto.Hash import CMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from .apdu import bytes_to_hex, hex_to_bytes


# ─── CMAC Subkey Generation ────────────────────────────────────────────────

def _shift_left(data: bytes) -> bytes:
    """Shift a byte array left by 1 bit."""
    result = bytearray(len(data))
    overflow = 0
    for i in range(len(data) - 1, -1, -1):
        result[i] = ((data[i] << 1) & 0xFF) | overflow
        overflow = 1 if (data[i] & 0x80) else 0
    return bytes(result)


def _generate_cmac_subkeys_aes(key: bytes) -> tuple:
    """
    Generate CMAC subkeys K1, K2 for AES-128.
    Per NIST SP 800-38B / AN10922.
    """
    cipher = AES.new(key, AES.MODE_ECB)
    L = cipher.encrypt(b'\x00' * 16)

    # K1
    K1 = _shift_left(L)
    if L[0] & 0x80:
        K1 = bytes(a ^ b for a, b in zip(K1, b'\x00' * 15 + b'\x87'))

    # K2
    K2 = _shift_left(K1)
    if K1[0] & 0x80:
        K2 = bytes(a ^ b for a, b in zip(K2, b'\x00' * 15 + b'\x87'))

    return K1, K2


def _generate_cmac_subkeys_3des(key: bytes) -> tuple:
    """
    Generate CMAC subkeys K1, K2 for 2K3DES.
    """
    cipher = DES3.new(key, DES3.MODE_ECB)
    L = cipher.encrypt(b'\x00' * 8)

    # K1
    K1 = _shift_left(L)
    if L[0] & 0x80:
        K1 = bytes(a ^ b for a, b in zip(K1, b'\x00' * 7 + b'\x1B'))

    # K2
    K2 = _shift_left(K1)
    if K1[0] & 0x80:
        K2 = bytes(a ^ b for a, b in zip(K2, b'\x00' * 7 + b'\x1B'))

    return K1, K2


def _cmac_aes(key: bytes, message: bytes) -> bytes:
    """
    Calculate AES-128 CMAC.
    """
    K1, K2 = _generate_cmac_subkeys_aes(key)
    block_size = 16

    # Pad or complete the last block
    n_blocks = max(1, (len(message) + block_size - 1) // block_size)
    last_block_complete = (len(message) > 0) and (len(message) % block_size == 0)

    if last_block_complete:
        # XOR with K1
        blocks = bytearray(message)
        for i in range(block_size):
            blocks[-(block_size - i)] ^= K1[i]
        padded = bytes(blocks)
    else:
        # Pad and XOR with K2
        padded = bytearray(message) + bytearray([0x80]) + bytearray(block_size - 1 - (len(message) % block_size))
        padded = padded[:n_blocks * block_size]
        for i in range(block_size):
            padded[-(block_size - i)] ^= K2[i]
        padded = bytes(padded)

    # CBC-MAC
    cipher = AES.new(key, AES.MODE_CBC, iv=b'\x00' * block_size)
    encrypted = cipher.encrypt(padded)
    return encrypted[-block_size:]


def _cmac_3des(key: bytes, message: bytes) -> bytes:
    """
    Calculate 2K3DES CMAC.
    """
    K1, K2 = _generate_cmac_subkeys_3des(key)
    block_size = 8

    n_blocks = max(1, (len(message) + block_size - 1) // block_size)
    last_block_complete = (len(message) > 0) and (len(message) % block_size == 0)

    if last_block_complete:
        blocks = bytearray(message)
        for i in range(block_size):
            blocks[-(block_size - i)] ^= K1[i]
        padded = bytes(blocks)
    else:
        padded = bytearray(message) + bytearray([0x80]) + bytearray(block_size - 1 - (len(message) % block_size))
        padded = padded[:n_blocks * block_size]
        for i in range(block_size):
            padded[-(block_size - i)] ^= K2[i]
        padded = bytes(padded)

    cipher = DES3.new(key, DES3.MODE_CBC, iv=b'\x00' * block_size)
    encrypted = cipher.encrypt(padded)
    return encrypted[-block_size:]


# ─── AN10922 Key Diversification ────────────────────────────────────────────

class DiversificationMethod:
    """Enumeration of supported diversification methods."""
    AN10922_AES128 = "AN10922 AES-128"
    AN10922_2K3DES = "AN10922 2K3DES"
    CUSTOM_AES = "Custom AES CMAC"


def diversify_key_an10922_aes128(
    master_key: List[int],
    uid: List[int],
    aid: Optional[List[int]] = None,
    system_identifier: Optional[List[int]] = None
) -> List[int]:
    """
    Diversify an AES-128 key according to NXP AN10922.

    Args:
        master_key: 16-byte master key
        uid: 7-byte UID (or 4-byte for classic)
        aid: Optional 3-byte application ID
        system_identifier: Optional additional identifier bytes

    Returns:
        16-byte diversified key
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("pycryptodome required for key diversification")

    key = bytes(master_key)

    # Build diversification input
    # Byte 0: 0x01 (AES diversification constant)
    div_input = bytearray([0x01])

    # Add UID
    div_input.extend(uid)

    # Add AID if provided
    if aid:
        div_input.extend(aid)

    # Add system identifier if provided
    if system_identifier:
        div_input.extend(system_identifier)

    # Pad to 32 bytes (2 AES blocks) as per AN10922
    while len(div_input) < 32:
        div_input.append(0x00)

    # Calculate CMAC
    diversified = _cmac_aes(key, bytes(div_input[:32]))

    return list(diversified)


def diversify_key_an10922_2k3des(
    master_key: List[int],
    uid: List[int],
    aid: Optional[List[int]] = None,
    system_identifier: Optional[List[int]] = None
) -> List[int]:
    """
    Diversify a 2K3DES key according to NXP AN10922.

    Args:
        master_key: 16-byte 2K3DES master key
        uid: 7-byte UID
        aid: Optional 3-byte application ID
        system_identifier: Optional additional identifier bytes

    Returns:
        16-byte diversified key
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("pycryptodome required for key diversification")

    key = bytes(master_key)

    # First half - diversification constant 0x01
    div_input_1 = bytearray([0x01])
    div_input_1.extend(uid)
    if aid:
        div_input_1.extend(aid)
    if system_identifier:
        div_input_1.extend(system_identifier)
    while len(div_input_1) < 16:
        div_input_1.append(0x00)

    # Second half - diversification constant 0x02
    div_input_2 = bytearray([0x02])
    div_input_2.extend(uid)
    if aid:
        div_input_2.extend(aid)
    if system_identifier:
        div_input_2.extend(system_identifier)
    while len(div_input_2) < 16:
        div_input_2.append(0x00)

    half1 = _cmac_3des(key, bytes(div_input_1[:16]))
    half2 = _cmac_3des(key, bytes(div_input_2[:16]))

    return list(half1) + list(half2)


def diversify_key_custom(
    master_key: List[int],
    diversification_data: List[int],
    method: str = DiversificationMethod.AN10922_AES128
) -> List[int]:
    """
    Generic key diversification with custom data.

    Args:
        master_key: Master key bytes
        diversification_data: Raw diversification input data
        method: Diversification method to use

    Returns:
        Diversified key bytes
    """
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("pycryptodome required for key diversification")

    key = bytes(master_key)
    data = bytes(diversification_data)

    if method == DiversificationMethod.AN10922_AES128:
        # AES CMAC
        padded = bytearray(data)
        while len(padded) < 32:
            padded.append(0x00)
        return list(_cmac_aes(key, bytes(padded[:32])))

    elif method == DiversificationMethod.AN10922_2K3DES:
        # 3DES CMAC - split into two halves
        padded = bytearray(data)
        while len(padded) < 16:
            padded.append(0x00)
        half1 = _cmac_3des(key, bytes(padded[:16]))

        padded2 = bytearray([0x02]) + bytearray(data)
        while len(padded2) < 16:
            padded2.append(0x00)
        half2 = _cmac_3des(key, bytes(padded2[:16]))
        return list(half1) + list(half2)

    elif method == DiversificationMethod.CUSTOM_AES:
        # Simple AES CMAC of the data
        return list(_cmac_aes(key, data))

    else:
        raise ValueError(f"Unknown diversification method: {method}")


# ─── Utility ────────────────────────────────────────────────────────────────

def format_diversification_info(
    master_key: List[int],
    uid: List[int],
    aid: Optional[List[int]],
    system_id: Optional[List[int]],
    method: str,
    result: List[int]
) -> str:
    """Format diversification result as a readable string."""
    lines = [
        f"Method: {method}",
        f"Master Key:    {bytes_to_hex(master_key)}",
        f"UID:           {bytes_to_hex(uid)}",
    ]
    if aid:
        lines.append(f"AID:           {bytes_to_hex(aid)}")
    if system_id:
        lines.append(f"System ID:     {bytes_to_hex(system_id)}")
    lines.append(f"Diversified:   {bytes_to_hex(result)}")
    return "\n".join(lines)
