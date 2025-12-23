#!/usr/bin/env python3
"""
Smart Card Reader Application
==============================
A modern, fluid application for reading smart card badges including
MIFARE DESFire EV1/EV2/EV3, JavaCard, and more.

Features:
- PC/SC reader selection and management
- DESFire EV1/EV2/EV3 card reading and authentication
- JavaCard applet interaction
- Key diversification (AN10922 AES-128, 2K3DES)
- Raw APDU console
- Modern dark theme UI

Usage:
    python main.py

Requirements:
    pip install -r requirements.txt
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def check_dependencies():
    """Check that required dependencies are installed."""
    missing = []

    try:
        import customtkinter
    except ImportError:
        missing.append("customtkinter")

    try:
        import smartcard
    except ImportError:
        missing.append("pyscard")

    try:
        from Crypto.Cipher import AES
    except ImportError:
        missing.append("pycryptodome")

    if missing:
        print("=" * 60)
        print("  Smart Card Reader - Missing Dependencies")
        print("=" * 60)
        print()
        print("  The following packages need to be installed:")
        print()
        for pkg in missing:
            print(f"    - {pkg}")
        print()
        print("  Install them with:")
        print(f"    pip install {' '.join(missing)}")
        print()
        print("  Or install all at once:")
        print("    pip install -r requirements.txt")
        print()
        print("=" * 60)

        # Only pyscard and customtkinter are required to start
        if "customtkinter" in missing:
            sys.exit(1)

    return missing


def main():
    """Application entry point."""
    missing = check_dependencies()

    if "pyscard" in missing:
        print("\n  [WARNING] pyscard is not installed.")
        print("  Reader functionality will be unavailable.")
        print("  Install it with: pip install pyscard\n")

    if "pycryptodome" in missing:
        print("\n  [WARNING] pycryptodome is not installed.")
        print("  Authentication and diversification will be unavailable.")
        print("  Install it with: pip install pycryptodome\n")

    from ui.app import SmartCardApp

    app = SmartCardApp()
    app.mainloop()


if __name__ == "__main__":
    main()
