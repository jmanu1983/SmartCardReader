# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_data_files

datas = []
datas += collect_data_files('customtkinter')


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=['smartcard', 'smartcard.System', 'smartcard.CardConnection', 'smartcard.CardMonitoring', 'smartcard.ReaderMonitoring', 'smartcard.Exceptions', 'smartcard.util', 'smartcard.pcsc', 'smartcard.pcsc.PCSCReader', 'smartcard.pcsc.PCSCCardConnection', 'smartcard.scard', 'Crypto', 'Crypto.Cipher', 'Crypto.Cipher.AES', 'Crypto.Cipher.DES', 'Crypto.Cipher.DES3', 'customtkinter', 'darkdetect', 'PIL'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SmartCardReader',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
