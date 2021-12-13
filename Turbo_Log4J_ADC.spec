# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.building.build_main import *
import sys
import os
from kivy_deps import sdl2, glew
from kivymd import hooks_path as kivymd_hooks_path

block_cipher = None


a = Analysis(['main.py'],
             pathex=['C:\\Users\\Mick\\PycharmProjects\\Turbo_Log4J_ADC'],
             binaries=[],
             datas=[('Log4j_ADC.kv', '.'), ('Images', '.'),] ,
             hiddenimports=[],
             hookspath=[],
             hooksconfig={},
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          *[Tree(p) for p in (sdl2.dep_bins + glew.dep_bins)],
          name='Turbo_Log4j_ADC',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          icon='.\\Images\Icon.Ico',
          console=False )
