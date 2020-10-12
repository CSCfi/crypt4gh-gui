# -*- mode: python ; coding: utf-8 -*-

block_cipher = None


a = Analysis(['crypt4gh_gui.py'],
             pathex=[],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
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
          a.binaries + [('GA-logo.ico', 'GA-logo.ico', 'DATA')],
          a.zipfiles,
          a.datas,
          [],
          name='crypt4gh_gui',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          upx_exclude=[],
          runtime_tmpdir=None,
          console=False,
	  icon='GA-logo.ico')
