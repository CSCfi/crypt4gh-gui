# SDS Uploader

This is a simple Graphical User Interface wrapped around the [crypt4gh python module](https://github.com/EGA-archive/crypt4gh). SDS Uploader is a modified Crypt4GH GUI with SFTP uploading feature.

## Demo
[![Demo Video](https://kannu.csc.fi/s/KP5paigcXnRo8fo/preview)](https://kannu.csc.fi/s/LiKpZ9zWznokjKn)

Click on the picture above to view the demo video

Current features:
- Generation of key pair
- Encryption of file(s)
- Direct uploading of encrypted file(s)
- Upload single files or whole directories
- Filled fields will be saved for later re-use
- Option to save password for session if encrypting and uploading multiple objects
- Supports RSA and Ed25519 keys or username+password for SFTP authentication

## Installation

The GUI requires:
- Python 3.6+
- Tkinter

```
git clone https://github.com/CSCfi/crypt4gh-gui
cd crypt4gh-gui
pip install .

sds_uploader
```

## Build Standalone Executable

Standalone executable build requires:
- pyinstaller

The GUI can be built into a standalone executable and distributed to machines that don't have python installed. After running the `pyinstaller` command, the standalone executable file can be found in the `dist/` directory.

```
pip install pyinstaller

pyinstaller --onefile crypt4gh_gui/crypt4gh_gui.py
```

This has been tested on Linux and Windows.

To run the executable on Linux:
```
./crypt4gh_gui
```

To run the executable on Windows:
- Double click on `crypt4gh_gui.exe` or run the following in `cmd`:
```
crypt4gh_gui.exe
```
