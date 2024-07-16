# GUI for Crypt4GH

This is a simple Graphical User Interface wrapped around the [crypt4gh python module](https://github.com/EGA-archive/crypt4gh).

## Demo
[![Demo Video](https://kannu.csc.fi/apps/files_sharing/publicpreview/4fx4MiMjpRdXc2x?x=1914&y=531&a=true&file=crypt4gh-gui-video-thumbnail.jpg)](https://kannu.csc.fi/s/kYYW64PPaeccEnY)

Click on the picture above to view the demo video

Current features:
- Generation of key pair (optional)
- Encryption of file with existing private key (optional)
- Encryption of file with generated temporary private key
- Decryption of file
- Decryption of file with sender public key validation (optional)
- Sender signature validation (optional)

For more advanced features, please refer to the [CLI](https://github.com/EGA-archive/crypt4gh#usage) instead.

## Installation

The GUI requires a python installation with [tkinter](https://docs.python.org/3/library/tkinter.html)
```bash
git clone https://github.com/CSCfi/crypt4gh-gui
pip install -r requirements.txt

python crypt4gh_gui.py
```

## Build Standalone Executable

Standalone executable build requires:
- pyinstaller

The GUI can be built into a standalone executable and distributed to machines that don't have python installed. After running the `pyinstaller` command, the standalone executable file can be found in the `dist/` directory.

```bash
pip install pyinstaller

pyinstaller --onefile crypt4gh_gui.py
```

This has been tested on Linux and Windows.

To run the executable on Linux:
```bash
./crypt4gh_gui
```

To run the executable on Windows:
- Double click on `crypt4gh_gui.exe` or run the following in `cmd`:
```bash
crypt4gh_gui.exe
```

### Ready-to-use Releases
You can download a pre-built executable from the [releases page](https://github.com/CSCfi/crypt4gh-gui/releases).

1. Download a zip archive for your current operating system
2. Extract the archive to get the executable

Note that the Linux and Windows builds are created with `amd64` architecture, and the MacOS build is created with `arm64` architecture. For other architectures you must build the executable yourself with the instructions above.
