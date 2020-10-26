"""CSC SDS SFTP GUI."""

import sys
import json
import getpass
import tkinter as tk
from typing import Dict

from tkinter.simpledialog import askstring
from tkinter.filedialog import askopenfilename, askdirectory
from tkinter.scrolledtext import ScrolledText
from functools import partial
from platform import system

from crypt4gh.keys import c4gh, get_private_key, get_public_key

from .sftp import _sftp_connection, _sftp_upload_file, _sftp_upload_directory, _sftp_client
from pathlib import Path

OS_CONFIG = {"field_width": 40, "config_button_width": 25}
if system() == "Linux":
    # use default config
    pass
elif system() == "Darwin":
    # use default config
    pass
elif system() == "Windows":
    OS_CONFIG["field_width"] = 70
    OS_CONFIG["config_button_width"] = 30
else:
    # unknown OS, use default config
    pass


class GUI:
    """Graphical User Interface."""

    def __init__(self, window):
        """Initialise window."""
        self.window = window
        self.window.resizable(False, False)
        self.window.title("CSC Sensitive Data Submission Tool")
        # print to activity log instead of console
        sys.stdout.write = self.print_redirect  # type:ignore

        # Load previous values from config file
        self.config_file = Path(Path.home()).joinpath(".crypt4gh_config.json")
        data = self.read_config(self.config_file)

        # 1st column FIELDS AND LABELS

        self.my_key_label = tk.Label(window, text="My Private Key")
        self.my_key_label.grid(column=0, row=0, sticky=tk.W)
        self.my_key_value = tk.StringVar()
        self.my_key_field = tk.Entry(window, width=OS_CONFIG["field_width"], textvariable=self.my_key_value)
        self.my_key_field.grid(column=0, row=1, sticky=tk.W)
        self.my_key_field.config(state="disabled")
        private_key_file = data.get("private_key_file", None)
        if private_key_file and Path(private_key_file).is_file():
            self.my_key_value.set(private_key_file)

        self.their_key_label = tk.Label(window, text="Recipient Public Key")
        self.their_key_label.grid(column=0, row=2, sticky=tk.W)
        self.their_key_value = tk.StringVar()
        self.their_key_field = tk.Entry(window, width=OS_CONFIG["field_width"], textvariable=self.their_key_value)
        self.their_key_field.grid(column=0, row=3, sticky=tk.W)
        self.their_key_field.config(state="disabled")
        public_key_file = data.get("public_key_file", None)
        if public_key_file and Path(public_key_file).is_file():
            self.their_key_value.set(public_key_file)

        self.file_label = tk.Label(window, text="File or Directory to Upload")
        self.file_label.grid(column=0, row=4, sticky=tk.W)
        self.file_value = tk.StringVar()
        self.file_field = tk.Entry(window, width=OS_CONFIG["field_width"], textvariable=self.file_value)
        self.file_field.grid(column=0, row=5, sticky=tk.W)
        self.file_field.config(state="disabled")

        self.sftp_label = tk.Label(window, text="SFTP Credentials")
        self.sftp_label.grid(column=0, row=6, sticky=tk.W)
        self.sftp_value = tk.StringVar()
        placeholder_sftp_value = "username@server:22"
        self.sftp_value.set(placeholder_sftp_value)
        self.sftp_field = tk.Entry(window, width=OS_CONFIG["field_width"], textvariable=self.sftp_value)
        self.sftp_field.grid(column=0, row=7, sticky=tk.W)
        sftp_credentials = data.get("sftp_credentials", None)
        if sftp_credentials and len(sftp_credentials) > 0:
            self.sftp_value.set(sftp_credentials)

        self.sftp_key_label = tk.Label(window, text="SFTP Key (Optional)")
        self.sftp_key_label.grid(column=0, row=8, sticky=tk.W)
        self.sftp_key_value = tk.StringVar()
        self.sftp_key_field = tk.Entry(window, width=OS_CONFIG["field_width"], textvariable=self.sftp_key_value)
        self.sftp_key_field.grid(column=0, row=9, sticky=tk.W)
        self.sftp_key_field.config(state="disabled")
        sftp_key_file = data.get("sftp_key_file", None)
        if sftp_key_file and Path(sftp_key_file).is_file():
            self.sftp_key_value.set(sftp_key_file)

        self.activity_label = tk.Label(window, text="Activity Log")
        self.activity_label.grid(column=0, row=10, sticky=tk.W)
        self.activity_field = ScrolledText(window, height=12)
        self.activity_field.grid(column=0, row=11, columnspan=3, sticky=tk.W)
        self.activity_field.config(state="disabled")

        # 2nd column BUTTONS

        self.generate_keys_button = tk.Button(
            window,
            text="Generate Keys",
            width=OS_CONFIG["config_button_width"],
            command=partial(self.password_prompt, "generate"),
        )
        self.generate_keys_button.grid(column=1, row=0, sticky=tk.E, columnspan=2)

        self.load_my_key_button = tk.Button(
            window,
            text="Load My Private Key",
            width=OS_CONFIG["config_button_width"],
            command=partial(self.open_file, "private"),
        )
        self.load_my_key_button.grid(column=1, row=1, sticky=tk.E, columnspan=2)

        self.load_their_key_button = tk.Button(
            window,
            text="Load Recipient Public Key",
            width=OS_CONFIG["config_button_width"],
            command=partial(self.open_file, "public"),
        )
        self.load_their_key_button.grid(column=1, row=2, sticky=tk.E, columnspan=2)

        self.select_file_button = tk.Button(
            window,
            text="Select File to Upload",
            width=OS_CONFIG["config_button_width"],
            command=partial(self.open_file, "file"),
        )
        self.select_file_button.grid(column=1, row=3, sticky=tk.E, columnspan=2)

        self.select_directory_button = tk.Button(
            window,
            text="Select Directory to Upload",
            width=OS_CONFIG["config_button_width"],
            command=partial(self.open_file, "directory"),
        )
        self.select_directory_button.grid(column=1, row=4, sticky=tk.E, columnspan=2)

        self.load_sftp_key_button = tk.Button(
            window,
            text="Load SFTP Key",
            width=OS_CONFIG["config_button_width"],
            command=partial(self.open_file, "sftp_key"),
        )
        self.load_sftp_key_button.grid(column=1, row=5, sticky=tk.E, columnspan=2)

        self.encrypt_button = tk.Button(
            window,
            text="Encrypt and Upload File(s)",
            width=OS_CONFIG["config_button_width"],
            height=3,
            command=partial(self.password_prompt, "encrypt"),
        )
        self.encrypt_button.grid(column=1, row=7, sticky=tk.E, columnspan=2, rowspan=3)

        self.remember_pass = tk.IntVar()
        self.passwords = {"private_key": "", "sftp_key": ""}
        self.remember_password = tk.Checkbutton(
            window, text="Save password for this session", variable=self.remember_pass, onvalue=1, offvalue=0
        )
        self.remember_password.grid(column=1, row=10, sticky=tk.E)

    def print_redirect(self, message):
        """Print to activity log widget instead of console."""
        self.activity_field.config(state="normal")
        self.activity_field.insert(tk.END, message, None)
        self.activity_field.see(tk.END)
        self.activity_field.config(state="disabled")
        self.window.update()

    def open_file(self, action):
        """Open file and return result according to type."""
        if action == "private":
            private_key_path = askopenfilename()
            self.my_key_value.set(private_key_path)
        elif action == "public":
            public_key_path = askopenfilename()
            self.their_key_value.set(public_key_path)
        elif action == "file":
            file_path = askopenfilename()
            self.file_value.set(file_path)
            if len(file_path) > 0:
                self.select_directory_button.config(state="disabled")
            else:
                self.select_directory_button.config(state="normal")
        elif action == "directory":
            file_path = askdirectory()
            self.file_value.set(file_path)
            if len(file_path) > 0:
                self.select_file_button.config(state="disabled")
            else:
                self.select_file_button.config(state="normal")
        elif action == "sftp_key":
            file_path = askopenfilename()
            self.sftp_key_value.set(file_path)
        else:
            print(f"Unknown action: {action}")

    def _generate_password(self):
        password = ""
        # Passphrase for private key generation
        password = askstring("Private Key Passphrase", "Private Key Passphrase", show="*")
        # This if-clause is for preventing error messages
        if password is None:
            return
        while len(password) == 0:
            password = askstring("Private Key Passphrase", "Passphrase can't be empty", show="*")
            # This if-clause is for preventing error messages
            if password is None:
                return
        # Use crypt4gh module to generate private and public keys
        c4gh.generate(
            f"{getpass.getuser()}_crypt4gh.key",
            f"{getpass.getuser()}_crypt4gh.pub",
            callback=partial(self.mock_callback, password),
        )
        print("Key pair has been generated, your private key will be auto-loaded the next time you launch this tool")
        print(f"Private key: {getpass.getuser()}_crypt4gh.key")
        print(f"Public key: {getpass.getuser()}_crypt4gh.pub")

    def _get_private_key(self, password):
        private_key = None
        try:
            private_key = get_private_key(self.my_key_value.get(), partial(self.mock_callback, password))
        except Exception:
            self.passwords["private_key"] = ""
            print("Incorrect private key passphrase")
            return
        # Ask for RSA key password
        sftp_password = self.passwords["sftp_key"]
        while len(sftp_password) == 0:
            sftp_password = askstring("SFTP Passphrase", "Passphrase for SFTP KEY or USERNAME", show="*")
            if self.remember_pass.get():
                self.passwords["sftp_key"] = sftp_password
            # This if-clause is for preventing error messages
            if sftp_password is None:
                return
        # Test SFTP connection
        sftp_credentials = self.sftp_value.get().split("@")
        sftp_username = sftp_credentials[0]
        sftp_hostname = sftp_credentials[1].split(":")[0]
        sftp_port = sftp_credentials[1].split(":")[1]
        sftp_auth = self.test_sftp_connection(
            username=sftp_username,
            hostname=sftp_hostname,
            port=sftp_port,
            rsa_key=self.sftp_key_value.get(),
            sftp_pass=sftp_password,
        )
        # Encrypt and upload
        if private_key and sftp_auth:
            sftp = _sftp_client(
                username=sftp_username,
                hostname=sftp_hostname,
                port=sftp_port,
                sftp_auth=sftp_auth,
            )
            public_key = get_public_key(self.their_key_value.get())
            self.sftp_upload(sftp=sftp, target=self.file_value.get(), private_key=private_key, public_key=public_key)
        else:
            print("Could not form SFTP connection.")

    def _get_encryption_password(self):
        password = ""
        # Check that all fields are filled before asking for password
        if self.my_key_value.get() and self.their_key_value.get() and self.file_value.get() and self.sftp_value.get():
            # Ask for passphrase for private key encryption
            password = self.passwords["private_key"]
            while len(password) == 0:
                password = askstring("Private Key Passphrase", "Passphrase for PRIVATE KEY", show="*")
                if self.remember_pass.get():
                    self.passwords["private_key"] = password
                # This if-clause is for preventing error messages
                if password is None:
                    return
            self._get_private_key(password)
        else:
            print("All fields must be filled before file upload can be started")

    def password_prompt(self, action):
        """Ask user for private key password."""

        if action == "generate":
            self._generate_password()
        elif action == "encrypt":
            self._get_encryption_password()
        else:
            print(f"Unknown action: {action}")

    def mock_callback(self, password):
        """Mock callback to return password."""
        return password

    def write_config(self):
        """Save field values for re-runs."""
        data = {
            "private_key_file": self.my_key_value.get(),
            "public_key_file": self.their_key_value.get(),
            "sftp_credentials": self.sftp_value.get(),
            "sftp_key_file": self.sftp_key_value.get(),
        }
        with open(self.config_file, "w") as f:
            f.write(json.dumps(data))

    def read_config(self, path) -> Dict[str, str]:
        """Read field values from previous run if they exist."""
        data = {}
        if Path(path).is_file():
            with open(path, "r") as f:
                data = json.loads(f.read())
        return data

    def test_sftp_connection(self, username=None, hostname=None, port=22, rsa_key=None, sftp_pass=None):
        """Test SFTP connection and determine key type before uploading."""
        sftp_auth = _sftp_connection(username, hostname, port, rsa_key, sftp_pass)
        self.write_config()  # save fields
        return sftp_auth

    def sftp_upload(self, sftp=None, target=None, private_key=None, public_key=None):
        """Upload file or directory."""
        print("Starting upload process.")

        if Path(target).is_file():
            _sftp_upload_file(
                sftp=sftp,
                source=target,
                destination=Path(target).name,
                private_key=private_key,
                public_key=public_key,
            )

        if Path(target).is_dir():
            _sftp_upload_directory(sftp=sftp, directory=target, private_key=private_key, public_key=public_key)

        # Close SFTP connection
        print("Disconnecting SFTP.")
        sftp.close()
        print("SFTP has been disconnected.")
