"""CSC SDS SFTP GUI."""

import os
import sys
import json
import getpass
import tkinter as tk
import paramiko

from tkinter.simpledialog import askstring
from tkinter.filedialog import askopenfilename, askdirectory
from tkinter.scrolledtext import ScrolledText
from functools import partial
from platform import system

from crypt4gh.keys import c4gh, get_private_key, get_public_key
from crypt4gh.lib import encrypt

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
        sys.stdout.write = self.print_redirect  # print to activity log instead of console

        # Load previous values from config file
        self.config_file = os.path.join(os.path.expanduser("~"), ".crypt4gh_config.json")
        data = self.read_config(self.config_file)

        # 1st column FIELDS AND LABELS

        self.my_key_label = tk.Label(window, text="My Private Key")
        self.my_key_label.grid(column=0, row=0, sticky=tk.W)
        self.my_key_value = tk.StringVar()
        self.my_key_field = tk.Entry(window, width=OS_CONFIG["field_width"], textvariable=self.my_key_value)
        self.my_key_field.grid(column=0, row=1, sticky=tk.W)
        self.my_key_field.config(state="disabled")
        if data.get("private_key_file") is not None and os.path.isfile(data.get("private_key_file")):
            self.my_key_value.set(data.get("private_key_file"))

        self.their_key_label = tk.Label(window, text="Recipient Public Key")
        self.their_key_label.grid(column=0, row=2, sticky=tk.W)
        self.their_key_value = tk.StringVar()
        self.their_key_field = tk.Entry(window, width=OS_CONFIG["field_width"], textvariable=self.their_key_value)
        self.their_key_field.grid(column=0, row=3, sticky=tk.W)
        self.their_key_field.config(state="disabled")
        if data.get("public_key_file") is not None and os.path.isfile(data.get("public_key_file")):
            self.their_key_value.set(data.get("public_key_file"))

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
        if data.get("sftp_credentials") is not None and len(data.get("sftp_credentials")) > 0:
            self.sftp_value.set(data.get("sftp_credentials"))

        self.sftp_key_label = tk.Label(window, text="SFTP Key (Optional)")
        self.sftp_key_label.grid(column=0, row=8, sticky=tk.W)
        self.sftp_key_value = tk.StringVar()
        self.sftp_key_field = tk.Entry(window, width=OS_CONFIG["field_width"], textvariable=self.sftp_key_value)
        self.sftp_key_field.grid(column=0, row=9, sticky=tk.W)
        self.sftp_key_field.config(state="disabled")
        if data.get("sftp_key_file") is not None and os.path.isfile(data.get("sftp_key_file")):
            self.sftp_key_value.set(data.get("sftp_key_file"))

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

    def password_prompt(self, action):
        """Ask user for private key password."""
        password = ""
        if action == "generate":
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
            print(
                "Key pair has been generated, your private key will be auto-loaded the next time you launch this tool"
            )
            print(f"Private key: {getpass.getuser()}_crypt4gh.key")
            print(f"Public key: {getpass.getuser()}_crypt4gh.pub")
        elif action == "encrypt":
            # Check that all fields are filled before asking for password
            if (
                self.my_key_value.get()
                and self.their_key_value.get()
                and self.file_value.get()
                and self.sftp_value.get()
            ):
                # Ask for passphrase for private key encryption
                password = self.passwords["private_key"]
                while len(password) == 0:
                    password = askstring("Private Key Passphrase", "Passphrase for PRIVATE KEY", show="*")
                    if self.remember_pass.get():
                        self.passwords["private_key"] = password
                    # This if-clause is for preventing error messages
                    if password is None:
                        return
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
                    sftp = self.sftp_client(
                        username=sftp_username,
                        hostname=sftp_hostname,
                        port=sftp_port,
                        sftp_auth=sftp_auth,
                    )
                    public_key = get_public_key(self.their_key_value.get())
                    self.sftp_upload(
                        sftp=sftp, target=self.file_value.get(), private_key=private_key, public_key=public_key
                    )
                else:
                    print("Could not form SFTP connection.")
            else:
                print("All fields must be filled before file upload can be started")
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

    def read_config(self, path):
        """Read field values from previous run if they exist."""
        data = {}
        if os.path.isfile(path):
            with open(path, "r") as f:
                data = json.loads(f.read())
        return data

    def test_sftp_connection(self, username=None, hostname=None, port=22, rsa_key=None, sftp_pass=None):
        """Test SFTP connection and determine key type before uploading."""
        print("Testing connection to SFTP server.")
        print(
            f'SFTP testing timeout is: {os.environ.get("SFTP_TIMEOUT", 5)}. You can change this with environment variable $SFTP_TIMEOUT'
        )
        # Test if key is RSA
        try:
            print("Testing if SFTP key is of type RSA")
            client = paramiko.SSHClient()
            paramiko_key = paramiko.RSAKey.from_private_key_file(rsa_key, password=sftp_pass)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname,
                allow_agent=False,
                look_for_keys=False,
                port=port,
                timeout=int(os.environ.get("SFTP_TIMEOUT", 5)),
                username=username,
                pkey=paramiko_key,
            )
            print("SFTP test connection: OK")
            self.write_config()  # save fields
            return paramiko_key
        except Exception as e:
            print(f"SFTP Error: {e}")
        finally:
            client.close()
        # Test if key is ed25519
        try:
            print("Testing if SFTP key is of type Ed25519")
            client = paramiko.SSHClient()
            paramiko_key = paramiko.ed25519key.Ed25519Key(filename=rsa_key, password=sftp_pass)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname,
                allow_agent=False,
                look_for_keys=False,
                port=port,
                timeout=int(os.environ.get("SFTP_TIMEOUT", 5)),
                username=username,
                pkey=paramiko_key,
            )
            print("SFTP test connection: OK")
            self.write_config()  # save fields
            return paramiko_key
        except Exception as e:
            print(f"SFTP Error: {e}")
        finally:
            client.close()
        # Authenticating with password, if key is not set
        try:
            print("Testing if SFTP auth scheme is username+password")
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname,
                allow_agent=False,
                look_for_keys=False,
                port=port,
                timeout=int(os.environ.get("SFTP_TIMEOUT", 5)),
                username=username,
                password=sftp_pass,
            )
            print("SFTP test connection: OK")
            self.write_config()  # save fields
            return sftp_pass
        except Exception as e:
            print(f"SFTP Error: {e}")
        finally:
            client.close()
        return False  # neither keys or password worked

    def sftp_client(self, username=None, hostname=None, port=22, sftp_auth=None):
        """SFTP client."""
        try:
            print(f"Connecting to {hostname} as {username}.")
            transport = paramiko.Transport((hostname, int(port)))
            if self.sftp_key_value.get():
                # If SFTP key is set, authenticate with that
                transport.connect(username=username, pkey=sftp_auth)
            else:
                # If key is not set, authenticate with password
                transport.connect(username=username, password=sftp_auth)
            sftp = paramiko.SFTPClient.from_transport(transport)
            print("SFTP connected, ready to upload files.")
            return sftp
        except paramiko.BadHostKeyException as e:
            print(f"SFTP error: {e}")
            raise Exception("BadHostKeyException on " + hostname)
        except paramiko.AuthenticationException as e:
            print(f"SFTP authentication failed, error: {e}")
            raise Exception("AuthenticationException on " + hostname)
        except paramiko.SSHException as e:
            print(f"Could not connect to {hostname}, error: {e}")
            raise Exception("SSHException on " + hostname)
        except Exception as e:
            print(f"SFTP Error: {e}")

        return False

    def sftp_upload(self, sftp=None, target=None, private_key=None, public_key=None):
        """Upload file or directory."""
        print("Starting upload process.")

        if os.path.isfile(target):
            self.upload_file(
                sftp=sftp,
                source=target,
                destination=os.path.basename(target),
                private_key=private_key,
                public_key=public_key,
            )

        if os.path.isdir(target):
            self.upload_directory(sftp=sftp, directory=target, private_key=private_key, public_key=public_key)

        # Close SFTP connection
        print("Disconnecting SFTP.")
        sftp.close()
        print("SFTP has been disconnected.")

    def upload_file(self, sftp=None, source=None, destination=None, private_key=None, public_key=None):
        """Upload a single file."""
        verified = self.verify_crypt4gh_header(source)
        if verified:
            print(f"File {source} was recognised as a Crypt4GH file, and will be uploaded.")
            print(f"Uploading {source}")
            sftp.put(source, destination)
            print(f"{source} has been uploaded.")
        else:
            # Encrypt before uploading
            print(f"File {source} was not recognised as a Crypt4GH file, and must be encrypted before uploading.")
            self.encrypt_file(file=source, private_key_file=private_key, recipient_public_key=public_key)
            print(f"Uploading {source}.c4gh")
            sftp.put(f"{source}.c4gh", f"{destination}.c4gh")
            print(f"{source}.c4gh has been uploaded.")
            print(f"Removing auto-encrypted file {source}.c4gh")
            os.remove(f"{source}.c4gh")
            print(f"{source}.c4gh removed")

    def upload_directory(self, sftp=None, directory=None, private_key=None, public_key=None):
        """Upload directory."""
        sftp_dir = ""
        for item in os.walk(directory):
            sftp_dir = os.path.join(sftp_dir, os.path.basename(item[0]))
            try:
                sftp.mkdir(sftp_dir)
                print(f"Directory {sftp_dir} created.")
            except OSError:
                print(f"Skipping directory {sftp_dir} creation, as it already exists.")
            for sub_item in item[2]:
                self.upload_file(
                    sftp=sftp,
                    source=os.path.join(item[0], sub_item),
                    destination=f"/{os.path.join(sftp_dir, sub_item)}",
                    private_key=private_key,
                    public_key=public_key,
                )

    def encrypt_file(self, file=None, private_key_file=None, recipient_public_key=None):
        """Encrypt a file with Crypt4GH."""
        print(f"Encrypting {file} as {file}.c4gh")
        original_file = open(file, "rb")
        encrypted_file = open(f"{file}.c4gh", "wb")
        encrypt([(0, private_key_file, recipient_public_key)], original_file, encrypted_file)
        original_file.close()
        encrypted_file.close()
        print("Encryption has finished.")

    def verify_crypt4gh_header(self, file=None):
        """Verify, that a file has Crypt4GH header."""
        print("Verifying file Crypt4GH header.")
        with open(file, "rb") as f:
            header = f.read()[:8]
            if header == b"crypt4gh":
                return True
            else:
                return False



