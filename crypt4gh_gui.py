import os
import sys
import getpass
import tkinter as tk

from tkinter.simpledialog import askstring
from tkinter.filedialog import askopenfilename
from tkinter.scrolledtext import ScrolledText
from functools import partial
from platform import system

from crypt4gh.keys import c4gh, get_private_key, get_public_key
from crypt4gh.lib import encrypt, decrypt

OS_CONFIG = {
    'field_width': 40,
    'config_button_width': 25,
    'operation_button_width': 10
}
if system() == 'Linux':
    # use default config
    pass
elif system() == 'Darwin':
    # MacOS, untested, use default config
    pass
elif system() == 'Windows':
    OS_CONFIG['field_width'] = 70
    OS_CONFIG['config_button_width'] = 30
    OS_CONFIG['operation_button_width'] = 14
else:
    # unknown OS, use default config
    pass


class GUI:
    """Graphical User Interface."""

    def __init__(self, window):
        """Initialise window."""
        self.window = window
        self.window.resizable(False, False)
        self.window.title("Crypt4GH")
        sys.stdout.write = self.print_redirect  # print to activity log instead of console

        # 1st column FIELDS AND LABELS

        self.my_key_label = tk.Label(window, text='My Private Key')
        self.my_key_label.grid(column=0, row=0, sticky=tk.W)
        self.my_key_value = tk.StringVar()
        self.my_key_field = tk.Entry(window, width=OS_CONFIG['field_width'], textvariable=self.my_key_value)
        self.my_key_field.grid(column=0, row=1, sticky=tk.W)
        self.my_key_field.config(state='disabled')
        # Auto-load generated private key if such exists: username_crypt4gh.key (can be changed in UI)
        default_private_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f'{getpass.getuser()}_crypt4gh.key')
        if os.path.isfile(default_private_key_path):
            self.my_key_value.set(default_private_key_path)

        self.their_key_label = tk.Label(window, text='Their Public Key')
        self.their_key_label.grid(column=0, row=2, sticky=tk.W)
        self.their_key_value = tk.StringVar()
        self.their_key_field = tk.Entry(window, width=OS_CONFIG['field_width'], textvariable=self.their_key_value)
        self.their_key_field.grid(column=0, row=3, sticky=tk.W)
        self.their_key_field.config(state='disabled')

        self.file_label = tk.Label(window, text='File to Encrypt/Decrypt')
        self.file_label.grid(column=0, row=4, sticky=tk.W)
        self.file_value = tk.StringVar()
        self.file_field = tk.Entry(window, width=OS_CONFIG['field_width'], textvariable=self.file_value)
        self.file_field.grid(column=0, row=5, sticky=tk.W)
        self.file_field.config(state='disabled')

        self.activity_label = tk.Label(window, text='Activity Log')
        self.activity_label.grid(column=0, row=6, sticky=tk.W)
        self.activity_field = ScrolledText(window, height=10)
        self.activity_field.grid(column=0, row=7, columnspan=3, sticky=tk.W)
        self.activity_field.config(state='disabled')

        # 2nd column BUTTONS

        self.generate_keys_button = tk.Button(window, text='Generate Keys', width=OS_CONFIG['config_button_width'], command=partial(self.password_prompt, 'generate'))
        self.generate_keys_button.grid(column=1, row=0, sticky=tk.E, columnspan=2)

        self.load_my_key_button = tk.Button(window, text='Load My Private Key', width=OS_CONFIG['config_button_width'], command=partial(self.open_file, 'private'))
        self.load_my_key_button.grid(column=1, row=1, sticky=tk.E, columnspan=2)

        self.load_their_key_button = tk.Button(window, text='Load Their Public Key', width=OS_CONFIG['config_button_width'], command=partial(self.open_file, 'public'))
        self.load_their_key_button.grid(column=1, row=2, sticky=tk.E, columnspan=2)

        self.select_file_button = tk.Button(window, text='Select File', width=OS_CONFIG['config_button_width'], command=partial(self.open_file, 'file'))
        self.select_file_button.grid(column=1, row=3, sticky=tk.E, columnspan=2)

        self.encrypt_button = tk.Button(window, text='Encrypt File', width=OS_CONFIG['operation_button_width'], height=3, command=partial(self.password_prompt, 'encrypt'))
        self.encrypt_button.grid(column=1, row=4, sticky=tk.E, rowspan=3)

        self.decrypt_button = tk.Button(window, text='Decrypt File', width=OS_CONFIG['operation_button_width'], height=3, command=partial(self.password_prompt, 'decrypt'))
        self.decrypt_button.grid(column=2, row=4, sticky=tk.E, rowspan=3)

    def print_redirect(self, message):
        """Print to activity log widget instead of console."""
        self.activity_field.config(state='normal')
        self.activity_field.insert(tk.END, message, None)
        self.activity_field.see(tk.END)
        self.activity_field.config(state='disabled')
        self.window.update()

    def open_file(self, action):
        """Open file and return result according to type."""
        if action == 'private':
            private_key_path = askopenfilename()
            self.my_key_value.set(private_key_path)
        elif action == 'public':
            public_key_path = askopenfilename()
            self.their_key_value.set(public_key_path)
        elif action == 'file':
            file_path = askopenfilename()
            self.file_value.set(file_path)
        else:
            print(f'Unknown action: {action}')

    def password_prompt(self, action):
        """Ask user for private key password."""
        password = ''
        if action == 'generate':
            # Passphrase for private key generation
            password = askstring('Private Key Passphrase', 'Private Key Passphrase', show='*')
            # This if-clause is for preventing error messages
            if password is None:
                return
            while len(password) == 0:
                password = askstring('Private Key Passphrase', 'Passphrase can\'t be empty', show='*')
                # This if-clause is for preventing error messages
                if password is None:
                    return
            # Use crypt4gh module to generate private and public keys
            c4gh.generate(f'{getpass.getuser()}_crypt4gh.key', f'{getpass.getuser()}_crypt4gh.pub', callback=partial(self.mock_callback, password))
            print('Key pair has been generated, your private key will be auto-loaded the next time you launch this tool')
            print(f'Private key: {getpass.getuser()}_crypt4gh.key')
            print(f'Public key: {getpass.getuser()}_crypt4gh.pub')
        elif action == 'encrypt':
            # Check that all fields are filled before asking for password
            if self.my_key_value.get() and self.their_key_value.get() and self.file_value.get():
                # All fields are filled, ask for passphrase for private key encryption
                password = askstring('Private Key Passphrase', 'Private Key Passphrase', show='*')
                # This if-clause is for preventing error messages
                if password is None:
                    return
                while len(password) == 0:
                    password = askstring('Private Key Passphrase', 'Passphrase can\'t be empty', show='*')
                    # This if-clause is for preventing error messages
                    if password is None:
                        return
                private_key = None
                try:
                    private_key = get_private_key(self.my_key_value.get(), partial(self.mock_callback, password))
                except Exception as e:
                    print('Incorrect private key passphrase')
                if private_key:
                    their_key = get_public_key(self.their_key_value.get())
                    print('Encrypting...')
                    original_file = open(self.file_value.get(), 'rb')
                    encrypted_file = open(f'{self.file_value.get()}.c4gh', 'wb')
                    encrypt([(0, private_key, their_key)],
                            original_file,
                            encrypted_file)
                    original_file.close()
                    encrypted_file.close()
                    print('Encryption has finished')
                    print(f'Encrypted file: {self.file_value.get()}.c4gh')
            else:
                print('All fields must be filled before file encryption can be started')
        elif action == 'decrypt':
            print(self.file_value.get())
            if not self.file_value.get().endswith('.c4gh'):
                print('File for decryption must be a file with .c4gh extension')
            else:
                # Check that all fields are filled before asking for password
                if self.my_key_value.get() and self.file_value.get():
                    # All fields are filled, ask for passphrase for private key encryption
                    password = askstring('Private Key Passphrase', 'Private Key Passphrase', show='*')
                    # This if-clause is for preventing error messages
                    if password is None:
                        return
                    while len(password) == 0:
                        password = askstring('Private Key Passphrase', 'Passphrase can\'t be empty', show='*')
                        # This if-clause is for preventing error messages
                        if password is None:
                            return
                    private_key = None
                    try:
                        private_key = get_private_key(self.my_key_value.get(), partial(self.mock_callback, password))
                    except Exception as e:
                        print('Incorrect private key passphrase')
                    if private_key:
                        their_key = None  # sender public key is optional when decrypting
                        if self.their_key_value.get():
                            print('Sender public key has been set, authenticity will be verified')
                            their_key = get_public_key(self.their_key_value.get())
                        else:
                            print('Sender public key has not been set, authenticity will not be verified')
                        print('Decrypting...')
                        encrypted_file = open(self.file_value.get(), 'rb')
                        decrypted_file = open(self.file_value.get()[:-5], 'wb')
                        error = False
                        try:
                            decrypt([(0, private_key, their_key)],
                                    encrypted_file,
                                    decrypted_file,
                                    sender_pubkey=their_key)
                        except ValueError as e:
                            error = True
                            print('Decryption failed')
                            if self.their_key_value.get():
                                print('This public key is not the sender of this file')
                            else:
                                print('This private key is not the intended recipient')
                        encrypted_file.close()
                        decrypted_file.close()
                        if not error:
                            print('Decryption has finished')
                            print(f'Decrypted file: {self.file_value.get()[:-5]}')
                else:
                    print('Private key and file to decrypt must be filled before decryption can be started')
                    print('Public key is optional')
        else:
            print(f'Unknown action: {action}')

    def mock_callback(self, password):
        """Mock callback to return password."""
        return password


def main():
    """Run Program."""
    root = tk.Tk()
    GUI(root)
    print('To begin file encryption or decryption:\n')
    print('1. Generate keys if you haven\'t already')
    print('2. Load your private key')
    print('3. Load your recipient\'s or sender\'s public key')
    print('4. Select file for encryption or decryption')
    print('5. Click [Encrypt File] or [Decrypt File]\n')
    root.mainloop()


if __name__ == '__main__':
    main()
