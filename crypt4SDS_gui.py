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
from base64 import b64decode, b64encode

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
      
        self.header_label = tk.Label(window, text='Encrypt a file for SD-connect service')
        self.header_label.grid(column=0, row=2, sticky=tk.W)

        self.select_file_button = tk.Button(window, text='Select File', width=OS_CONFIG['config_button_width'], command=partial(self.open_file, 'file'))
        self.select_file_button.grid(column=0, row=6, sticky=tk.W, columnspan=2)

        self.file_label = tk.Label(window, text='File to Encrypt')
        self.file_label.grid(column=0, row=7, sticky=tk.W)
        self.file_value = tk.StringVar()
        self.file_field = tk.Entry(window, width=OS_CONFIG['field_width'], textvariable=self.file_value)
        self.file_field.grid(column=0, row=8, sticky=tk.W)
        self.file_field.config(state='disabled')

        self.encrypt_button = tk.Button(window, text='Encrypt.', width=OS_CONFIG['operation_button_width'], height=3, command=partial(self.password_prompt, 'encrypt'))
        self.encrypt_button.grid(column=0, row=11, sticky=tk.W, rowspan=3)

        self.activity_label = tk.Label(window, text='Activity Log')
        self.activity_label.grid(column=0, row=14, sticky=tk.W)
        self.activity_field = ScrolledText(window, height=10)
        self.activity_field.grid(column=0, row=15, columnspan=3, sticky=tk.W)
        self.activity_field.config(state='disabled')


    def print_redirect(self, message):
        """Print to activity log widget instead of console."""
        self.activity_field.config(state='normal')
        self.activity_field.insert(tk.END, message, None)
        self.activity_field.see(tk.END)
        self.activity_field.config(state='disabled')
        self.window.update()

    def open_file(self, action):
        """Open file and return result according to type."""
        if action == 'file':
            file_path = askopenfilename()
            self.file_value.set(file_path)
        else:
            print(f'Unknown action: {action}')

    def password_prompt(self, action):
        if action == 'encrypt':
            # Check that all fields are filled before asking for password
            if self.file_value.get():
                    csc_key = b64decode("dmku3fKA/wrOpWntUTkkoQvknjZDisdmSwU4oFk/on0=")
                    print('Encrypting...')
                    original_file = open(self.file_value.get(), 'rb')
                    encrypted_file = open(f'{self.file_value.get()}.c4gh', 'wb')
                    encrypt([(0, csc_key, csc_key)], original_file, encrypted_file)
                    original_file.close()
                    encrypted_file.close()
                    print('Encryption has finished')
                    print(f'Encrypted file: {self.file_value.get()}.c4gh')
            else:
                print('File field must be filled before file encryption can be started')
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
    print('To begin file encryption for SD-connect:\n')
    print('1. Select file for encryption\n')
    print('2. Click [Encrypt File]\n')
    root.mainloop()


if __name__ == '__main__':
    main()
