from .crypt4gh_gui import GUI
import tkinter as tk


def main():
    """Run Program."""
    root = tk.Tk()
    GUI(root)
    print("To begin file upload:\n")
    print("1. Generate keys if you haven't already")
    print("2. Load your private key")
    print("3. Load your recipient's public key")
    print("4. Select a file or a directory for upload (not both)")
    print("5. Write SFTP username, server and port to SFTP Credentials")
    print("6. Load your SFTP RSA key")
    print(
        "7. Click [Encrypt and Upload File(s)] to upload selected file or directory"
    )
    print("8. Password for private key and RSA key will be prompted\n")
    root.mainloop()


if __name__ == "__main__":
    main()