from crypt4gh.lib import encrypt


def encrypt_file(file=None, private_key_file=None, recipient_public_key=None):
    """Encrypt a file with Crypt4GH."""
    print(f"Encrypting {file} as {file}.c4gh")
    original_file = open(file, "rb")
    encrypted_file = open(f"{file}.c4gh", "wb")
    encrypt([(0, private_key_file, recipient_public_key)], original_file, encrypted_file)
    original_file.close()
    encrypted_file.close()
    print("Encryption has finished.")


def verify_crypt4gh_header(file=None):
    """Verify, that a file has Crypt4GH header."""
    print("Verifying file Crypt4GH header.")
    with open(file, "rb") as f:
        header = f.read()[:8]
        if header == b"crypt4gh":
            return True
        else:
            return False
