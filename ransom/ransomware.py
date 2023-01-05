import pathlib, os, secrets, base64, getpass
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# the secrets module is used to generate secure random numbers
def gen_salt(size=16):
    # Generates the salt for key derivation
    # salt: A salt is random data (not specifically a number) that is used as an input for a one way function in encryption
    # Key derivation: A function that returns keys used in cryptographic functions
    return secrets.token_bytes(size)

# I wish I knew what this did
def derive_key(salt, password):
    kdf = Scrypt(salt=salt, length=32, n=2**16, r=8, p=1)
    return kdf.derive(password.encode())

# Loads the salt from salt.salt
def load_salt():
    return open("salt.salt" , "rb").read()

# Will either open the already existing salt file or generate a new one and save it to salt.salt
def generate_key(password, salt_size=16, load_existing_salt=False, save_salt=True):
    if load_existing_salt:
        salt = open("salt.salt", "rb").read()
    elif save_salt:
        salt = gen_salt()
        with open("salt.salt", "wb") as f:
            f.write(salt)
            f.close()
    derived_key = derive_key(salt, password)
    return base64.urlsafe_b64encode(derived_key)

# Will take the data from a file, encrypt it and overwrite the data that was in the file with the encrypted data
def encrypt(filename, key):
    print(f"Key: {key}")
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

# Will take the encrypted data from the file, decrypt it and overwrite the encrypted data with the decrypted data
def decrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    try:
        decrypted_data = f.decrypt(encrypted_data)
    except:
        print("Failed to decrypt (password is likely incorrect)")
    with open(filename, "wb") as file:
        file.write(decrypted_data)


def encrypt_folder(foldername, key):
    # Loop through all files in the folder
    for child in pathlib.Path(foldername).glob("*"):
        # if the file is not a directory then encrypt it
        if child.is_file():
            print(f"Encrypting {child}")
            encrypt(child, key)
        # If the file is a folder, run this function on that folder
        elif child.is_dir():
            encrypt_folder(child, key)

def decrypt_folder(foldername, key):
    # Loop through the files in the folder
    for child in pathlib.Path(foldername).glob("*"):
        # if the file is a file, then decrypt it
        if child.is_file():
            print(f"Decrypting {child}")
            decrypt(child, key)
        # If the file is a directory then run this function on that directory
        elif child.is_dir():
            decrypt_folder(child, key)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="File encryption 'software'")
    # Default argument that doesnt need a flag
    parser.add_argument("path", help="path to directory to encrypt/decrypt")
    # define the size of the salt using the -s flag (must be an intiger)
    parser.add_argument("-s", "--salt-size", help="If this is set, a new salt with the set size will be generated", type=int)
    # Define wether you want to encrypt or decrypt the file
    parser.add_argument("-e", "--encrypt", help="choose to encrypt the file", action="store_true")
    parser.add_argument("-d", "--decrypt", help="choose to decrypt the file", action="store_true")
    args = parser.parse_args()
    # Asks the user for a password used to encrypt or decrypt the file
    if args.encrypt:
        password = getpass.getpass("Enter your password for encryption: ")
    elif args.decrypt:
        password = getpass.getpass("Enter your password for decryption: ")
    if args.salt_size:
        key = generate_key(password, args.salt_size, save_salt=True)
    else: 
        key = generate_key(password, load_existing_salt=True)
    if args.encrypt and args.decrypt:
        raise TypeError("You must provide only one action (encrypt or decrypt)")
    elif args.encrypt:
        if os.path.isfile(args.path):
            encrypt(args.path, key)
        elif os.path.isdir(args.path):
            encrypt_folder(args.path, key)

    elif args.decrypt:
        if os.path.isfile(args.path):
            decrypt(args.path, key)
        if os.path.isdir(args.path):
            decrypt_folder(args.path, key)
    
    else: 
        raise TypeError("Choose to either encrypt or decrypt")
