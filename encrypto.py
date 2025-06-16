from os import sys,path,listdir
from os.path import isfile, join
from sys import exit
from cryptography.fernet import Fernet
import hashlib,subprocess,os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa

def flvrf():
        cfile = 'reaper.cxy'
        check_file = path.isfile(cfile)
        compute_hash = hashlib.sha512(open(cfile, 'rb').read()).hexdigest()
        if compute_hash == '43d32486552ae307f4878dda2118715985489f5848e23e16eefcf1423147bc20d71151901fbb76222142845e873ab69f772':
               print('[+]File Verification sucessfull!!')
               choice1()
        else:
               print('[-]Verification failed!!\n')
               sys.exit()
def fstauth(machine_id):
    if machine_id  == "66cfff1cc72b4bf7bcf1cd41abe9d13e":
                print('[+]Machine verified sucessfully!!')
                choice1()
    else:
                print('[!]Machine verification failed!!\nEnter password to start file verification:')
                fval = input()
                if fval == 'pasfrase':
                        print('[+]Verification successful!!')
                        flvrf()
                else:
                        print('[-]Verification failed')
                        sys.exit()

def choice1():
	print("			WARNING:- You MUST keep your keys SAFE. If not you WON't be able to get your files back!!\n")
	print("Please select encryption type to use :\n1.Elliptic Curve\n2.RSA")
	keyoption = input()
	if keyoption == '1':
		curvy()
	elif keyoption == '2':
		rsaal()
	else:
		print('[-]r u nuts????')
		choice1()
def curvy():
	print('[+]Elliptic Curve Algorithm Selected')
	choice2el()
def rsaal():
	print('[+]RSA cryptography selected 4096 will be used by default.')
	choice2rsa()
def choice2rsa():
    print('Please select key options:\n1.Generate new keys.\n2.Use existing keys')
    keyoption = input()
    
    if keyoption == '1':  # Corrected indentation
        gen_new_keyrsa()
    elif keyoption == '2':
        use_exst_keytrsa()
    else:
        print('[-]r u nuts???')
        choice1()
def choice2el():
    print('Please select key options:\n1.Generate new keys.\n2.Use existing keys')
    keyoption = input()
    
    if keyoption == '1':  # Correct indentation (aligned with the previous lines)
        gen_new_keyel()
    elif keyoption == '2':
        use_exst_keyel()
    else:
        print('[-]r u nuts???')
        choice1()
def verify_key_pair(private_key, public_key):
    # Data to encrypt and verify
    message = b"Verify this message"

    # Encrypt with public key
    ciphertext = public_key.encrypt(
        message,
        PKCS1v15()
    )

    # Decrypt with private key
    try:
        decrypted_message = private_key.decrypt(
            ciphertext,
            PKCS1v15()
        )
        # Verify that the decrypted message matches the original message
        if decrypted_message == message:
            print("Key pair verified successfully!")
            return True
        else:
            print("Decryption failed: message mismatch.")
            return False
    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return False

def gen_new_keyrsa():
    print("[+] New keys will be used")
    # Check if the private key file already exists
    if os.path.exists("private_key.pem"):
        confirm = input("[!] Private key already exists. Are you sure you want to OVERWRITE? "
                        "\n[!] You won't get your files back encrypted by the existing key (y/n)? ")
        if confirm.lower() != 'y':
            print('[+] Key generation aborted')
            return
    # Generate RSA key pair (4096 bits)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    public_key = private_key.public_key()
    # Verify key pair
    if verify_key_pair(private_key, public_key):
        print("RSA key pair is valid.")
    else:
        print("RSA key pair is invalid.")
        return

    # Export private key to file (PEM format)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # No password encryption
    )
    
    # Write the private key to file
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        if os.name != 'nt':  # If not Windows
            os.chmod("private_key.pem", 0o600)  # Secure file permissions
        print("Private key saved to private_key.pem")

    # Export public key to file (PEM format)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    # Write the public key to file
    with open("public_key.pem", "wb") as public_file:
        public_file.write(public_pem)
        print("Public key saved to public_key.pem")

def use_exst_keyrsa():
	print('[+]Existing keys will be used')
	real_choice()
def gen_new_keyel(): 
        print("[+]New keys will be used")
        real_choice()
def use_exst_keyel():
        print('[+]Existing keys will be used')
        real_choice()

def real_choice():
	print('Choose the best dancer\n1.Encrypt file\n2.Encrypt files in a folder\n3.Decrypt file\n4.Decrypt files in a folder')
	realoption = input()
	if realoption == '1':
		print('[+]file encrypted')
	elif realoption == '2':
		print('[+]files in a folder encrypted')
	elif realoption == '3':
		print('[+]file decrpyted')
	elif realoption == '4':
		print('[+]files in a folder decrpted')
	else:
		print('[-]u r definitely nuts!!!')
		real_choice()
def get_machine_id():
    if sys.platform == "linux":
        print('[!]This program is protected by SECURE EXECUTION.\n[+]Linux OS detected!') 
        command = "cat /etc/machine-id"
    elif sys.platform == "win32":
        print('[!]This program is protected by SECURE EXECUTION.\n[+]Windows OS detected!')   
        command = "wmic csproduct get UUID"
    elif sys.platform == "darwin":
        print("[!]This program is protected by SECURE EXECUTION.\n[+]macOS detected!")
        command = "system_profiler SPHardwareDataType | grep 'Hardware UUID'"
    else:
        raise Exception("[-]Unsupported platform")
    result = subprocess.check_output(command, shell=True).decode()
    machine_id = result.split("\n")[-2].strip()
    return machine_id
machine_id = get_machine_id()
fstauth(machine_id)
