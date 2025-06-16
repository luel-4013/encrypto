from os import sys,path,listdir
from os.path import isfile, join
from sys import exit
from cryptography.fernet import Fernet
import hashlib,subprocess,os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
	print("			WARNING:- You MUST keep your keys SAFE. If not you WON'T be able to get your files back!!\n")
	print("[#]Please select encryption type to use :\n1.Elliptic Curve\n2.RSA")
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
    print('[#]Please select key options:\n1.Generate new keys\n2.Use existing keys')
    keyoption = input()
    
    if keyoption == '1':
        gen_new_keyrsa()
    elif keyoption == '2':
        use_exst_keyrsa()
    else:
        print('[-]r u nuts???')
        choice1()
def choice2el():
    print('[$]Please select key options:\n1.Generate new keys\n2.Use existing keys')
    keyoption = input()
    
    if keyoption == '1':
        gen_new_keyel()
    elif keyoption == '2':
        use_exst_keyel()
    else:
        print('[-]r u nuts???')
        choice1()
def verify_key_pair(private_key, public_key):
    message = b"Verify this message"
    ciphertext = public_key.encrypt(
        message,
        PKCS1v15()
    )
    try:
        decrypted_message = private_key.decrypt(
            ciphertext,
            PKCS1v15()
        )
        if decrypted_message == message:
            print("[+]RSA key pair compatibility verified successfully!")
            return True
        else:
            print("[-]Decryption failed: please regenerate key.")
            return False
    except Exception as e:
        print(f"[-]An error occurred during decryption: {e}")
        return False

def gen_new_keyrsa():
    print("[+] New keys will be used")
    if os.path.exists("private_key.pem"):
        confirm = input("[!] Private key already exists. Are you sure you want to OVERWRITE? "
                        "\n[!] You won't get your files back encrypted by the existing key (y/n)? ")
        if confirm.lower() != 'y':
            print('[+] Key generation aborted')
            return
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    public_key = private_key.public_key()
    if verify_key_pair(private_key, public_key):
        print("[+]RSA key pair valid.")
    else:
        print("[-]RSA key pair invalid.")
        return
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("private_key.pem", "wb") as private_file:
        private_file.write(private_pem)
        if os.name != 'nt':  # If not Windows
            os.chmod("private_key.pem", 0o600)
        print("[+]Private key saved to private_key.pem")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("public_key.pub", "wb") as public_file:
        public_file.write(public_pem)
        print("[+]Public key saved to public_key.pub")
        real_choice_rsa()
def load_public_key(pub_key_path="public_key.pub"):
    with open(pub_key_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(priv_key_path="private_key.pem"):
    with open(priv_key_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
def encrypt_file_rsa(input_file, public_key):
    with open(input_file, "rb") as f:
        data = f.read()
    aes_key = os.urandom(32)
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    from struct import pack
    encrypted_file = input_file + ".R2D2"
    with open(encrypted_file, "wb") as f:
        f.write(pack(">I", len(encrypted_aes_key)))
        f.write(encrypted_aes_key)
        f.write(iv)
        f.write(tag)
        f.write(encrypted_data)
    print(f"Encrypted file saved as: {encrypted_file}")
    return encrypted_file
def decrypt_file_rsa(encrypted_file, private_key):
    from struct import unpack
    with open(encrypted_file, "rb") as f:
        enc_key_len_bytes = f.read(4)
        enc_key_len = unpack(">I", enc_key_len_bytes)[0]
        encrypted_aes_key = f.read(enc_key_len)
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        iv = f.read(12)
        tag = f.read(16)
        encrypted_data = f.read()
    decryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    if encrypted_file.endswith(".R2D2"):
        decrypted_file = encrypted_file[:-5]
    else:
        decrypted_file = encrypted_file + ".fallback"

    with open(decrypted_file, "wb") as f:
        f.write(decrypted_data)

    print(f"Decrypted file saved as: {decrypted_file}")
    return decrypted_file
def use_exst_keyrsa():
    print('[+]Existing keys will be used')
    real_choice_rsa()
def gen_new_keyel(): 
        print("[+]New keys will be used")
        real_choice_el()
def use_exst_keyel():
        print('[+]Existing keys will be used')
        real_choice_el()
def real_choice_rsa():
    print('[#]Choose the best dancer\n1.Encrypt file\n2.Encrypt files in a folder\n3.Decrypt file\n4.Decrypt files in a folder')
    realoption = input()
    
    if realoption == '1':
        input_file = input("Enter file to encrypt: ").strip()
        if not os.path.isfile(input_file):
            print("File not found.")
            return
        public_key = load_public_key()
        encrypt_file_rsa(input_file, public_key)
        #encrypt_file_rsa()
        print('[+]File encrypted')
    elif realoption == '2':
        print('[+]files in a folder encrypted (AM IN PROGRESS)')
    elif realoption == '3':
        input_file = input("Enter file to decrypt (.R2D2): ").strip()
        if not os.path.isfile(input_file):
            print("[!]File not found.")
            return
        private_key = load_private_key()
        decrypt_file_rsa(input_file, private_key)
        print('[+]File decrypted')
        #decrypt_file_rsa()
    elif realoption == '4':
        print('[+]files in a folder decrpted(AM IN PROGRESS)')
    else:
        print('[-]u r definitely nuts!!!')
        real_choice_rsa()
def real_choice_el():
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
                real_choice_el()

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

