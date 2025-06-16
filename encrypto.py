from os import sys,path,listdir
from os.path import isfile, join
from sys import exit
from cryptography.fernet import Fernet
import hashlib

def fstthgs1st():
	print('This program is protected by SECURE EXECUTION')
	vald = input()
	if vald == 'pasfrase':
		print('Verification successful!!')
		choice1()
	elif vald == 'f':
		fstauth()
	else:
		print('Verification failed!!')
		sys.exit()
def fstauth():
	cfile = 'reaper.cxy'
	check_file = path.isfile(cfile)
	compute_hash = hashlib.sha512(open(cfile, 'rb').read()).hexdigest()
	if compute_hash == '43d32486552ae307f4878dda2118715985489f5848e23e16eefcf1423147bc20d71151901fbb76222142845e873ab69f772f7c8a3e4144b3be8cfd08d07c71c6':
		print('File Verification sucessfull!!')
		choice1()
	else:
		print('Verification failed!!')
		sys.exit()
def choice1():
	print("			WARNING:- You MUST keep your keys SAFE. If not you WON't be able to get your files back!!\n")
	print("Please select encryption type to use :\n1.Elliptic Curve.\n2.RSA")
	keyoption = input()
	if keyoption == '1':
		curvy()
	elif keyoption == '2':
		rsa()
	else:
		print('r u nuts????')
		choice1()
def curvy():
	print('Elliptic Curve Algorithm Selected')
	choice2()
def rsa():
	print('RSA cryptography selected 4096 will be used by default.')
	choice2()
def choice2():
	print('Please select key options:\n1.Generate new keys.\n2.Use existing keys')
	keyoption = input()
	if keyoption == '1':
		gen_new_key()
	elif keyoption == '2':
		use_exst_key()
	else:
		print('r u nuts???')
		choice2()
#test comment
def gen_new_key():
	print("New keys will be used")
	real_choice()
def use_exst_key():
	print('Existing keys will be used')
	real_choice()

def real_choice():
	print('Choose the best dancer\n1.Encrypt file\n2.Encrypt files in a folder\n3.Decrypt file\n4.Decrypt files in a folder')
	realoption = input()
	if realoption == '1':
		print('file encrypted')
	elif realoption == '2':
		print('files in a folder encrypted')
	elif realoption == '3':
		print('file decrpyted')
	elif realoption == '4':
		print('files in a folder decrpted')
	else:
		print('u r definitely nuts!!!')
		real_choice()
fstthgs1st()
#fstauth()
