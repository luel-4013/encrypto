from os import sys,path,listdir
from os.path import isfile, join
from sys import exit
from cryptography.fernet import Fernet
import hashlib

def choice1():
	print("			WARNING:- You MUST keep your keys SAFE. If not you WON't be able to get your files back!!\n")
	print("Please select key options:\n1.Generate new keys.\n2.Use existing keys")
	keyoption = input()
	if keyoption == '1':
		gen_new_key()
	elif keyoption == '2':
		use_exst_key()
	else:
		print('r u nuts????')
		choice1()

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
choice1()
