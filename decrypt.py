#!/usr/bin/env python

from Crypto.Cipher import AES
import sys
import argparse
import random
import os
import binascii


def b_to_num(message):
    # converts bytes to nums
    num = []
    for i in range(0, len(message)):
        num.append(int(message[i].encode('hex'), 16))
    return num

def b_to_num(message):
    # converts bytes to nums
    num = []
    for i in range(0, len(message)):
        num.append(int(message[i].encode('hex'), 16))
    return num

def check_pad(message):
    # checks the padding of a message AFTER decryption
    mnum = b_to_num(message)
    wantpad = mnum[-1]
    if wantpad == 0:
        return 0
    for i in range(0, wantpad):
        if mnum[-1-i] != wantpad:
            return 0
    return 1

# XORs two string
def strxor(s1, s2):
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

def run(message):
    # Get the last block of the ciphertext (last 16 bytes)
    message = message[16:]
    print('{:x}'.format(int(binascii.b2a_hex(message),16)))

    # Generate yn-1 ciphertext and concatenate with the ciphertext
    randomcipher = binascii.a2b_hex(binascii.b2a_hex(os.urandom(15)) + "00")

    # Increment the last bytes till the padding is correct
    for i in range(0, 256):
        plaintext = obj.decrypt(randomcipher + message)
        if check_pad(plaintext) == 1:
            print("correct padding")
            break

        temp = randomcipher[0:15]
        bytes16 = '{:x}'.format(int(i))
        # Add 4 extra bits if value is under 16
        if i < 16:
            bytes16 = "0" + bytes16

        randomcipher = binascii.a2b_hex(binascii.b2a_hex(temp) + bytes16)
    print("R16 = ")
    print(bytes16)

    # Find length of padding
    for k in range (0,15):
        bytes_modif = None
        # Modify R bytes from left to right
        for i in range(0, 256):
            #Replace Ri bytes randomly
            bytes_modif = binascii.b2a_hex(os.urandom(1))

            if k == 0:
                randomcipher = binascii.a2b_hex(bytes_modif + binascii.b2a_hex(randomcipher[k+1:]))
                print(binascii.b2a_hex(randomcipher))
            elif k == 15:
                randomcipher = binascii.a2b_hex(binascii.b2a_hex(randomcipher[0:k]) + bytes_modif)
                print(binascii.b2a_hex(randomcipher))
            else:
                randomcipher = binascii.a2b_hex(binascii.b2a_hex(randomcipher[0:k]) + bytes_modif + binascii.b2a_hex(randomcipher[k+1:]))
                print(binascii.b2a_hex(randomcipher))

            plaintext = obj.decrypt(randomcipher + message)
            if check_pad(plaintext) == 1:
                error = "No change in padding"
            else:
                error = "padding start at here"
                print(k)

        print(error)

    print ("end")
try:
    fname = sys.argv[1]
    f = open(fname, "r")
except:
    print "./poracle <filename>"
    sys.exit(1)

# Get Ciphertext
line = f.read()
if len(line) % 16 != 0 or len(line) < 32:
    print("Input file must contain at least 32 characters, and it must be a multiple of 16.")
    sys.exit(1)

iv = line[0:16]
ciphertext = line[16:]

key = 'COMP3632 testkey'
obj = AES.new(key, AES.MODE_CBC, iv)
# plaintext = obj.decrypt(ciphertext)
# sys.stdout.write(str(check_pad(plaintext)))

run(ciphertext)