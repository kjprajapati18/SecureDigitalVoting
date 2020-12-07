# -*- coding: utf-8 -*-
"""
Created on Sun Dec  6 18:02:40 2020

@author: kjpra
"""
from Crypto.PublicKey import RSA

#Generate a public/ private key pair using 4096 bits key length (512 bytes)
new_key = RSA.generate(4096, e=3)
#The private key in PEM format
private_key = new_key.exportKey("PEM")
#The public key in PEM Format
public_key = new_key.publickey().exportKey("PEM")

fd = open("auth_private_key.pem", "wb")
fd.write(private_key)
fd.close()
fd = open("auth_public_key.pem", "wb")
fd.write(public_key)
fd.close()
print("Finished making authentication keys")

new_key = RSA.generate(4096, e=3)
#The private key in PEM format
private_key = new_key.exportKey("PEM")
#The public key in PEM Format
public_key = new_key.publickey().exportKey("PEM")

fd = open("conf_private_key.pem", "wb")
fd.write(private_key)
fd.close()
fd = open("conf_public_key.pem", "wb")
fd.write(public_key)
fd.close()
print("Finished making confidential keys")

new_key = RSA.generate(4096, e=3)
#The private key in PEM format
private_key = new_key.exportKey("PEM")
#The public key in PEM Format
public_key = new_key.publickey().exportKey("PEM")

fd = open("cli_private_key.pem", "wb")
fd.write(private_key)
fd.close()
fd = open("cli_public_key.pem", "wb")
fd.write(public_key)
fd.close()
print("Finished making client keys")