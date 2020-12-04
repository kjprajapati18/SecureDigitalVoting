###imports
import socket
from Crypto.PublicKey import RSA
from collections import Counter

### Notes that are different from Design Document
#We can hash SSN because we encrypt the whole thing afterwards
#We can send password directly we encrypt

### Client should always send the messages in this format
#   (time, email, password, action...)

### Server should always respond in the following way
#   (time, response)

###Function and headers
def generate_key(modulus_length,exponent, file_name):
    ###
    #   Make this function check if a key with file_name already exists
    #   If key does not, generate a public/private pair
    #       Write this key to file_name
    #   Use this function twice (one pair for auth key, one pair for confidential)
    ###
    key = RSA.generate(modulus_length,e=exponent)
    pub_key = key.publickey()
    private_key = key.exportKey()
    public_key = pub_key.exportKey()
    
    return private_key, public_key

def vote_counter(voting_file):
#counting votes it uses a .txt file that contains votes
    file = open(voting_file).readlines()
    vote_count = dict(Counter(file))
    for choice in vote_count:
        choice_ = choice.rstrip()
        print(choice_, ': ', vote_count[choice]) #prints voting choices and the number of votes they received 

def RSA_encrypt(plaintext, pub_key):
    # Use RSA key to encrypt the plaintext
    # Return the encrypted result
    ciphertext = plaintext
    return ciphertext

def RSA_decrypt(ciphertext, pri_key):
    # Use RSA key to decrypt cipher
    # Return result
    plaintext = ciphertext
    return plaintext

def accept_user_login():
    #Receive the User's enail/pass\
    #Verify user in database (add later, for now just accept)
    #Let the user know that they have succesfully logged in (Ballot sent in different function)
    return

def get_vote():
    #send ballot information to user that has logged in
    #Get user's response to vote
    #Store this in database, mark user as voted
    #Send client message that vote was successful
    return

def get_message(conn, auth_pri_key):
    # Get message from client
    # Decrypt message
    # Check time stamp
    #   If too late, give error message and end program (for now/for demo purposes)
    # Tokenize (user, pass, action)
    user = None
    password = None
    action = None
    return user, password, action

def send_message(conn, auth_pub_key, response):
    # Get current time
    # Create (time, response)
    # Encrypt and send to client
    return



### Main Server
#Socket set-up and server client communication

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen()
conn, addr = s.accept()

print('Connected by', addr)
while True:
    data = conn.recv(1024)
    if not data:
        break
    conn.sendall(data)
