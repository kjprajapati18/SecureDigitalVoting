###imports
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime

### Client should always send the messages in this format
#   (time, email, password, action...)

### Server should always respond in the following way
#   (time, response)

###Function and headers
def testReadC(s):
    data = s.recv(1024)
    print('Received', repr(data))
    
def testWriteC(s):
    s.sendall(b'Hello, world')



def get_RSA_keys(file_name):
    #Read public & private key. Return
    private_key = None
    public_key = None
    
    return private_key, public_key


def RSA_encrypt(plaintext, public_key):
    # Use RSA key to encrypt the plaintext
    # Return the encrypted result
    key = public_key
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def RSA_decrypt(ciphertext, private_key):
    # Use RSA key to decrypt cipher
    # Return result
    key = private_key
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def login(s, auth_pub_key, cli_pri_key):
     
    username= None
    password = None
    error = "Error - Login not correct!"

    # Prompt for username and password
    # Send server
    # Read repsonse and notify user if successful
    # (Ballot/voting taken care of in next functino)
    username = input("Enter username:")
    password = input("Enter password:")

    send_message(s, auth_pub_key, username, password, "login")
    message = get_message(s, cli_pri_key)

    if message == "Successfully logged in!": 
        print('\n' + message + '\n')
        return username, password
    
    return error, error


def vote(s, private_key, auth_pub_key, confidential_key, username, password):
    # read ballot information and display to user
    # Get user's vote
    # Encrypt in proper manner and send to server
    ballot = get_message(s, private_key)
    print(ballot)
    vote = input("Please enter the number of the option you want...")
    vote = getCandidate(ballot, vote)
    if vote == None:
        print("You did not enter a valid vote!")
        send_message(s, auth_pub_key, username, password, "No Vote")
        return
    ### Encrypted vote is too long to be sent
    ### In real world, we would split the message into chunks and send each chunk
    ### Had difficulty implementing this for this demo
    #vote = bytes(vote, 'utf-8')
    #encryptedVote = repr(RSA_encrypt(vote, confidential_key))
    encryptedVote = vote
    
    send_message(s, auth_pub_key, username, password, encryptedVote)
    confirmation = get_message(s, private_key)
    print('\n' + confirmation)
    return

def get_message(s, auth_pub_key):
    # Get message from server
    # Decrypt message
    # Check time stamp
    #   If too late, give error message and end program (for now/for demo purposes)
    encrypted = s.recv(1024)
    message = RSA_decrypt(encrypted, auth_pub_key)
    split = message.decode('utf-8').split(', ')

    time = split[0]
    #print(time)
    #Check time
    response = split[1]
    return response

def send_message(s, auth_pub_key, username, password, response):
    # Get current time
    # Create (time, user, password, response)
    # Encrypt and send to client
    now = datetime.now()
    time = now.strftime("%m/%d/%Y %H:%M:%S")
    message = bytes('{}, {}, {}, {}'.format(time, username, password, response), 'utf-8')
    encrypted = RSA_encrypt(message, auth_pub_key)
    s.sendall(encrypted)
    return

def getCandidate(ballot, vote):
    delimited = ballot.split()
    length = len(delimited)

    eleNum = int(vote)*2+4
    if eleNum >= length:
        return None
    return delimited[eleNum]

### Main Client
auth_pub_key = RSA.importKey(open('auth_public_key.pem').read())
conf_pub_key = RSA.importKey(open('conf_public_key.pem').read())
cli_pub_key = RSA.importKey(open('cli_public_key.pem').read())
cli_pri_key = RSA.importKey(open('cli_private_key.pem').read())
#Socket set-up and server client communication

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65433        # The port used by the server

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ###Pass in "s" to any function that needs to talk with server
s.connect((HOST, PORT))

username, password = login(s, auth_pub_key, cli_pri_key)
vote(s, cli_pri_key, auth_pub_key, conf_pub_key, username, password)

print("\nShutting down!")
s.shutdown(socket.SHUT_RDWR)
s.close()
