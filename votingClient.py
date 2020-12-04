###imports
import socket


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

def RSA_encrypt(plaintext, pub_key):
    # Use RSA key to encrypt the plaintext
    # Return the encrypted result
    ciphertext = plaintext
    return ciphertext

def RSA_decrypt(ciphertext, pub_key):
    # Use RSA key to decrypt cipher
    # Return result
    plaintext = ciphertext
    return plaintext

def login(s):
    # Prompt for username and password
    # Send server
    # Read repsonse and notify user if successful
    # (Ballot/voting taken care of in next functino)
    username = None
    password = None

    return username, password #on success

def vote(s, username, password):
    # read ballot information and display to user
    # Get user's vote
    # Encrypt in proper manner and send to server
    return

def get_message(s, auth_pub_key):
    # Get message from server
    # Decrypt message
    # Check time stamp
    #   If too late, give error message and end program (for now/for demo purposes)
    response = None
    return response

def send_message(s, auth_pub_key, username, password, response):
    # Get current time
    # Create (time, user, password, response)
    # Encrypt and send to client
    return


### Main Client
#Socket set-up and server client communication

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ###Pass in "s" to any function that needs to talk with server
s.connect((HOST, PORT))
testWriteC(s)
testReadC(s)

