###imports
import socket
from Crypto.PublicKey import RSA
from collections import Counter
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime

###Things to mention in the Demo
# Client should not have an RSA key pair. That the server sends is confidential
#       We only have a pair because pyCrypto does not let you use public key decryption
# We should be encrypting the vote using the confidential key
#       We do not do that because then the plaintext becomes too long to encrypt
#       We should split the message into blocks and encrypt each block
# We have not implemented account creation or data storage
#       This is a relatively simple, but time-consuming, fix since we already have our RSA encryption down
#       In reality, we store all the users to file following the encryption scheme outlined in design document
# RSA keys are made with small exponents (e=3) for faster compute time.
#       The premise of the program stands but the security of it is traded for performance
#       This is only for the purpose of demonstration

### Client should always send the messages in this format
#   (time, email, password, action...)

### Server should always respond in the following way
#   (time, response)

###Function and headers

    
def generate_keys(modulus_length,exponent): #Osama
    ###
    #   Make this function check if a key with file_name already exists
    #   If key does not, generate a public/private pair
    #       Write this key to file_name
    #   Use this function twice (one pair for auth key, one pair for confidential)
    ###
    key = RSA.generate(modulus_length,e=exponent)
    pub_key = key.publickey()
    #The private key in PEM format
    private_key = key.exportKey("PEM")
    #The public key in PEM Format
    public_key = key.publickey().exportKey("PEM")
    
    
    return private_key, public_key    

def vote_counter(ballot_database): #(Nirav)
    # Go through the database and decrypt the votes
    # Use the confidential private key to decrypt the votes
    # Tally each vote as you decrypt them
    # Display what each candidate got (# of votes)
    # Dislpay the winner
    print("\n\nStarting the Counting Process!\n")
    freq = {} 
    for key, value in ballot_database.items(): 
        if (value in freq): 
            freq[value] += 1
        else: 
            freq[value] = 1
  
    for key, value in freq.items(): 
        print ("% s : % d votes"%(key, value)) 

    winner = max(freq, key=freq.get)
    print('\nWinner is: ' + winner)



def RSA_encrypt(plaintext, public_key): #Osama
    # Use RSA key to encrypt the plaintext
    # Return the encrypted result
    key = public_key
    cipher = PKCS1_OAEP.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

def RSA_decrypt(ciphertext, private_key): #Osama
    # Use RSA key to decrypt cipher
    # Return result
    key = private_key
    cipher = PKCS1_OAEP.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def accept_user_login(conn, cli_public_key, auth_pri_key): #Erik
    #Receive the User's enail/pass\
    #Checks if user information is in the database
    username, password, action = get_message(conn, auth_pri_key)
    #Verify user in database (add later, for now just accept)
    #Here we will verify using the username and password initialized above
    #Let the user know that they have succesfully logged in (Ballot sent in different function)
    #print(username)
    #print(password)
    send_message(conn, cli_public_key, "Successfully logged in!")
    #If(Verified), return True; else return false  --- Implement once we can verify from the database
    return

def get_vote(conn, cli_public_key, auth_pri_key): #Krishna
    #send ballot information to user that has logged in
    #Get user's response to vote
    #Store this in database, mark user as voted
    #Send client message that vote was successful
    ballot = """Who are you voting for:
        1. Obama 
        2. Trump 
        3. Hillary 
        4. Biden
        5. Trappe"""
    send_message(conn, cli_public_key, ballot)
    username, password, vote = get_message(conn, auth_pri_key)
    if(vote == "No Vote"):
        return username, None
    #Check if User is in database to confirm
    #Mark they have voted
    send_message(conn, cli_public_key, "Successful Vote!")
    return username, vote

def get_message(conn, auth_pri_key): #Krishna
    # Get message from client
    # Decrypt message
    # Check time stamp
    #   If too late, give error message and end program (for now/for demo purposes)
    # Tokenize (user, pass, action)
    encrypted = conn.recv(1024)
    print('Receiving: ' + repr(encrypted) + '\n')
    message = RSA_decrypt(encrypted, auth_pri_key)
    split = message.decode('utf-8').split(', ')
    
    time = split[0]
    # Check time here, implemented later
    user = split[1]
    password = split[2]
    action = split[3]
    
    return user, password, action

def send_message(conn, auth_pri_key, response): #Krishna
    # Get current time
    # Create (time, response)
    # Encrypt and send to client
    now = datetime.now()
    time = now.strftime("%m/%d/%Y %H:%M:%S")
    message = bytes('{}, {}'.format(time, response), 'utf-8')
    encrypted = RSA_encrypt(message, auth_pri_key)
    print('Sending: ' + repr(encrypted) + '\n')
    conn.sendall(encrypted)
    return


Users_database={}
Ballot_database={}
def create_users(message): #Jack
    #message=get_message()
    #Before using this function, you have to get message from client
    Username,Password=message[0],message[1]
    Users_database[Username]=Password
    return


def create_ballot(vote): #Jack
    #vote=get_vote
    #Get vote first
    #Confirm the user
    Username, Vote=vote[0],vote[1]
    Ballot_database[Username]=Vote
    return


def save_ballots(Ballot_database, conf_public_key): #Jack
    for item in Ballot_database.items():
        for i in range(len(item)):
            str1=repr(RSA_encrypt(bytes(item[i], 'utf-8'), conf_public_key))
            with open(r'Ballot_database.txt', 'a') as f:
                f.write(str1)
                f.write('\r\t')
    return None


### Main Server
#Socket set-up and server client communication
auth_public_key = RSA.importKey(open('auth_public_key.pem').read())
auth_private_key = RSA.importKey(open('auth_private_key.pem').read())
conf_public_key = RSA.importKey(open('conf_public_key.pem').read())
conf_private_key = RSA.importKey(open('conf_private_key.pem').read())
cli_public_key = RSA.importKey(open('cli_public_key.pem').read())

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65433        # Port to listen on (non-privileged ports are > 1023)

s= socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
print("\nServer Ready!")
s.listen()

i = 0
while(i < 4):
    conn, addr = s.accept()

    print('\nConnected by', addr)

    accept_user_login(conn, cli_public_key, auth_private_key)
    ballot = get_vote(conn, cli_public_key, auth_private_key)
    if ballot[1] != None:
        create_ballot(ballot)
        i += 1
    print("Ended connection\n")

vote_counter(Ballot_database)
save_ballots(Ballot_database, conf_public_key)
print("\nDone!")
