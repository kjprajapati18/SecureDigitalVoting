###imports

###Function and headers
def generate_key(modulus_length,exponent):
    key = RSA.generate(modulus_length,e=exponent)
    pub_key = key.publickey()
    private_key = key.exportKey()
    public_key = pub_key.exportKey()
    return private_key, public_key


### Main Server
#Socket set-up and server client communication

import socket

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)
