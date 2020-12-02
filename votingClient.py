###imports
import socket


###Function and headers
def testReadC(s):
    data = s.recv(1024)
    print('Received', repr(data))
    
def testWriteC(s):
    s.sendall(b'Hello, world')


### Main Client
#Socket set-up and server client communication

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) ###Pass in "s" to any function that needs to talk with server
s.connect((HOST, PORT))
testWriteC(s)
testReadC(s)

