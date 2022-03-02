import socket
from network_utils import Messenger
from Crypto.PublicKey import RSA

PORT = 5002
HOST = '127.0.0.1'

if __name__ == '__main__':
    f = open('rsa_keys/merchant_key.pem', 'r')
    private_key = RSA.import_key(f.read())
    s = socket.socket()
    print("Socket successfully created")
    s.bind(('', PORT))
    print("socket binded to %s" % (PORT))
    s.listen(5)
    print("socket is listening")

    while True:
        c, addr = s.accept()
        print('Got connection from', addr)
        client_messenger = Messenger(private_key, c)
        msg = client_messenger.receive()
        print(f"Decrypted: {msg}")
        # msg = public_key.export_key('PEM')
        # c.send('Thank you for connecting'.encode())
        c.close()