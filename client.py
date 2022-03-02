import socket
from Crypto.PublicKey import RSA
from network_utils import Messenger

PORT = 5002
HOST = '127.0.0.1'
KEY_LENGTH = 2048

def get_public_keys():
    f = open('rsa_keys/merchant_public_key.pem', 'r')
    merchant_key = RSA.import_key(f.read())

    f = open('rsa_keys/pg_public_key.pem', 'r')
    pg_key = RSA.import_key(f.read())
    return (merchant_key, pg_key)

def generate_keys():
    key = RSA.generate(KEY_LENGTH)
    pub_key = key.publickey()
    return (key, pub_key)

if __name__ == '__main__':
    public_key, private_key = generate_keys()
    merchant_key, pg_key = get_public_keys()

    s = socket.socket()
    s.connect(('127.0.0.1', PORT))
    merchant_messenger = Messenger(private_key, s)
    merchant_messenger.set_dest_pub_key(merchant_key)
    # msg = public_key.export_key('PEM')
    msg = "Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!"
    merchant_messenger.send(msg)
    s.close()

