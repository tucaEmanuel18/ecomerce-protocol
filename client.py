import socket
from Crypto.PublicKey import RSA
from network_utils import Messenger, Authenticator, AuthenticationFailedException
import json

PORT = 5002
HOST = '127.0.0.1'
KEY_LENGTH = 2048

def get_public_keys():
    f = open('rsa_keys/merchant_public_key.pem', 'r')
    merchant_key = RSA.import_key(f.read())

    f = open('rsa_keys/pg_public_key.pem', 'r')
    pg_key = RSA.import_key(f.read())
    print("LOG: Obtained the public RSA keys of the Merchant and PG!")
    return (merchant_key, pg_key)

def generate_keys():
    key = RSA.generate(KEY_LENGTH)
    pub_key = key.publickey()
    print("LOG: Generated RSA keys!")
    return key, pub_key

if __name__ == '__main__':
    private_key, public_key = generate_keys()
    merchant_key, pg_key = get_public_keys()
    authenticator = Authenticator(private_key)

    s = socket.socket()
    print("LOG: Socket successfully created!")

    s.connect(('127.0.0.1', PORT))
    print("LOG: Successfully connected with the merchant socket!")

    merchant_messenger = Messenger(private_key, s)
    merchant_messenger.set_dest_pub_key(merchant_key)

    # Step1 - Setup Sub-protocol
    merchant_messenger.send(public_key.export_key('PEM').decode())
    print("LOG: Successfully sent my public RSA key to the merchant! Waiting the Sid!")

    sid_message = json.loads(merchant_messenger.receive())
    print("LOG: Successfully received the sid message!")

    if authenticator.verify(sid_message["sid"], sid_message["signature"], merchant_key):
        print("LOG: The message is authentic! We can continue the protocol!")
        SID = sid_message["sid"]
        print(f"The SID = {SID}")
    else:
        s.close()
        raise AuthenticationFailedException()

    s.close()
