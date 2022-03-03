import socket
from network_utils import Messenger, Authenticator, KEY_LENGTH
from Crypto.PublicKey import RSA
import json
import uuid

PORT = 5002
HOST = '127.0.0.1'


def generate_rsa_keys():
    key = RSA.generate(KEY_LENGTH)
    f = open('rsa_keys/merchant_key.pem', 'wb')
    f.write(key.export_key('PEM'))
    f.close()

    public_key = key.public_key()
    f = open('rsa_keys/merchant_public_key.pem', 'wb')
    f.write(public_key.export_key('PEM'))
    f.close()

    return key, public_key


def generate_wrong_rsa_keys():
    """
    This function generates a pair of RSA keys, but don't save them into files
    It can be used to test what happens when the message is signed with another key
    (Simulating an stranger message)
    :return: a pair of RSA keys
    """
    key = RSA.generate(KEY_LENGTH)
    public_key = key.public_key()
    return key, public_key


def prepare_sid_message():
    sid = str(uuid.uuid4())
    signed_sid = authenticator.sign(sid)
    msg = {
        "sid": sid,
        "signature": signed_sid
    }
    return sid, json.dumps(msg)


if __name__ == '__main__':
    private_key, public_key = generate_rsa_keys()
    authenticator = Authenticator(private_key)

    s = socket.socket()
    print("LOG: Socket successfully created")
    s.bind(('', PORT))
    print("LOG: Socket binded to %s" % (PORT))
    s.listen(5)
    print("LOG: Socket is listening")

    while True:
        c, addr = s.accept()
        print('LOG: Got connection from', addr)
        client_messenger = Messenger(private_key, c)

        # Step1 - Setup Sub-protocol
        client_public_key = RSA.import_key(client_messenger.receive().encode())
        print("LOG: Received the client public RSA key")
        client_messenger.set_dest_pub_key(client_public_key)

        current_sid, sid_message = prepare_sid_message()
        client_messenger.send(sid_message)
        print("LOG: Sent the sid to the client")
        c.close()
