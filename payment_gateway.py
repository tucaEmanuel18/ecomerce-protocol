import json
from Crypto.PublicKey import RSA
import socket

from client import KEY_LENGTH
from network_utils import Messenger, Authenticator, Packer, AuthenticationFailedException

PORT = 5003


def get_data():
    f = open('dummy_card_data.json')
    jsonData = json.load(f)
    print(jsonData)
    for i in jsonData['data']['cards']:
        print(i)
    f.close()

    # return both merchants and cards dictionaries


def get_merchant_public_key():
    f = open('rsa_keys/merchant_public_key.pem', 'r')
    return RSA.import_key(f.read())


def get_my_rsa_keys():
    f = open('rsa_keys/pg_key.pem', 'r')
    key = RSA.import_key(f.read())

    f = open('rsa_keys/pg_public_key.pem', 'r')
    public_key = RSA.import_key(f.read())

    return key, public_key


# def generate_rsa_keys():
#     key = RSA.generate(KEY_LENGTH)
#     public_key = key.public_key()
#     f = open('rsa_keys/pg_public_key.pem', 'wb')
#     f.write(public_key.export_key('PEM'))
#     f.close()
#
#     return key, public_key

def authenticate_messages(msg):
    def auth_merchant():
        message_for_auth = json.dumps({
            'sid': pm['sid'],
            'pub_key_c': pm['public_key'],
            'amount': pm['amount']
        })

        if authenticator.verify(message_for_auth, msg['signature'], merchant_key):
            print(f"LOG: The received message from merchant is authentic!")
        else:
            raise AuthenticationFailedException()

    def auth_client():
        signature = pm.pop('signature')
        client_pub_key = RSA.import_key(pm['public_key'].encode())
        if authenticator.verify(json.dumps(pm), signature, client_pub_key):
            print(f"LOG: The received message from client through merchant is authentic!")
        else:
            raise AuthenticationFailedException()

    auth_merchant()
    auth_client()


def resolve_transaction(pm):
    def get_transaction_resp():
        return "The transaction was successful"

    resp = get_transaction_resp()
    msg_for_sign = {
        "resp": resp,
        "sid": pm['sid'],
        "amount": pm['amount'],
        "nc": pm['nc']
    }

    return json.dumps(
        {
            "resp": get_transaction_resp(),
            "sid": pm['sid'],
            "signature": authenticator.sign(json.dumps(msg_for_sign))
        }
    )


if __name__ == '__main__':
    private_key, public_key = get_my_rsa_keys()
    merchant_key = get_merchant_public_key()
    messenger = Messenger(private_key)
    authenticator = Authenticator(private_key)
    packer = Packer()

    client_socket = socket.socket()
    print("LOG: Socket successfully created")
    client_socket.bind(('', PORT))
    print("LOG: Socket binded to %s" % PORT)
    client_socket.listen(5)
    print("LOG: Socket is listening")

    while True:
        channel, addr = client_socket.accept()
        print('LOG: Got connection from', addr)
        messenger.set_channel(channel)
        msg = json.loads(messenger.receive())

        if 'pm' in msg:  # it is a merchant
            print("LOG: Its a transaction request from a merchant")
            messenger.set_dest_pub_key(merchant_key)

            encrypted_pm = msg['pm']
            pm = json.loads(
                messenger.decrypt(
                    packer.unpack(encrypted_pm['msg']),
                    packer.unpack(encrypted_pm['key'])
                )
            )
            authenticate_messages(msg)
            messenger.send(resolve_transaction(pm))
        else:
            client_public_key = RSA.import_key(msg['client_pub_key'].encode())
            messenger.set_dest_pub_key(client_public_key)
            messenger.send("Resolution Flow - To Be implemented!")
