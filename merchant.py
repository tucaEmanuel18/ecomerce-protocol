import socket
from network_utils import Messenger, Authenticator, AuthenticationFailedException, KEY_LENGTH, get_uniq_id
from Crypto.PublicKey import RSA
import json
import time

PG_ADDRESS = '127.0.0.1'
PG_PORT = 5003

PORT = 5002
SIMULATE_TIMEOUT = False
SLEEP_VALUE = 2
SIMULATE_FAKE_SIGNATURE = False

def get_pg_public_key():
    f = open('rsa_keys/pg_public_key.pem', 'r')
    return RSA.import_key(f.read())


def get_my_rsa_keys():
    f = open('rsa_keys/merchant_key.pem', 'r')
    key = RSA.import_key(f.read())

    f = open('rsa_keys/merchant_public_key.pem', 'r')
    public_key = RSA.import_key(f.read())

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
    sid = get_uniq_id()
    msg = {
        "sid": sid,
        "signature": authenticator.sign(sid)
    }
    return sid, json.dumps(msg)


def setup_sub_protocol():
    client_public_key = RSA.import_key(client_messenger.receive().encode())
    print("LOG: Received the client public RSA key")
    client_messenger.set_dest_pub_key(client_public_key)

    current_sid, sid_message = prepare_sid_message()
    client_messenger.send(sid_message)
    print("LOG: Sent the sid to the client")

    clients_registry[current_sid] = client_public_key


def exchange_sub_protocol():
    def authenticate_po():
        signature = po.pop("signature")  # remove the 'signature' key to obtain the signed part of the message
        if authenticator.verify(json.dumps(po), signature, clients_registry[po['sid']]):
            print(f"LOG: The received message is authentic!")
        else:
            raise AuthenticationFailedException()

    def pg_request():
        def get_msg_to_pg():
            client_pub_key = clients_registry[po['sid']]
            msg_for_signature = json.dumps({
                'sid': po['sid'],
                'pub_key_c': client_pub_key.export_key('PEM').decode(),
                'amount': po['amount']
            })
            return json.dumps({
                "pm": pm,
                "signature": authenticator.sign(msg_for_signature)
            })

        pg_messenger = Messenger(private_key)
        pg_messenger.set_dest_pub_key(get_pg_public_key())
        pg_socket = socket.socket()
        print("LOG: PG Socket successfully created!")
        pg_socket.connect((PG_ADDRESS, PG_PORT))
        print("LOG: Successfully connected with the payment gateway socket!")
        pg_messenger.set_channel(pg_socket)

        pg_messenger.send(get_msg_to_pg())
        print("LOG: The transaction request is sent to the payment gateway!")
        response = json.loads(pg_messenger.receive())
        pg_socket.close()
        return response

    msg_from_client = json.loads(client_messenger.receive())
    pm = msg_from_client["pm"]
    po = msg_from_client["po"]
    if po['sid'] in clients_registry:
        authenticate_po()
        pg_response = pg_request()
        print(f"LOG: I receive the pg response: '{pg_response['resp']}'")
        if SIMULATE_TIMEOUT:
            time.sleep(SLEEP_VALUE)
        client_messenger.send(json.dumps(pg_response))
        print("LOG: The transaction response is sent to the client!\n")
    else:
        # @TODO  To return specific message to the client!
        print("ERROR: Invalid SID")
        return False


if __name__ == '__main__':
    clients_registry = {}
    private_key, public_key = get_my_rsa_keys()
    client_messenger = Messenger(private_key)
    authenticator = Authenticator(private_key)

    client_socket = socket.socket()
    print("LOG: Socket successfully created")
    client_socket.bind(('', PORT))
    print("LOG: Socket binded to %s" % PORT)
    client_socket.listen(5)
    print("LOG: Socket is listening")

    while True:
        client_channel, addr = client_socket.accept()
        print('LOG: Got connection from', addr)
        client_messenger.set_channel(client_channel)

        setup_sub_protocol()
        exchange_sub_protocol()
