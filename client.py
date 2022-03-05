import socket
from Crypto.PublicKey import RSA
from network_utils import Messenger, Authenticator, AuthenticationFailedException, get_uniq_id, Packer
import json

MERCHANT_ADDRESS = '127.0.0.1'
MERCHANT_PORT = 5002
PG_ADDRESS = '127.0.0.1'
PG_PORT = 5003
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


def get_payment_data():
    return {
        "id": "0",
        "amount": "350",
        "card_number": "4000000000003220",
        "card_expiry_date": "09/23",
        "card_ccode": "443",
        "order_description": "Valid Payment with Correct Data",
        "merchant": "5476"
      }


def setup_sub_protocol():
    merchant_messenger.send(public_key.export_key('PEM').decode())
    print("LOG: Successfully sent my public RSA key to the merchant! Waiting the Sid!")

    sid_message = json.loads(merchant_messenger.receive())
    print("LOG: Successfully received the sid message!")

    if authenticator.verify(sid_message["sid"], sid_message["signature"], merchant_key):
        print(f"LOG: The received message is authentic! The SID is: {sid_message['sid']}")
        return sid_message['sid']
    else:
        merchant_socket.close()
        raise AuthenticationFailedException()


def exchange_sub_protocol():
    def create_pm_msg():
        pi = {
            "card_number": payment_data["card_number"],
            "card_expiry_date": payment_data["card_expiry_date"],
            "card_ccode": payment_data["card_ccode"],
            "sid": sid,
            "amount": payment_data["amount"],
            "public_key": public_key.export_key('PEM').decode(),
            "nc": nc,
            "merchant": payment_data["merchant"]
        }
        pi["signature"] = authenticator.sign(json.dumps(pi))

        pi_encrypted, pi_key = pg_messenger.encrypt(json.dumps(pi))
        return {
            "msg": packer.pack(pi_encrypted),
            "key": packer.pack(pi_key)
        }

    def create_po_msg():
        po = {
            "order_description": payment_data["order_description"],
            "sid": sid,
            "amount": payment_data["amount"],
            "nc": nc,
        }
        po["signature"] = authenticator.sign(json.dumps(po))
        return po

    pm = create_pm_msg()
    po = create_po_msg()
    msg = json.dumps({
        "pm": pm,
        "po": po
    })

    merchant_socket.settimeout(5.0)
    try:
        merchant_messenger.send(msg)
        response = json.loads(merchant_messenger.receive())
        signature = response.pop('signature')
        msg_for_auth = json.dumps({
            "resp": response['resp'],
            "sid": sid,
            "amount": payment_data['amount'],
            "nc": nc
        })
        if authenticator.verify(msg_for_auth, signature, pg_key):
            print(f"LOG: The response is authentic!")
        else:
            raise AuthenticationFailedException()
        print(f"Response: {response['resp']}")
        return True
    except socket.timeout:
        print("LOG: Exchange sub-protocol time is out!")
        return False


def resolution_sub_protocol():
    print("Client resolution sub protocol: TO BE Implemented")


if __name__ == '__main__':
    private_key, public_key = generate_keys()
    merchant_key, pg_key = get_public_keys()
    payment_data = get_payment_data()
    nc = get_uniq_id()

    merchant_messenger = Messenger(private_key)
    merchant_messenger.set_dest_pub_key(merchant_key)
    pg_messenger = Messenger(private_key)
    pg_messenger.set_dest_pub_key(pg_key)
    authenticator = Authenticator(private_key)
    packer = Packer()

    merchant_socket = socket.socket()
    print("LOG: Socket successfully created!")
    merchant_socket.connect((MERCHANT_ADDRESS, MERCHANT_PORT))
    print("LOG: Successfully connected with the merchant socket!")
    merchant_messenger.set_channel(merchant_socket)

    sid = setup_sub_protocol()
    if not exchange_sub_protocol():
        resolution_sub_protocol()

    merchant_socket.close()
