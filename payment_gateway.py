import json
from Crypto.PublicKey import RSA
import socket
from datetime import datetime

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
    print("LOG: Resolving the transaction request")
    # Success or failure and motive
    # Get the available cards data from the database
    f = open('dummy_card_data.json')
    existingCards = json.load(f)
    f.close()
    payment_card = None
    # Check card number validity
    for card in existingCards['data']['cards']:
        if card["card_number"] == pm["card_number"]:
            payment_card = card
    if payment_card is None:
        nounce = pm["nc"]
        print_msg = "Transaction Failed. Invalid Card Number."
        requests_registry[nounce] = print_msg
        print(print_msg)
        return False
    # Check Expiration Date of the Card
    card_expiration_date = pm["card_expiry_date"]
    card_exp = datetime.strptime(card_expiration_date, "%d/%m/%Y")
    present = datetime.now()
    if card_exp.date() < present.date() or pm["card_expiry_date"] != payment_card["card_expiry_date"]:
        nounce = pm["nc"]
        print_msg = "Transaction Failed. Invalid Expiration Data."
        requests_registry[nounce] = print_msg
        print(print_msg)
        return False
    # Check CCode
    card_ccode = pm["card_ccode"]
    if card_ccode != payment_card["card_ccode"]:
        nounce = pm["nc"]
        print_msg = "Transaction Failed. Invalid Ccode."
        requests_registry[nounce] = print_msg
        print(print_msg)
        return False
    # Check Card Balance
    if pm["amount"] > payment_card["balance"]:
        nounce = pm["nc"]
        print_msg = "Transaction Failed. Insufficient Funds."
        requests_registry[nounce] = print_msg
        print(print_msg)
        return False
    # Check if Merchant Exists
    f = open('merchants_list.json')
    existingMerchants = json.load(f)
    f.close()
    valid_merchant = False
    for merchant in existingMerchants['data']['merchants']:
        if merchant["merchant_name"] == pm["merchant"]:
            valid_merchant = True
            break
    if valid_merchant == False:
        nounce = pm["nc"]
        print_msg = "Transaction Failed. Merchant not registered in Payment Gateway Database."
        requests_registry[nounce] = print_msg
        print(print_msg)
        return False
    if pm["nc"] in requests_registry:
        nounce = pm["nc"]
        print_msg = "Transaction Failed. Request nounce Already Registered in our Registry."
        requests_registry[nounce] = print_msg
        print(print_msg)
        return False
    nounce = pm["nc"]
    print_msg = "The transaction was successful"
    requests_registry[nounce] = print_msg
    return print_msg
    
    
def get_response_msg(resp):
    msg_for_sign = {
        "resp": resp,
        "sid": pm['sid'],
        "amount": pm['amount'],
        "nc": pm['nc']
    }

    return json.dumps(
        {
            "resp": resp,
            "sid": pm['sid'],
            "signature": authenticator.sign(json.dumps(msg_for_sign))
        }
    )


if __name__ == '__main__':
    requests_registry = {}
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
            resp = resolve_transaction(pm)
            messenger.send(get_response_msg(resp))
            print("LOG: The receipt was sent to the merchant")
        else:
            print("LOG: Its a resolution request")
            client_public_key = RSA.import_key(msg['public_key'].encode())
            messenger.set_dest_pub_key(client_public_key)
            signature = msg.pop('signature')
            if authenticator.verify(json.dumps(msg), signature, client_public_key):
                print(f"LOG: The request is authentic!")
            else:
                raise AuthenticationFailedException()
            nc = msg['nc']
            if nc in requests_registry:
                messenger.send(get_response_msg(requests_registry[nc]))
                print("LOG: The transaction was fount and the digital receipt was sent!")
            else:
                print("LOG: The transaction was not found!")
                messenger.send(get_response_msg("The transaction was not found"))
