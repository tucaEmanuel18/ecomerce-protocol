import json
from Crypto.PublicKey import RSA
import socket
from datetime import datetime
from network_utils import Messenger, Authenticator, Packer, AuthenticationFailedException

PORT = 5003


def get_data():
    f = open('dummy_card_data.json')
    cards_data = json.load(f)['data']['cards']
    f.close()
    f = open('merchants_list.json')
    merchants_data = json.load(f)['data']['merchants']
    f.close()
    return cards_data, merchants_data


def get_merchant_public_key():
    f = open('rsa_keys/merchant_public_key.pem', 'r')
    return RSA.import_key(f.read())


def get_my_rsa_keys():
    f = open('rsa_keys/pg_key.pem', 'r')
    key = RSA.import_key(f.read())

    f = open('rsa_keys/pg_public_key.pem', 'r')
    public_key = RSA.import_key(f.read())

    return key, public_key


def resolve_transaction(pm):
    def get_card_by_number(card_number):
        for card in cards_data:
            if card["card_number"] == card_number:
                return card
        return False

    def is_valid_date(request_expiration_date):
        request_exp = datetime.strptime(request_expiration_date, "%d/%m/%Y")
        present = datetime.now()
        return request_expiration_date == card["card_expiry_date"] and request_exp.date() > present.date()

    def get_merchant_by_name(request_merchant):
        for merchant in merchants_data:
            if merchant["merchant_name"] == request_merchant:
                return merchant
        return False

    def exchange_amount():
        card['balance'] -= pm['amount']
        merchant['balance'] += pm['amount']

    print("LOG: Resolving the transaction request")
    if pm["nc"] in requests_registry:
        return "Transaction Failed. This request is already precessed."

    card = get_card_by_number(pm["card_number"])
    if not card:
        return "Transaction Failed. Invalid card number!"

    if not is_valid_date(pm["card_expiry_date"]):
        return "Transaction Failed. Invalid Expiration Date!"

    if not pm["card_ccode"] == card["card_ccode"]:
        return "Transaction Failed. Invalid challenge code!"

    if pm["amount"] > card["balance"]:
        return "Transaction Failed. Insufficient Funds!"

    merchant = get_merchant_by_name(pm['merchant'])
    if not merchant:
        return "Transaction Failed. Merchant not registered!"

    exchange_amount()
    return "Transaction successful!"
    
    
def get_response_msg(data, resp):
    msg_for_sign = {
        "resp": resp,
        "sid": data['sid'],
        "amount": data['amount'],
        "nc": data['nc']
    }

    return json.dumps(
        {
            "resp": resp,
            "sid": data['sid'],
            "signature": authenticator.sign(json.dumps(msg_for_sign))
        }
    )


def exchange_sub_protocol(msg):
    def auth_merchant():
        message_for_auth = json.dumps({
            'sid': pm['sid'],
            'pub_key_c': pm['public_key'],
            'amount': pm['amount']
        })
        if authenticator.verify(message_for_auth, msg['signature'], merchant_key):
            print(f"LOG: Merchant message authenticated!")
        else:
            raise AuthenticationFailedException()

    def auth_client():
        signature = pm.pop('signature')
        client_pub_key = RSA.import_key(pm['public_key'].encode())
        if authenticator.verify(json.dumps(pm), signature, client_pub_key):
            print(f"LOG: Client message authenticated")
        else:
            raise AuthenticationFailedException()

    print("LOG: Exchange sub-protocol is running!")
    messenger.set_dest_pub_key(merchant_key)

    encrypted_pm = msg['pm']
    pm = json.loads(
        messenger.decrypt(
            packer.unpack(encrypted_pm['msg']),
            packer.unpack(encrypted_pm['key'])
        )
    )

    auth_merchant()
    auth_client()
    resp = resolve_transaction(pm)
    requests_registry[pm['nc']] = resp
    messenger.send(get_response_msg(pm, resp))
    print("LOG: The response was sent to the merchant\n")


def resolution_sub_protocol(msg):
    print("LOG: Resolution sub-protocol is running")
    client_public_key = RSA.import_key(msg['public_key'].encode())
    messenger.set_dest_pub_key(client_public_key)

    signature = msg.pop('signature')
    if authenticator.verify(json.dumps(msg), signature, client_public_key):
        print(f"LOG: Client message authenticated!")
    else:
        raise AuthenticationFailedException()

    if msg['nc'] in requests_registry:
        messenger.send(get_response_msg(msg, requests_registry[msg['nc']]))
        print("LOG: The transaction was fount and the digital receipt was sent!")
    else:
        print("LOG: The transaction was not found!")
        messenger.send(get_response_msg(msg, "The transaction was not found"))


if __name__ == '__main__':
    requests_registry = {}
    private_key, public_key = get_my_rsa_keys()
    merchant_key = get_merchant_public_key()
    messenger = Messenger(private_key)
    authenticator = Authenticator(private_key)
    packer = Packer()

    cards_data, merchants_data = get_data()

    socket = socket.socket()
    print("LOG: Socket successfully created")
    socket.bind(('', PORT))
    print("LOG: Socket binded to %s" % PORT)
    socket.listen(5)
    print("LOG: Socket is listening")

    while True:
        channel, addr = socket.accept()
        print('LOG: Got connection from', addr)
        messenger.set_channel(channel)
        msg = json.loads(messenger.receive())

        try:
            if 'pm' in msg:
                exchange_sub_protocol(msg)
            else:
                resolution_sub_protocol(msg)
        except AuthenticationFailedException as e:
            print(e.message)
