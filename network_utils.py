import binascii

from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from hashlib import sha512
import uuid

KEY_LENGTH = 2048
AES_KEY_LENGTH = 32
BYTES_NUMBER = 32
ENCODING = 'big'


class DestinationPublicKeyNotSetException(Exception):
    def __init__(self, message="The destination public key is not set"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message}'


class CommunicationChannelNotSetException(Exception):
    def __init__(self, message="The communication channel is not set"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message}'


class AuthenticationFailedException(Exception):
    def __init__(self, message="The message authentication failed! A stranger sent to you this message! The protocol must to be stoped!"):
        self.message = message
        super().__init__(self.message)

    def __str__(self):
        return f'{self.message}'


class AESCipher:
    def pad(self, m):
        return m + b"\0" * (AES.block_size - len(m) % AES.block_size)

    def encrypt(self, message, key):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def decrypt(self, cipher_text, key):
        iv = cipher_text[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain_text = cipher.decrypt(cipher_text[AES.block_size:])
        return plain_text.rstrip(b"\0")

    def get_new_key(self):
        return Random.new().read(AES_KEY_LENGTH)


class Messenger:
    def __init__(self, my_priv_key):
        self.my_priv_key = my_priv_key
        self.decryptor = PKCS1_OAEP.new(my_priv_key)
        self.cipher = AESCipher()

        self.dest_pub_key = None
        self.encryptor = None
        self.channel = None

    def set_dest_pub_key(self, dest_pub_key):
        self.dest_pub_key = dest_pub_key
        self.encryptor = PKCS1_OAEP.new(dest_pub_key)

    def set_channel(self, channel):
        self.channel = channel

    def send(self, message):
        if self.dest_pub_key is None:
            raise DestinationPublicKeyNotSetException()

        if self.channel is None:
            raise CommunicationChannelNotSetException()

        encrypted_msg, encrypted_key = self.encrypt(message)
        self.channel.send(len(encrypted_key).to_bytes(BYTES_NUMBER, ENCODING))
        self.channel.send(encrypted_key)

        self.channel.send(len(encrypted_msg).to_bytes(BYTES_NUMBER, ENCODING))
        self.channel.send(encrypted_msg)

    def encrypt(self, message):
        if self.dest_pub_key is None:
            raise DestinationPublicKeyNotSetException()

        secret_key = self.cipher.get_new_key()
        encrypted_msg = self.cipher.encrypt(message.encode(), secret_key)
        encrypted_key = self.encryptor.encrypt(secret_key)
        return encrypted_msg, encrypted_key

    def receive(self):
        if self.channel is None:
            raise CommunicationChannelNotSetException()

        encrypted_key_length = int.from_bytes(self.channel.recv(BYTES_NUMBER), ENCODING)
        encrypted_key = self.channel.recv(encrypted_key_length)

        encrypted_msg_length = int.from_bytes(self.channel.recv(BYTES_NUMBER), ENCODING)
        encrypted_msg = self.channel.recv(encrypted_msg_length)

        return self.decrypt(encrypted_msg, encrypted_key)

    def decrypt(self, encrypted_msg, encrypted_key):
        secret_key = self.decryptor.decrypt(encrypted_key)
        return self.cipher.decrypt(encrypted_msg, secret_key).decode()


class Authenticator:
    def __init__(self, my_private_key):
        self.my_private_key = my_private_key

    def sign(self, msg):
        msg_hash = int.from_bytes(sha512(msg.encode()).digest(), byteorder=ENCODING)
        signature = pow(msg_hash, self.my_private_key.d, self.my_private_key.n)
        return signature

    def verify(self, msg, signature, pair_public_key):
        msg_hash = int.from_bytes(sha512(msg.encode()).digest(), byteorder=ENCODING)
        signature_hash = pow(signature, pair_public_key.e, pair_public_key.n)
        return msg_hash == signature_hash


class Packer:
    def pack(self, encrypted_msg_bytes):
        return binascii.hexlify(encrypted_msg_bytes).decode()

    def unpack(self, packed_message):
        return binascii.unhexlify(packed_message.encode())


def get_uniq_id():
    return str(uuid.uuid4())


def generate_keys():
    key = RSA.generate(KEY_LENGTH)
    f = open('rsa_keys/merchant_key.pem', 'wb')
    f.write(key.export_key('PEM'))
    f.close()

    public_key = key.public_key()
    f = open('rsa_keys/merchant_public_key.pem', 'wb')
    f.write(public_key.export_key('PEM'))
    f.close()

    key = RSA.generate(KEY_LENGTH)
    f = open('rsa_keys/pg_key.pem', 'wb')
    f.write(key.export_key('PEM'))
    f.close()

    public_key = key.public_key()
    f = open('rsa_keys/pg_public_key.pem', 'wb')
    f.write(public_key.export_key('PEM'))
    f.close()


if __name__ == '__main__':
     generate_keys()











# def generate_rsa_keys():
#     key = RSA.generate(KEY_LENGTH)
#     public_key = key.public_key()
#     f = open('rsa_keys/merchant_public_key.pem', 'wb')
#     f.write(public_key.export_key('PEM'))
#     f.close()
#
#     return key, public_key
