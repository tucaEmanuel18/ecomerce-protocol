from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

KEY_LENGTH = 2048
AES_KEY_LENGTH = 32
BLOCK_LENGTH = 190
BYTES_NUMBER = 16
ENCODING = 'big'


class DestinationPublicKeyNotSetException(Exception):
    def __init__(self, message="The destination public key is not set"):
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
    def __init__(self, my_priv_key, channel, secret_key=Random.new().read(AES_KEY_LENGTH)):
        self.channel = channel
        self.my_priv_key = my_priv_key
        self.secret_key = secret_key
        self.cipher = AESCipher()
        self.decryptor = PKCS1_OAEP.new(my_priv_key)

        self.dest_pub_key = None
        self.encryptor = None

    def set_dest_pub_key(self, dest_pub_key):
        self.dest_pub_key = dest_pub_key
        self.encryptor = PKCS1_OAEP.new(dest_pub_key)

    def set_secret_key(self, secret_key):
        self.secret_key = secret_key

    def send(self, message):
        if self.dest_pub_key is not None:
            encrypted_msg, encrypted_key = self.encrypt(message)
            self.channel.send(len(encrypted_key).to_bytes(BYTES_NUMBER, ENCODING))
            self.channel.send(encrypted_key)

            self.channel.send(len(encrypted_msg).to_bytes(BYTES_NUMBER, ENCODING))
            self.channel.send(encrypted_msg)
        else:
            raise DestinationPublicKeyNotSetException()

    def receive(self):
        encrypted_key_length = int.from_bytes(self.channel.recv(BYTES_NUMBER), ENCODING)
        print(encrypted_key_length)
        encrypted_key = self.channel.recv(encrypted_key_length)

        encrypted_msg_length = int.from_bytes(self.channel.recv(BYTES_NUMBER), ENCODING)
        print(encrypted_msg_length)
        encrypted_msg = self.channel.recv(encrypted_msg_length)

        return self.decrypt(encrypted_msg, encrypted_key).decode()

    def encrypt(self, message):
        encrypted_msg = self.cipher.encrypt(message.encode(), self.secret_key)
        encrypted_key = self.encryptor.encrypt(self.secret_key)
        return encrypted_msg, encrypted_key

    def decrypt(self, encrypted_msg, encrypted_key):
        self.secret_key = self.decryptor.decrypt(encrypted_key)
        return self.cipher.decrypt(encrypted_msg, self.secret_key)



def get_public_keys():
    f = open('rsa_keys/merchant_public_key.pem', 'r')
    merchant_key = RSA.import_key(f.read())

    f = open('rsa_keys/pg_public_key.pem', 'r')
    pg_key = RSA.import_key(f.read())
    return (merchant_key, pg_key)


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
    msg = "Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!Acest este un mesaj secret!"


# class Messenger:
#     def __init__(self, my_priv_key, channel):
#         self.channel = channel
#         self.my_priv_key = my_priv_key
#         self.decryptor = PKCS1_OAEP.new(my_priv_key)
#
#         self.dest_pub_key = None
#         self.encryptor = None
#
#     def send(self, message):
#         encrypt_msg = self.encrypt(message)
#         if not encrypt_msg:
#             return False
#         else:
#             self.channel.send(len(encrypt_msg).to_bytes(BYTES_NUMBER, ENCODING))
#             self.channel.send(encrypt_msg)
#
#     def receive(self):
#         msg_length = int.from_bytes(self.channel.recv(BYTES_NUMBER), ENCODING)
#         print(msg_length)
#         encrypt_msg = self.channel.recv(msg_length)
#         message = self.decrypt(encrypt_msg).decode()
#         return message
#
#     def set_dest_pub_key(self, dest_pub_key):
#         self.dest_pub_key = dest_pub_key
#         self.encryptor = PKCS1_OAEP.new(dest_pub_key)
#
#     def encrypt(self, message):
#         if self.dest_pub_key is None:
#             return False
#         else:
#             encrypted_message = ''.encode()
#             start_position = 0
#             length = len(message)
#             while start_position + BLOCK_LENGTH <= length:
#                 current_block = message[start_position:start_position + BLOCK_LENGTH]
#                 encrypted_message += (self.encryptor.encrypt(current_block.encode()))
#                 start_position += BLOCK_LENGTH
#
#             if start_position < length:
#                 current_block = message[start_position:length]
#                 encrypted_message += (self.encryptor.encrypt(current_block.encode()))
#             return encrypted_message
#
#     def decrypt(self, message):
#         decrypted_message = ''.encode()
#         start_position = 0
#         length = len(message)
#         while start_position + BLOCK_LENGTH <= length:
#             current_block = message[start_position:start_position + BLOCK_LENGTH]
#             decrypted_message += (self.decryptor.decrypt(current_block))
#             start_position += BLOCK_LENGTH
#
#         if start_position < length:
#             current_block = message[start_position:length]
#             decrypted_message += (self.decryptor.decrypt(current_block))
#         return decrypted_message
