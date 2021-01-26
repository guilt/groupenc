from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import os
from .config import DEFAULT_PUBLIC_KEY, DEFAULT_PRIVATE_KEY, DEFAULT_KEY_BITS
from .helpers import encodeToBase64, makeBytesOf

def _bootstrapKeyPair(privateKeyFile=DEFAULT_PRIVATE_KEY, publicKeyFile=DEFAULT_PUBLIC_KEY):
    keyPair = RSA.generate(DEFAULT_KEY_BITS)

    privateKey = keyPair.export_key()
    with open(privateKeyFile, "wb") as privateKeyFileStream:
        privateKeyFileStream.write(privateKey)

    publicKey = keyPair.publickey().export_key()
    with open(publicKeyFile, "wb") as publicKeyFileStream:
        publicKeyFileStream.write(publicKey)

    return keyPair


def _initializeOrGetKeyPair(privateKeyFile=DEFAULT_PRIVATE_KEY, publicKeyFile=DEFAULT_PUBLIC_KEY):
    if os.path.exists(privateKeyFile):
        with open(privateKeyFile, "rb") as privateKeyFileStream:
            privateKey = privateKeyFileStream.read()
            return RSA.import_key(privateKey)
    else:
        return _bootstrapKeyPair(privateKeyFile, publicKeyFile)


class Identity:

    keyPair = None

    def __init__(self, privateKeyFile=DEFAULT_PRIVATE_KEY, publicKeyFile=DEFAULT_PUBLIC_KEY):
        self.keyPair = _initializeOrGetKeyPair(privateKeyFile, publicKeyFile)

    def getKeyPair(self):
        return self.keyPair

    def encryptPublic(self, message):
        pkcs1 = PKCS1_OAEP.new(self.keyPair.publickey())
        return encodeToBase64(pkcs1.encrypt(makeBytesOf(message)))

    def encryptPrivate(self, message):
        pkcs1 = PKCS1_OAEP.new(self.keyPair.export_key())
        return encodeToBase64(pkcs1.encrypt(makeBytesOf(message)))
