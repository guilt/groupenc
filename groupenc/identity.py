from .config import *
from Crypto.PublicKey import RSA

def bootstrapKeyPair(privateKeyFile=DEFAULT_PRIVATE_KEY, publicKeyFile=DEFAULT_PUBLIC_KEY):
    keyPair = RSA.generate(DEFAULT_KEY_BITS)

    privateKey = keyPair.export_key()
    with open(privateKeyFile, "wb") as privateKeyFileStream:
        privateKeyFileStream.write(privateKey)

    publicKey = keyPair.publickey().export_key()
    with open(publicKeyFile, "wb") as publicKeyFileStream:
        publicKeyFileStream.write(publicKey)

    return keyPair

def initializeOrGetKeyPair(privateKeyFile=DEFAULT_PRIVATE_KEY, publicKeyFile=DEFAULT_PUBLIC_KEY):
    if os.path.exists(privateKeyFile):
        with open(privateKeyFile, "rb") as privateKeyFileStream:
            privateKey = privateKeyFileStream.read()
            return RSA.import_key(privateKey)
    else:
        return bootstrapKeyPair(privateKeyFile, publicKeyFile)
