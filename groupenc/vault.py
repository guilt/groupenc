import json
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from .config import DEFAULT_VAULT_FILE, DEFAULT_GROUP_KEY_BITS, DEFAULT_PAD_BYTES, DEFAULT_IV_BITS, ALLOW_SECRET_LISTING
from .helpers import makeBytesOf, makeStringOf, encodeToBase64, decodeFromBase64
from .identity import Identity

PUBLIC_KEY_HIVE = 'public_keys'
GROUP_KEY_HIVE = 'group_keys'
SECRETS_HIVE = 'secrets'


def _bootstrapGroupKey(groupKeyBits=DEFAULT_GROUP_KEY_BITS):
    return get_random_bytes(groupKeyBits // 8)


def _saveVault(vaultContents, vaultFile=DEFAULT_VAULT_FILE):
    with open(vaultFile, "w") as vaultFileStream:
        json.dump(vaultContents, vaultFileStream, indent=4, sort_keys=True)


def _bootstrapVault(identity, vaultFile=DEFAULT_VAULT_FILE):
    groupKey = _bootstrapGroupKey()
    publicKey = identity.getPublicKey()
    publicKeyId = identity.getPublicKeyId()
    encryptedGroupKey = identity.encryptPublic(groupKey)

    vaultContents = {
        PUBLIC_KEY_HIVE: {
            publicKeyId: publicKey
        },
        GROUP_KEY_HIVE: {
            publicKeyId: encryptedGroupKey
        },
        SECRETS_HIVE: {
        },
    }

    _saveVault(vaultContents, vaultFile)

    return vaultContents


def _initializeOrGetVault(identity, vaultFile=DEFAULT_VAULT_FILE):
    if os.path.exists(vaultFile):
        with open(vaultFile, "rb") as vaultFileStream:
            vaultContents = json.load(vaultFileStream)
            return vaultContents
    else:
        return _bootstrapVault(identity, vaultFile)


def _makeIV(encryptionKey, ivBits=DEFAULT_IV_BITS):
    assert encryptionKey
    sha256 = SHA256.new(makeBytesOf(encryptionKey))
    return sha256.digest()[:(ivBits // 8)]


def _encryptValue(encryptionKey, message):
    assert encryptionKey
    assert message
    encryptionKey = makeBytesOf(encryptionKey)
    iv = _makeIV(encryptionKey)
    aes = AES.new(encryptionKey, AES.MODE_GCM, nonce=iv)
    message = makeBytesOf(message)
    messagePadded = pad(message, DEFAULT_PAD_BYTES)
    messageEncrypted = aes.encrypt(messagePadded)
    return encodeToBase64(messageEncrypted)


def _decryptValue(encryptionKey, message):
    assert encryptionKey
    assert message
    encryptionKey = makeBytesOf(encryptionKey)
    iv = _makeIV(encryptionKey)
    aes = AES.new(encryptionKey, AES.MODE_GCM, nonce=iv)
    messageEncrypted = decodeFromBase64(message)
    messagePadded = aes.decrypt(messageEncrypted)
    message = unpad(messagePadded, DEFAULT_PAD_BYTES)
    return makeStringOf(message)


def _encryptKey(encryptionKey, message):
    if ALLOW_SECRET_LISTING:
        return _encryptValue(encryptionKey, message)
    assert encryptionKey
    sha256 = SHA256.new(makeBytesOf(encryptionKey)+makeBytesOf(message))
    return sha256.hexdigest()


def _decryptKey(encryptionKey, message):
    if ALLOW_SECRET_LISTING:
        return _decryptValue(encryptionKey, message)
    return None


class Vault:
    identity = None
    vaultFile = None
    vaultContents = None

    def __init__(self, identity=None, vaultFile=DEFAULT_VAULT_FILE):
        self.identity = identity or Identity()
        self.vaultFile = vaultFile or DEFAULT_VAULT_FILE
        self.vaultContents = _initializeOrGetVault(self.identity, self.vaultFile)

    def _getGroupKeyAsBytes(self):
        groupKeyEncrypted = self.vaultContents.get(GROUP_KEY_HIVE).get(self.identity.getPublicKeyId())
        return self.identity.decrypt(groupKeyEncrypted)

    def listSecrets(self):
        groupKey = self._getGroupKeyAsBytes()
        for encryptedSecretKey in self.vaultContents.get(SECRETS_HIVE, {}):
            secretKey = _decryptKey(groupKey, encryptedSecretKey)
            if secretKey:
                yield secretKey

    def getSecret(self, secretKey):
        assert secretKey
        groupKey = self._getGroupKeyAsBytes()
        encryptedSecretKey = _encryptKey(groupKey, secretKey)
        encryptedSecretValue = self.vaultContents[SECRETS_HIVE].get(encryptedSecretKey)
        if encryptedSecretValue:
            secretValue = _decryptValue(groupKey, encryptedSecretValue)
            return secretValue
        return None

    def addSecret(self, secretKey, secretValue=None):
        assert secretKey
        secretValue = secretValue or ""
        groupKey = self._getGroupKeyAsBytes()
        encryptedSecretKey = _encryptKey(groupKey, secretKey)
        encryptedSecretValue = _encryptValue(groupKey, secretValue)
        self.vaultContents[SECRETS_HIVE][encryptedSecretKey] = encryptedSecretValue

    def removeSecret(self, secretKey):
        assert secretKey
        groupKey = self._getGroupKeyAsBytes()
        encryptedSecretKey = _encryptKey(groupKey, secretKey)
        del self.vaultContents[SECRETS_HIVE][encryptedSecretKey]

    def save(self):
        _saveVault(self.vaultContents, self.vaultFile)
