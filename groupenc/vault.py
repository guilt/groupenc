import json
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from .config import DEFAULT_VAULT_FILE, DEFAULT_GROUP_KEY_BITS, DEFAULT_PAD_BYTES, DEFAULT_IV_BITS, DEFAULT_KEY_ENCODING, ALLOW_SECRET_LISTING
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

def _inductIntoVault(vaultContents, identity, groupKey):
    publicKey = identity.getPublicKey()
    keyId = identity.getId()
    encryptedGroupKey = identity.encryptPublic(groupKey)
    vaultContents[PUBLIC_KEY_HIVE][keyId] = publicKey
    vaultContents[GROUP_KEY_HIVE][keyId] = encryptedGroupKey
    return vaultContents

def _disownFromVault(vaultContents, identity):
    keyId = identity.getId()
    if keyId in vaultContents.get(PUBLIC_KEY_HIVE, {}):
        del vaultContents[PUBLIC_KEY_HIVE][keyId]
    if keyId in vaultContents.get(GROUP_KEY_HIVE, {}):
        del vaultContents[GROUP_KEY_HIVE][keyId]
    return vaultContents

def _bootstrapVault(identity, vaultFile=DEFAULT_VAULT_FILE):
    groupKey = _bootstrapGroupKey()

    vaultContents = {
        PUBLIC_KEY_HIVE: {},
        GROUP_KEY_HIVE: {},
        SECRETS_HIVE: {},
    }

    vaultContents = _inductIntoVault(vaultContents, identity, groupKey)
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
    sha256 = SHA256.new(makeBytesOf(encryptionKey, DEFAULT_KEY_ENCODING))
    return sha256.digest()[:(ivBits // 8)]


def _encryptValue(encryptionKey, message):
    assert encryptionKey
    assert message
    encryptionKey = makeBytesOf(encryptionKey, DEFAULT_KEY_ENCODING)
    iv = _makeIV(encryptionKey)
    aes = AES.new(encryptionKey, AES.MODE_GCM, nonce=iv)
    message = makeBytesOf(message)
    messagePadded = pad(message, DEFAULT_PAD_BYTES)
    messageEncrypted = aes.encrypt(messagePadded)
    return encodeToBase64(messageEncrypted)


def _decryptValue(encryptionKey, message):
    assert encryptionKey
    assert message
    encryptionKey = makeBytesOf(encryptionKey, DEFAULT_KEY_ENCODING)
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
    sha256 = SHA256.new(makeBytesOf(message))
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
        groupKeyEncrypted = self.vaultContents.get(GROUP_KEY_HIVE).get(self.identity.getId())
        if not groupKeyEncrypted:
            return None
        return self.identity.decrypt(groupKeyEncrypted)

    def listSecrets(self):
        groupKey = self._getGroupKeyAsBytes()
        for encryptedSecretKey in self.vaultContents.get(SECRETS_HIVE, {}):
            secretKey = _decryptKey(groupKey, encryptedSecretKey)
            if secretKey:
                yield secretKey

    def listKeys(self):
        for keyId, keyValue in self.vaultContents.get(PUBLIC_KEY_HIVE, {}).items():
            yield keyId, keyValue

    def getSecret(self, secretKey):
        assert secretKey
        groupKey = self._getGroupKeyAsBytes()
        encryptedSecretKey = _encryptKey(groupKey, secretKey)
        encryptedSecretValue = self.vaultContents.get(SECRETS_HIVE, {}).get(encryptedSecretKey)
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

    def induct(self, givenKey = None, groupKey = None):
        groupKey = groupKey or self._getGroupKeyAsBytes()
        assert groupKey
        identity = self.identity if (givenKey == None) else Identity(givenKey=givenKey)
        self.vaultContents = _inductIntoVault(self.vaultContents, identity, groupKey)

    def disown(self, givenKey = None):
        identity = self.identity if (givenKey == None) else Identity(givenKey=givenKey)
        self.vaultContents = _disownFromVault(self.vaultContents, identity)

    def rotate(self):
        newGroupKey = _bootstrapGroupKey()
        groupKey = self._getGroupKeyAsBytes()
        assert newGroupKey != groupKey
        for keyId, givenKey in self.listKeys():
            self.disown(givenKey)
            self.induct(givenKey, newGroupKey)

    def save(self):
        _saveVault(self.vaultContents, self.vaultFile)
