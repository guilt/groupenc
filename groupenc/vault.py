import json
import os

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from .config import DEFAULT_VAULT_FILE, DEFAULT_GROUP_KEY_BITS, DEFAULT_PAD_BYTES, DEFAULT_IV_BITS, \
    DEFAULT_KEY_ENCODING, HASH_SECRETS
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
    assert encryptionKey, "Encryption Key Unspecified"
    sha256 = SHA256.new(makeBytesOf(encryptionKey, DEFAULT_KEY_ENCODING))
    return sha256.digest()[:(ivBits // 8)]


def _encryptValue(encryptionKey, message):
    assert encryptionKey, "Encryption Key Unspecified"
    assert message, "Message Unspecified"
    encryptionKey = makeBytesOf(encryptionKey, DEFAULT_KEY_ENCODING)
    iv = _makeIV(encryptionKey)
    aes = AES.new(encryptionKey, AES.MODE_GCM, nonce=iv)
    message = makeBytesOf(message)
    messagePadded = pad(message, DEFAULT_PAD_BYTES)
    messageEncrypted = aes.encrypt(messagePadded)
    return encodeToBase64(messageEncrypted)


def _decryptValue(encryptionKey, message):
    assert encryptionKey, "Encryption Key Unspecified"
    assert message, "Message Unspecified"
    encryptionKey = makeBytesOf(encryptionKey, DEFAULT_KEY_ENCODING)
    iv = _makeIV(encryptionKey)
    aes = AES.new(encryptionKey, AES.MODE_GCM, nonce=iv)
    messageEncrypted = decodeFromBase64(message)
    messagePadded = aes.decrypt(messageEncrypted)
    message = unpad(messagePadded, DEFAULT_PAD_BYTES)
    return makeStringOf(message)


def _hashKey(message):
    assert message, "Message Unspecified"
    sha256 = SHA256.new(makeBytesOf(message))
    return sha256.hexdigest()

def _encryptKey(encryptionKey, message):
    assert encryptionKey, "Encryption Key Unspecified"
    if HASH_SECRETS:
        return _hashKey(message)
    return _encryptValue(encryptionKey, message)


def _decryptKey(encryptionKey, message):
    assert encryptionKey, "Encryption Key Unspecified"
    if HASH_SECRETS:
        return None
    return makeBytesOf(_decryptValue(encryptionKey, message))

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

    def _listSecretsEncrypted(self):
        for encryptedSecretKey in self.vaultContents.get(SECRETS_HIVE, {}):
            yield encryptedSecretKey

    def listSecrets(self):
        if not HASH_SECRETS:
            groupKey = self._getGroupKeyAsBytes()
            for encryptedSecretKey in self._listSecretsEncrypted():
                decryptedKey = _decryptKey(groupKey, encryptedSecretKey)
                if decryptedKey:
                    yield makeStringOf(decryptedKey)

    def listKeys(self):
        for keyId, keyValue in self.vaultContents.get(PUBLIC_KEY_HIVE, {}).items():
            yield keyId, keyValue

    def _getSecretForEncryptedKey(self, encryptedSecretKey, groupKey=None):
        assert encryptedSecretKey, "Encrypted Secret Unspecified"
        groupKey = groupKey or self._getGroupKeyAsBytes()
        encryptedSecretValue = self.vaultContents.get(SECRETS_HIVE, {}).get(encryptedSecretKey)
        if encryptedSecretValue:
            secretValue = _decryptValue(groupKey, encryptedSecretValue)
            return secretValue
        return None

    def getSecret(self, secretKey, groupKey=None):
        assert secretKey, "Secret Unspecified"
        groupKey = groupKey or self._getGroupKeyAsBytes()
        encryptedSecretKey = _encryptKey(groupKey, secretKey)
        return self._getSecretForEncryptedKey(encryptedSecretKey)

    def _addSecretForEncryptedKey(self, encryptedSecretKey, secretValue=None, groupKey=None):
        assert encryptedSecretKey, "Encrypted Secret Unspecified"
        groupKey = groupKey or self._getGroupKeyAsBytes()
        secretValue = secretValue or ""
        encryptedSecretValue = _encryptValue(groupKey, secretValue)
        self.vaultContents[SECRETS_HIVE][encryptedSecretKey] = encryptedSecretValue

    def addSecret(self, secretKey, secretValue=None, groupKey=None):
        assert secretKey, "Secret Unspecified"
        groupKey = groupKey or self._getGroupKeyAsBytes()
        encryptedSecretKey = _encryptKey(groupKey, secretKey)
        self._addSecretForEncryptedKey(encryptedSecretKey, secretValue, groupKey)

    def _removeSecretForEncryptedKey(self, encryptedSecretKey):
        assert encryptedSecretKey, "Encrypted Secret Unspecified"
        if encryptedSecretKey in self.vaultContents.get(SECRETS_HIVE, {}):
            del self.vaultContents[SECRETS_HIVE][encryptedSecretKey]

    def removeSecret(self, secretKey):
        assert secretKey, "Secret Unspecified"
        groupKey = self._getGroupKeyAsBytes()
        encryptedSecretKey = _encryptKey(groupKey, secretKey)
        self._removeSecretForEncryptedKey(encryptedSecretKey)

    def induct(self, givenKey, groupKey=None):
        assert givenKey, "Unable to get an Identity to Induct"
        groupKey = groupKey or self._getGroupKeyAsBytes()
        assert groupKey, "Unable to get a Group Key"
        identity = Identity(givenKey=givenKey)
        self.vaultContents = _inductIntoVault(self.vaultContents, identity, groupKey)

    def disown(self, givenKey=None):
        identity = Identity(givenKey=givenKey) if givenKey else self.identity
        self.vaultContents = _disownFromVault(self.vaultContents, identity)

    def rotate(self):
        groupKey = self._getGroupKeyAsBytes()
        newGroupKey = _bootstrapGroupKey()
        assert newGroupKey != groupKey, "Unable to derive a New Group Key"

        if not HASH_SECRETS:
            for secretKey in list(self.listSecrets()):
                secretValue = self.getSecret(secretKey)
                self.removeSecret(secretKey)
                self.addSecret(secretKey, secretValue, newGroupKey)
        else:
            for encryptedSecretKey in list(self._listSecretsEncrypted()):
                secretValue = self._getSecretForEncryptedKey(encryptedSecretKey)
                self._removeSecretForEncryptedKey(encryptedSecretKey)
                self._addSecretForEncryptedKey(encryptedSecretKey, secretValue, newGroupKey)

        for _, givenKey in dict(self.listKeys()).items():
            self.disown(givenKey)
            self.induct(givenKey, newGroupKey)

    def save(self):
        _saveVault(self.vaultContents, self.vaultFile)
