# -*- coding: utf-8 -*-
import unittest

from groupenc.config import DEFAULT_VALUE_ENCODING, DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY
from groupenc.identity import Identity


class TestIdentity(unittest.TestCase):

    testVectors = [
        "Test Message",
        '0',
        '0000',
        u"한",
        u"😘🤩",
        '8'*22
    ]

    publicKey = \
"""-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIUMl904p2Ap6I2A067jo/JtxcHAQBMy
7oveuoUKUcYeEGQCSa89KIFCW2QLB1PAtIzGLTXiOU7HqrIdGXhtHjkCAwEAAQ==
-----END PUBLIC KEY-----"""

    privateKey = \
"""-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBAIUMl904p2Ap6I2A067jo/JtxcHAQBMy7oveuoUKUcYeEGQCSa89
KIFCW2QLB1PAtIzGLTXiOU7HqrIdGXhtHjkCAwEAAQJAMoQUiP8AtcdTr55RQR7X
Wa2KH0VSTrfQ0LRxVyAS6khk/TSHIat8w8+uMb601l0z93r4cpKzqLJa8aUa2Web
8QIhAM0duS7HrzBgIQ+5hZTY7Fvw3bEJ4d+9Js8BhxvUMCqtAiEApg4gpgy4IsqS
P8TEciEYiFbIYGDEiuA4KMypaOPoHz0CIF+y+4CA+BLY9vPwOgvtfbGT2stL8g/C
n8W7T79DK8ntAiAnbi9efqKy0DtOHSEwoJ88sK7AA/pnp7puJbsMhyG1WQIgDoNz
RD4AHbY9l8WHeSiISGbAO/AaCK6AR/izYUXUjkI=
-----END RSA PRIVATE KEY-----"""

    def testIdentityInitializationWithPublicKey(self):
        identity = Identity(givenKey=self.publicKey)
        self.assertEqual(identity.getId(), "a3436e524870d4bea0b9d36a83e9b0d937a88f8e92bd2e99d6d383beb5a67641")
        for plain in self.testVectors:
            _ = identity.encryptPublic(plain, DEFAULT_VALUE_ENCODING)

    def testIdentityInitializationWithPrivateKey(self):
        identity = Identity(givenKey=self.privateKey)
        self.assertEqual(identity.getId(), "a3436e524870d4bea0b9d36a83e9b0d937a88f8e92bd2e99d6d383beb5a67641")
        self.assertEqual(identity.getPublicKey(), self.publicKey)
        for plain in self.testVectors:
            encrypted = identity.encryptPublic(plain, DEFAULT_VALUE_ENCODING)
            decrypted = identity.decrypt(encrypted, DEFAULT_VALUE_ENCODING)
            assert plain == decrypted

    def testFileBasedInitialization(self):
        for _ in range(5):
            identity = Identity()
            for plain in self.testVectors:
                encrypted = identity.encryptPublic(plain, DEFAULT_VALUE_ENCODING)
                decrypted = identity.decrypt(encrypted, DEFAULT_VALUE_ENCODING)
                assert plain == decrypted

    def testFileBasedInitializationpartial(self):
        identityOriginal = Identity()
        identityPartialPublic = Identity(privateKeyFile=None, publicKeyFile=DEFAULT_PUBLIC_KEY)
        self.assertEqual(identityOriginal.getId(), identityPartialPublic.getId())
        identityPartialPrivate = Identity(privateKeyFile=DEFAULT_PRIVATE_KEY, publicKeyFile=None)
        self.assertEqual(identityOriginal.getId(), identityPartialPrivate.getId())
