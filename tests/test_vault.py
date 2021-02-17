# -*- coding: utf-8 -*-
import unittest

from groupenc.vault import Vault

class TestVault(unittest.TestCase):
    publicKey = \
        """-----BEGIN PUBLIC KEY-----
        MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIUMl904p2Ap6I2A067jo/JtxcHAQBMy
        7oveuoUKUcYeEGQCSa89KIFCW2QLB1PAtIzGLTXiOU7HqrIdGXhtHjkCAwEAAQ==
        -----END PUBLIC KEY-----"""

    def testFileBasedInitialization(self):
        for _ in range(5):
            _ = Vault()

    def testVaultCreation(self):
        vault = Vault()
        vault.addSecret("password", "Hello World!")
        vault.addSecret("password", "Not Hello World!")
        vault.addSecret("not a password", "Test!")
        vault.removeSecret("password")
        print(vault.getSecret("password"))
        print(vault.getSecret("not a password"))
        print(list(vault.listSecrets()))
        print(dict(vault.listKeys()))
        vault.induct(self.publicKey)
        vault.save()
