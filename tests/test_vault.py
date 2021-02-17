# -*- coding: utf-8 -*-
import unittest

from groupenc.vault import Vault

class TestVault(unittest.TestCase):
    publicKey = \
        """-----BEGIN PUBLIC KEY-----
        MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAIUMl904p2Ap6I2A067jo/JtxcHAQBMy
        7oveuoUKUcYeEGQCSa89KIFCW2QLB1PAtIzGLTXiOU7HqrIdGXhtHjkCAwEAAQ==
        -----END PUBLIC KEY-----"""

    vaultFile = '.test-groupenc.json'

    def testVaultBasic(self):
        vault = Vault(vaultFile=self.vaultFile)

        vault.addSecret("password", "Hello World!")
        self.assertEqual(vault.getSecret("password"), "Hello World!")

        vault.removeSecret("password")
        self.assertEqual(vault.getSecret("password"), None)

        vault.addSecret("not a password", "Test!")
        self.assertEqual(vault.getSecret("not a password"), "Test!")
        vault.save()

    def testVaultInduction(self):
        vault = Vault(vaultFile=self.vaultFile)
        vault.induct(self.publicKey)
        vault.addSecret("unicodepassword", u"😘🤩")
        vault.save()

    def testVaultDisown(self):
        vault = Vault(vaultFile=self.vaultFile)
        vault.disown(self.publicKey)
        vault.save()

    def testVaultRotate(self):
        vault = Vault(vaultFile=self.vaultFile)
        vault.getSecret("unicodepassword")
        vault.addSecret("unicodepassword", u"😘🤩")
        vault.save()
        vault.rotate()
        self.assertEqual(vault.getSecret("unicodepassword"), u"😘🤩")
        vault.save()
