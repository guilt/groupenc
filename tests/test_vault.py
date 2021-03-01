# -*- coding: utf-8 -*-
import unittest

from groupenc.vault import Vault

class TestVault(unittest.TestCase):
    publicKey = \
        """-----BEGIN PUBLIC KEY-----
MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAw3CwioITi1EILpngP09o
ZTpx0d9kSTYzYrkxayDy/g1EQCYk1tGfzLvrNoZkdWzzf1YyjIDs7nBj1+sgtvjL
Pc2160PI7UAPUsdYJDQagVbO+WR48QFZoCYvC3qlJhCc8UvILju+LrruKv69Kd5i
OFDpwQNs426UQBflsT74+4ofl1xQr2wZAldYJt1Gdl6O+DWBh9KgNHEOWgstA0M+
tuQetAANgHO/zEERU/TstOY7VMhhZsBm5h9qmWfKE6cees8PnLITrxEwFyQBNk+W
refLGykTeYif9LVQb/z3aCDxltQYdaj3yxU7DlQ61rYqUb9K7C5FsrqmqdP7ahsf
TjRs1VsrLftolbUy170MJ7KyHQikvDn9/kFXPQahprmTcLVdDingV+k/F8h6qids
h7D/KvgoE0xw79Dx6rijTIsceRi3Mh5sfSwg5Tgk/dK32b08fRhiUgNz41+RvuH8
CDnpNAW64vfLpj+4EsyY+TsI1G1iK7/h8WUYSOOCZi9V53xwKLfMkxa8zkWq3HTy
e6sx/ffWh+xzqbDoxYD5FZ2NQcBuDBx4V/M89nOzTPVKZXf7HIyRaz9w8X60K3AD
BiVh98iLT71wLSsnWyqAnKruOTGDj0LOOoB+wE4eHEHq66Iem8zCG6+nfPT9EGCq
9ryZu74Tk6oREVcw+2HlGll8dL5KgAwhBaBul6htPBTaubNf6AJi0EP06K5O00CX
riOyOJwPQZx3ha/jjxSOvPl8mhX0JXkAAKgq/JcItIvDni0/vt8DqmcFCGs3+wa8
FnWzz+/c2EojHhroBsrbyaA17D6uSwxCa94D7/h6r8BUgU4kxLmsiCSIQ+t1RG+/
uRxl+wwbTScQ3498jFB8t9h5+JAHHNi8YpWCd8ls1Y/MA8Wba/TNNAxAMNYWUjBs
HNGDIZgBXjsrrQ1cby9IbUNqod/i3v2iyih6gOrkpVIwcihDIKJgnhisXZKZc0uV
EfMyAUvzeWE1dOY/Kg04jYc/WZ30S47T3hwqszQto7UsAQlMTLI/NBBXZaEa7QaA
mgY1QRC3CUyktf4TdpAyHLd58bfGXK0P5TWysi7bxiV1O9Hpp4jjHYssFR0/L0db
Y+kmHLl54hwpqArWK2vH0FRQlVEeBVK1jJSuHiHDOB/PcWehV6A3hCTaxlhY3XrZ
8R0oAah3nAYIWXAwK9pt7N24pBENSymG0LNw6n+6UhHHF5UyqOS8gmV3fvxhgUmt
jtD5usocpldtnLjqZeIlWU3yaD1ScBRL9bL9lUGyHn95nK04DNU2g+0FFoikYeEM
9kccPXwrLbUaDGhuKzG3xYLcHA4u6KjBoL6E9eLmpxy3cKDurXEvD5h2aqv7X75S
sQIDAQAB
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
