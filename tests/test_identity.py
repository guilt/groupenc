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

    privateKey = \
"""-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

    def testIdentityInitializationWithPublicKey(self):
        identity = Identity(givenKey=self.publicKey)
        self.assertEqual(identity.getId(), "6b9288c93c3055dd828c201f5139c995a36a9866b0d8b522d040a248dc78a570")
        for plain in self.testVectors:
            _ = identity.encryptPublic(plain, DEFAULT_VALUE_ENCODING)

    def testIdentityInitializationWithPrivateKey(self):
        identity = Identity(givenKey=self.privateKey)
        self.assertEqual(identity.getId(), "6b9288c93c3055dd828c201f5139c995a36a9866b0d8b522d040a248dc78a570")
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
