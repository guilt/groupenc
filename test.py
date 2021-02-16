from groupenc.vault import Vault
from groupenc.identity import Identity

if __name__ == '__main__':
    vault = Vault()
    vault.addSecret("password", "Hello World!")
    vault.addSecret("password", "Not Hello World!")
    vault.addSecret("not a password", "Test!")
    vault.removeSecret("password")
    print(vault.getSecret("password"))
    print(vault.getSecret("not a password"))
    print(list(vault.listSecrets()))
    print(dict(vault.listKeys()))
    vault.save()

    publicKey = \
"""-----BEGIN PUBLIC KEY-----
MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgGi8MBivg6Hrh6bLDQM0dtjpfQ5j
uEU5vLYdDQ4nW744HTSjOK2JOhnEiYcigbArXNvr+sZcItbBGkJzpz4Ml/cpuERX
o/suYbiqrgonh7WFeR3L1Lek2uM7/LhIJM3gTSy9BWMBsaUeMZRFkX6+nAoBKSKw
x8SLLRZQ4193RKm5AgMBAAE=
-----END PUBLIC KEY-----
"""
    print(Identity(givenKey=publicKey).encryptPublic('Test Encryption!'))


