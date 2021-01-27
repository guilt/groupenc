from groupenc.vault import Vault

if __name__ == '__main__':
    vault=Vault()
    vault.addSecret("password", "Hello World!")
    vault.addSecret("password", "Not Hello World!")
    vault.addSecret("not a password", "Test!")
    vault.removeSecret("password")
    print(vault.getSecret("password"))
    print(vault.getSecret("not a password"))
    vault.save()