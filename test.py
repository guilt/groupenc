from groupenc.identity import Identity

if __name__ == '__main__':
    print(Identity().encryptPublic("Hello, World!"))
    print(Identity().encryptPrivate("Hello, World!"))
