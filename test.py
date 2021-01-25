from groupenc.identity import initializeOrGetKeyPair

if __name__ == '__main__':

    kp = initializeOrGetKeyPair()
    print(kp.publickey())