import base64

def makeBytesOf(payload):
    if not isinstance(payload, (bytes, bytearray)):
        payload = payload.encode('latin1')
    return payload


def makeStringOf(payload):
    if isinstance(payload, (bytes, bytearray)):
        try:
            payload = payload.decode()
        except:
            payload = payload.decode('latin1')
    return payload

def encodeToBase64(payload):
    return makeStringOf(base64.b64encode(payload))

def decodeFromBase64(payload):
    return makeBytesOf(base64.b64decode(payload))