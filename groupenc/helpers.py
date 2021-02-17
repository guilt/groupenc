import base64

from .config import DEFAULT_VALUE_ENCODING, DEFAULT_KEY_ENCODING


def makeBytesOf(payload, encoding=DEFAULT_VALUE_ENCODING):
    if not isinstance(payload, (bytes, bytearray)):
        payload = payload.encode(encoding)
    return payload


def makeStringOf(payload, encoding=DEFAULT_VALUE_ENCODING):
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.decode(encoding)
    return payload


def encodeToBase64(payload, encoding=DEFAULT_KEY_ENCODING):
    return makeStringOf(base64.b64encode(payload), encoding)


def decodeFromBase64(payload, encoding=DEFAULT_KEY_ENCODING):
    return makeBytesOf(base64.b64decode(payload), encoding)
