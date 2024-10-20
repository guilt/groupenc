import os

def __getEnvNumber(varName, defaultValue):
    try:
        return int(os.getenv(varName, str(defaultValue)))
    except:
        return int(defaultValue)

DEFAULT_KEY_BITS = __getEnvNumber('GROUPENC_KEY_BITS', 8192)
DEFAULT_KEY_BYTES = DEFAULT_KEY_BITS // 8
DEFAULT_GROUP_KEY_BITS = __getEnvNumber('GROUPENC_GROUP_KEY_BITS', 256)
DEFAULT_GROUP_KEY_BYTES = DEFAULT_GROUP_KEY_BITS // 8
DEFAULT_IV_BITS = __getEnvNumber('GROUPENC_IV_BITS', DEFAULT_GROUP_KEY_BITS)
DEFAULT_IV_BYTES = DEFAULT_IV_BITS // 8
DEFAULT_PAD_BITS = __getEnvNumber('GROUPENC_PAD_BITS', DEFAULT_GROUP_KEY_BITS)
DEFAULT_PAD_BYTES = DEFAULT_PAD_BITS // 8

DEFAULT_KEY_ENCODING = os.getenv('GROUPENC_KEY_ENCODING', 'latin1')
DEFAULT_VALUE_ENCODING = os.getenv('GROUPENC_VALUE_ENCODING', 'utf8')

DEFAULT_VAULT_FILE = os.getenv('GROUPENC_FILE', '.groupenc.json')
DEFAULT_PRIVATE_KEY = os.getenv('GROUPENC_PRIVATE_KEY', os.path.expanduser('~/.groupenc_private'))
DEFAULT_PUBLIC_KEY = os.getenv('GROUPENC_PUBLIC_KEY', os.path.expanduser('~/.groupenc_public'))
HASH_SECRETS = os.getenv('GROUPENC_HASH_SECRETS')
