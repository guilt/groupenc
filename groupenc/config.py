import os

DEFAULT_KEY_BITS=4096
DEFAULT_GROUP_KEY_BITS = 128
DEFAULT_VAULT_FILE=os.getenv('GROUPENC_FILE', '.groupenc.json')
DEFAULT_PRIVATE_KEY=os.getenv('GROUPENC_PRIVATE_KEY', os.path.expanduser('~/.groupenc_private'))
DEFAULT_PUBLIC_KEY=os.getenv('GROUPENC_PUBLIC_KEY', os.path.expanduser('~/.groupenc_public'))
