#!/usr/bin/env python
# pylint: disable=W0107
from __future__ import print_function

import argparse
import os
import sys

from .config import DEFAULT_PUBLIC_KEY, DEFAULT_PRIVATE_KEY, DEFAULT_VAULT_FILE
from .identity import Identity
from .vault import Vault

try:
    import colorama

    colorama.init()
    OUTPUT_COLOR = 'auto'
except ImportError:
    OUTPUT_COLOR = 'never'

S_RED = '\033[31m'
S_BLUE = '\033[34m'
S_GREEN = '\033[32m'
S_CYAN = '\033[36m'
S_MAGENTA = '\033[35m'
S_YELLOW = '\033[33m'
S_WHITE = '\033[37m'
S_RESET = '\033[0m'


def _coloredPrint(message, color, file_=sys.stdout):
    output_color = False
    if OUTPUT_COLOR == 'never':
        pass
    elif OUTPUT_COLOR == 'auto':
        output_color = file_.isatty()
    elif OUTPUT_COLOR == 'always':
        output_color = True
    if output_color:
        return '{}{}{}'.format(color, message, S_RESET)
    return message


def _printMessage(message, color=S_WHITE, file_=sys.stdout):
    print(_coloredPrint(message, color, file_=file_), file=file_)


def _debugMessage(message, file_=sys.stderr):
    if os.getenv('DEBUG'):
        print(_coloredPrint(message, color=S_YELLOW, file_=file_), file=file_)


def _printSuccess(message, file_=sys.stdout):
    print(_coloredPrint(message, S_GREEN, file_=file_), file=file_)


def _printError(message, file_=sys.stderr):
    print(_coloredPrint(message, S_RED, file_=file_), file=file_)


def _valueOrContentsOf(value):
    if value and value.startswith("@"):
        valueFile = value.lstrip("@")
        if os.path.exists(valueFile):
            with open(valueFile, "rb") as valueStream:
                value = valueStream.read()
    return value


def _commandBootstrap(args):
    """
    Bootstrap
    :param args: System Arguments Passed
    """
    vaultFile = args.vault_file
    privateKeyFile = args.private_key_file
    publicKeyFile = args.public_key_file

    _debugMessage('Bootstrapping Identity, this will take some time ...')
    identity = Identity(privateKeyFile, publicKeyFile)
    _debugMessage('Opening or Bootstrapping Vault ...')
    _ = Vault(identity=identity, vaultFile=vaultFile)

    _printSuccess('Vault Ready.')


def _commandId(args):
    """
    Show Identity
    :param args: System Arguments Passed
    """
    vaultFile = args.vault_file
    privateKeyFile = args.private_key_file
    publicKeyFile = args.public_key_file

    _debugMessage('Bootstrapping Identity, this will take some time ...')
    identity = Identity(privateKeyFile, publicKeyFile)
    _debugMessage('Opening or Bootstrapping Vault ...')
    vault = Vault(identity=identity, vaultFile=vaultFile)

    _debugMessage('Listing Identity ...')
    _printMessage(vault.identity.getPublicKey())


def _commandSecretAdd(args):
    """
    Add a Secret
    :param args: System Arguments Passed
    """
    vaultFile = args.vault_file
    privateKeyFile = args.private_key_file
    publicKeyFile = args.public_key_file

    _debugMessage('Bootstrapping Identity, this will take some time ...')
    identity = Identity(privateKeyFile, publicKeyFile)
    _debugMessage('Opening or Bootstrapping Vault ...')
    vault = Vault(identity=identity, vaultFile=vaultFile)

    secretKey = args.key
    secretValue = _valueOrContentsOf(args.value)
    _debugMessage('Adding Secret {} ...'.format(secretKey))
    vault.addSecret(secretKey, secretValue)
    _debugMessage('Saving Vault ...')
    vault.save()
    _debugMessage('Vault Saved.')

    _printSuccess('Key Added.')

def _commandSecretRemove(args):
    """
    Remove a Secret
    :param args: System Arguments Passed
    """
    vaultFile = args.vault_file
    privateKeyFile = args.private_key_file
    publicKeyFile = args.public_key_file

    _debugMessage('Bootstrapping Identity, this will take some time ...')
    identity = Identity(privateKeyFile, publicKeyFile)
    _debugMessage('Opening or Bootstrapping Vault ...')
    vault = Vault(identity=identity, vaultFile=vaultFile)

    secretKey = args.key
    _debugMessage('Removing Secret {} ...'.format(secretKey))
    vault.removeSecret(secretKey)
    _debugMessage('Saving Vault ...')
    vault.save()
    _debugMessage('Vault Saved.')

    _printSuccess('Key Removed.')

def _commandSecretList(args):
    """
    List Secrets
    :param args: System Arguments Passed
    """
    vaultFile = args.vault_file
    privateKeyFile = args.private_key_file
    publicKeyFile = args.public_key_file

    _debugMessage('Bootstrapping Identity, this will take some time ...')
    identity = Identity(privateKeyFile, publicKeyFile)
    _debugMessage('Opening or Bootstrapping Vault ...')
    vault = Vault(identity=identity, vaultFile=vaultFile)

    _debugMessage('Listing Secrets ...')
    for secretKey in vault.listSecrets():
        _printMessage(secretKey)

def _commandSecretShow(args):
    """
    Show a Secret
    :param args: System Arguments Passed
    """
    vaultFile = args.vault_file
    privateKeyFile = args.private_key_file
    publicKeyFile = args.public_key_file

    _debugMessage('Bootstrapping Identity, this will take some time ...')
    identity = Identity(privateKeyFile, publicKeyFile)
    _debugMessage('Opening or Bootstrapping Vault ...')
    vault = Vault(identity=identity, vaultFile=vaultFile)

    secretKey = args.key
    _debugMessage('Displaying Secret {} ...'.format(secretKey))
    secretValue = vault.getSecret(secretKey)
    if secretValue:
        _printMessage(secretValue)

def _commandInduct(args):
    """
    Induct a User
    :param args: System Arguments Passed
    """
    vaultFile = args.vault_file
    privateKeyFile = args.private_key_file
    publicKeyFile = args.public_key_file

    _debugMessage('Bootstrapping Identity, this will take some time ...')
    identity = Identity(privateKeyFile, publicKeyFile)
    _debugMessage('Opening or Bootstrapping Vault ...')
    vault = Vault(identity=identity, vaultFile=vaultFile)

    identityNew = _valueOrContentsOf(args.identity)
    _debugMessage('Inducting Identity ...')
    vault.induct(identityNew)
    _debugMessage('Saving Vault ...')
    vault.save()
    _debugMessage('Vault Saved.')

    _printSuccess('Inducted.')

def _commandDisown(args):
    """
    Disown a User
    :param args: System Arguments Passed
    """
    vaultFile = args.vault_file
    privateKeyFile = args.private_key_file
    publicKeyFile = args.public_key_file

    _debugMessage('Bootstrapping Identity, this will take some time ...')
    identity = Identity(privateKeyFile, publicKeyFile)
    _debugMessage('Opening or Bootstrapping Vault ...')
    vault = Vault(identity=identity, vaultFile=vaultFile)

    identityToDisown = _valueOrContentsOf(args.identity)
    confirm = args.confirm
    _debugMessage('Disowning Identity ...')
    assert (identityToDisown or confirm), 'Must Confirm when Removing Self'
    vault.disown(identityToDisown)
    _debugMessage('Saving Vault ...')
    vault.save()
    _debugMessage('Vault Saved.')

    _printSuccess('Disowned.')

def _commandRotate(args):
    """
    Rotate Keys in Vault
    :param args: System Arguments Passed
    """
    vaultFile = args.vault_file
    privateKeyFile = args.private_key_file
    publicKeyFile = args.public_key_file

    _debugMessage('Bootstrapping Identity, this will take some time ...')
    identity = Identity(privateKeyFile, publicKeyFile)
    _debugMessage('Opening or Bootstrapping Vault ...')
    vault = Vault(identity=identity, vaultFile=vaultFile)

    _debugMessage('Rotating Vault ...')
    vault.rotate()
    _debugMessage('Saving Vault ...')
    vault.save()
    _debugMessage('Vault Saved.')

    _printSuccess('Rotated.')

def main():
    """Main Program."""
    parser = argparse.ArgumentParser('groupenc', description='groupenc: Group Encryption CLI in Python.')
    parser.add_argument('--vault-file', type=str, default=DEFAULT_VAULT_FILE, help='Vault File')
    parser.add_argument('--private-key-file', type=str, default=DEFAULT_PRIVATE_KEY, help='Private Key File')
    parser.add_argument('--public-key-file', type=str, default=DEFAULT_PUBLIC_KEY, help='Public Key File')

    subparsers = parser.add_subparsers()

    parserBootstrap = subparsers.add_parser('bootstrap', help='Bootstrap')
    parserBootstrap.set_defaults(func=_commandBootstrap)

    parserId = subparsers.add_parser('id', help='Show Identity')
    parserId.set_defaults(func=_commandId)

    parserSecret = subparsers.add_parser('secret', help='Manage Secrets')
    subparserSecret = parserSecret.add_subparsers()

    parserSecretAdd = subparserSecret.add_parser('add', help='Add a Secret')
    parserSecretAdd.add_argument('key', type=str, help='Key to Add')
    parserSecretAdd.add_argument('value', type=str, help='Value to Add')
    parserSecretAdd.set_defaults(func=_commandSecretAdd)

    parserSecretRemove = subparserSecret.add_parser('remove', help='Remove a Secret')
    parserSecretRemove.add_argument('key', type=str, help='Key to Remove')
    parserSecretRemove.set_defaults(func=_commandSecretRemove)

    parserSecretList = subparserSecret.add_parser('list', help='List Secrets')
    parserSecretList.set_defaults(func=_commandSecretList)

    parserSecretShow = subparserSecret.add_parser('show', help='Show a Secret')
    parserSecretShow.add_argument('key', type=str, help='Key to Show')
    parserSecretShow.set_defaults(func=_commandSecretShow)

    parserInduct = subparsers.add_parser('induct', help='Induct a User')
    parserInduct.add_argument('identity', type=str, help='Public Key Value or File to Induct.')
    parserInduct.set_defaults(func=_commandInduct)

    parserDisown = subparsers.add_parser('disown', help='Disown a User')
    parserDisown.add_argument('--identity', type=str, help='Public Key Value or File to Disown. If none, Remove self.')
    parserDisown.add_argument('--confirm', type=str, help='Confirm when Removing Self.')
    parserDisown.set_defaults(func=_commandDisown)

    parserRotate = subparsers.add_parser('rotate', help='Rotate Keys in Vault')
    parserRotate.set_defaults(func=_commandRotate)

    args = parser.parse_args()
    try:
        func = args.func
    except AttributeError:
        func = None
        _printMessage(parser.format_help())
    try:
        if func:
            func(args)
    except Exception as exc:
        errorMessage = str(exc) or 'Exception Occured'
        _printError(errorMessage)

if __name__ == '__main__':
    main()
