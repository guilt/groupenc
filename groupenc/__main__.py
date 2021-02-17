#!/usr/bin/env python
#pylint: disable=W0107
import argparse

from .config import DEFAULT_PUBLIC_KEY, DEFAULT_PRIVATE_KEY, DEFAULT_VAULT_FILE

def commandBootstrap(args):
    """
    Bootstrap
    :param args: System Arguments Passed
    """
    pass

def commandSecretAdd(args):
    """
    Add a Secret
    :param args: System Arguments Passed
    """
    pass

def commandSecretRemove(args):
    """
    Remove a Secret
    :param args: System Arguments Passed
    """
    pass

def commandSecretList(args):
    """
    List Secrets
    :param args: System Arguments Passed
    """
    pass

def commandSecretShow(args):
    """
    Show a Secret
    :param args: System Arguments Passed
    """
    pass

def commandInduct(args):
    """
    Induct a User
    :param args: System Arguments Passed
    """
    pass

def commandDisown(args):
    """
    Disown a User
    :param args: System Arguments Passed
    """
    pass

def commandRotate(args):
    """
    Rotate Keys in Vault
    :param args: System Arguments Passed
    """
    pass

def main():
    """Main Program."""
    parser = argparse.ArgumentParser('groupenc', description='groupenc: Group Encryption CLI in Python.')
    parser.add_argument('--vault-file', type=str, default=DEFAULT_VAULT_FILE, help='Vault File')
    parser.add_argument('--private-key-file', type=str, default=DEFAULT_PRIVATE_KEY, help='Private Key File')
    parser.add_argument('--public-key-file', type=str, default=DEFAULT_PUBLIC_KEY, help='Public Key File')

    subparsers = parser.add_subparsers()

    parser_bootstrap = subparsers.add_parser('bootstrap', help='Bootstrap')
    parser_bootstrap.set_defaults(func=commandBootstrap)

    parser_secret = subparsers.add_parser('secret', help='Manage Secrets')
    subparsers_parser_secret = parser_secret.add_subparsers()

    parser_secret_add = subparsers_parser_secret.add_parser('add', help='Add a Secret')
    parser_secret_add.add_argument('key', type=str, help='Key to Add')
    parser_secret_add.add_argument('value', type=str, help='Value to Add')
    parser_secret_add.set_defaults(func=commandSecretAdd)

    parser_secret_remove = subparsers_parser_secret.add_parser('remove', help='Remove a Secret')
    parser_secret_remove.add_argument('key', type=str, help='Key to Remove')
    parser_secret_add.set_defaults(func=commandSecretRemove)

    parser_secret_list = subparsers_parser_secret.add_parser('list', help='List Secrets')
    parser_secret_list.set_defaults(func=commandSecretList)

    parser_secret_show = subparsers_parser_secret.add_parser('show', help='Show a Secret')
    parser_secret_show.add_argument('key', type=str, help='Key to Show')
    parser_secret_add.set_defaults(func=commandSecretShow)

    parser_induct = subparsers.add_parser('induct', help='Induct a User')
    parser_induct.add_argument('--identity', type=str, help='Public Key or Public Key File to Induct')
    parser_induct.set_defaults(func=commandInduct)

    parser_induct = subparsers.add_parser('disown', help='Disown a User')
    parser_induct.add_argument('--identity', type=str, help='Public Key or Public Key File to Disown')
    parser_induct.set_defaults(func=commandDisown)

    parser_induct = subparsers.add_parser('rotate', help='Rotate Keys in Vault')
    parser_induct.set_defaults(func=commandRotate)

    args = parser.parse_args()
    try:
        func = args.func
    except AttributeError:
        func = None
        print(parser.format_help())
    try:
        if func:
            func(args)
    except Exception as exc:
        errorMessage = str(exc) or 'Exception Occured'
        print(errorMessage)

if __name__ == '__main__':
    main()
