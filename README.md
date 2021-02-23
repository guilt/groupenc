# groupenc: Group Encryption Utilities

Group Encryption utilities in Python, with a CLI.

# Installation

```bash
pip install groupenc
```

# Usage

## Bootstrap

To Bootstrap a vault, use:

```bash
groupenc bootstrap
```

It would typically create a file called `.groupenc.json` and a private key
/public key pair in `~/.groupenc_private` and `~/.groupenc_public`.

You can share your own identity with other people, so they
can induct you later:

```bash
groupenc id
```

It typically displays your public key.

## Secrets

To add a secret, use:

```bash
groupenc secret add --key password --value changeMe
```

To add a secret from a file, use:

```bash
groupenc secret add --key id_rsa_server --value @~/.ssh/id_rsa
```

To list secrets, use:

```bash
groupenc secret list
password
id_rsa_server
```

To display a secret, use:

```bash
groupenc secret show --key password
changeMe
```

To remove a secret, use:

```
groupenc secret remove --key password
```

## Induction

When you add someone else to the vault file, this process allows them to view secrets. To do that, an existing user
inducts them into the system.

```bash
groupenc induct --identity @~/other_id_rsa.pub
```

and then you transmit the new file across. They should be able to decode and view the secrets.

## Rotation

Sometimes, it is a good practice to rotate the encryption keys so people can't view updated secrets.

```bash
groupenc rotate
```

## Remove

When you want to remove people from a group, you simply remove them with a known public key, then rotate:

```
groupenc disown --identity @~/other_id_rsa.pub
groupenc rotate
```

Note that the secrets that they already have access to cannot be unshared/forgotten, so you should manually revoke their
accesses from any services. It is a good practice to share multiple vault files and induct people based on their actual
role/need to access.


## Running Unit Tests

```bash
pip install tox
tox
```

## Call for Testing Volunteers

The code was tested on Python 2.7, 3.8.

Please volunteer to test it and send in your patches (or) bug reports.
Design feedback always welcome.