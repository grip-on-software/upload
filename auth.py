"""
Add, modify or delete client authentication.
"""

import argparse
import configparser
from getpass import getpass
from hashlib import md5
import keyring

def md5_hex(nonce):
    """
    Encode as MD5.
    """

    return md5(nonce.encode('ISO-8859-1')).hexdigest()

def ha1_nonce(username, realm, password):
    """
    Create an encoded variant for the user's password in the realm.
    """

    return md5_hex('%s:%s:%s' % (username, realm, password))

def parse_args(config):
    """
    Parse command line arguments.
    """

    parser = argparse.ArgumentParser(description='Modify client authentication')
    options = parser.add_mutually_exclusive_group()
    options.add_argument('--add', action='store_true', help='Add new user')
    options.add_argument('--modify', action='store_true', help='Alter user')
    options.add_argument('--delete', action='store_true', help='Remove user')
    options.add_argument('--secret', action='store_true',
                         help='Set server secret digest authentication value')
    options.add_argument('--private', action='store_true',
                         help='Set server private key passphrase')

    parser.add_argument('--keyring', default=config.get('server', 'keyring'),
                        help='Name of keyring containg authentication')
    parser.add_argument('--realm', default=config.get('server', 'realm'),
                        help='Name of authentication realm')
    parser.add_argument('--user', help='Username to modify')
    parser.add_argument('--password', help='New password or secret to set')

    return parser.parse_args()

def get_password(args, hashed=True, prompt='New password: '):
    """
    Retrieve the password to be set.
    """

    if hashed:
        if args.password is not None:
            return ha1_nonce(args.user, args.realm, args.password)

        return ha1_nonce(args.user, args.realm, getpass(prompt))

    return args.password if args.password is not None else getpass(prompt)

def main():
    """
    Main entry point.
    """

    config = configparser.RawConfigParser()
    config.read('upload.cfg')
    args = parse_args(config)

    if args.secret:
        keyring.set_password(args.keyring + '-secret', 'server',
                             get_password(args, hashed=False, prompt='Secret key: '))
    elif args.private:
        keyring.set_password(args.keyring + '-secret', 'privkey',
                             get_password(args, hashed=False, prompt='Passphrase: '))
    else:
        exists = keyring.get_password(args.keyring, args.user)
        if args.delete:
            if exists:
                raise KeyError('User {} already exists'.format(args.user))

            keyring.delete_password(args.realm, args.user)
        elif args.add:
            password = get_password(args)
            if exists:
                raise KeyError('User {} already exists'.format(args.user))

            keyring.set_password(args.keyring, args.user, password)
        elif args.modify:
            password = get_password(args)
            if not exists:
                raise KeyError('User {} does not exist'.format(args.user))

            keyring.set_password(args.keyring, args.user, password)

if __name__ == "__main__":
    main()
