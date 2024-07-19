"""
Add, modify or delete client authentication.

Copyright 2017-2020 ICTU
Copyright 2017-2022 Leiden University
Copyright 2017-2023 Leon Helwerda

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from argparse import ArgumentParser, Namespace
from configparser import RawConfigParser
from getpass import getpass
from hashlib import md5
import keyring

def md5_hex(nonce: str) -> str:
    """
    Encode as MD5.
    """

    return md5(nonce.encode('ISO-8859-1')).hexdigest()

def ha1_nonce(username: str, realm: str, password: str) -> str:
    """
    Create an encoded variant for the user's password in the realm.
    """

    return md5_hex(f'{username}:{realm}:{password}')

def parse_args(config: RawConfigParser) -> Namespace:
    """
    Parse command line arguments.
    """

    parser = ArgumentParser(description='Modify client authentication')
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

def get_password(args: Namespace, hashed: bool = True,
                 prompt: str = 'New password: ') -> str:
    """
    Retrieve the password to be set.
    """

    if hashed:
        if args.password is not None:
            return ha1_nonce(args.user, args.realm, args.password)

        return ha1_nonce(args.user, args.realm, getpass(prompt))

    return str(args.password) if args.password is not None else getpass(prompt)

def main() -> None:
    """
    Main entry point.
    """

    config = RawConfigParser()
    config.read('upload.cfg')
    args = parse_args(config)

    if args.secret:
        keyring.set_password(f'{args.keyring}-secret', 'server',
                             get_password(args, hashed=False, prompt='Secret key: '))
    elif args.private:
        keyring.set_password(f'{args.keyring}-secret', 'privkey',
                             get_password(args, hashed=False, prompt='Passphrase: '))
    else:
        exists = keyring.get_password(args.keyring, args.user)
        if args.delete:
            if exists:
                raise KeyError(f'User {args.user} already exists')

            keyring.delete_password(args.realm, args.user)
        elif args.add:
            password = get_password(args)
            if exists:
                raise KeyError(f'User {args.user} already exists')

            keyring.set_password(args.keyring, args.user, password)
        elif args.modify:
            password = get_password(args)
            if not exists:
                raise KeyError(f'User {args.user} does not exist')

            keyring.set_password(args.keyring, args.user, password)

if __name__ == "__main__":
    main()
