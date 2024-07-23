"""
Subcommand to add, modify or delete client authentication.

Copyright 2017-2020 ICTU
Copyright 2017-2022 Leiden University
Copyright 2017-2024 Leon Helwerda

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
import keyring
from .hash import ha1_nonce

def add_args(parser: ArgumentParser, config: RawConfigParser) -> None:
    """
    Add command line arguments to an argument parser.
    """

    options = parser.add_mutually_exclusive_group(required=True)
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

def handle_command(args: Namespace) -> None:
    """
    Perform a modification to the authentication keyring.
    """

    domain = str(args.keyring)
    if args.secret:
        keyring.set_password(f'{domain}-secret', 'server',
                             get_password(args, hashed=False,
                                          prompt='Secret key: '))
    elif args.private:
        keyring.set_password(f'{domain}-secret', 'privkey',
                             get_password(args, hashed=False,
                                          prompt='Passphrase: '))
    else:
        user = str(args.user)
        exists = keyring.get_password(domain, user)
        if args.add == bool(exists):
            raise KeyError(f'"{user}" {"must" if exists else "does"} not exist')

        if args.delete:
            keyring.delete_password(domain, user)
        else:
            # Add or modify (after existence check)
            password = get_password(args)
            keyring.set_password(domain, user, password)
