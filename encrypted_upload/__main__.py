"""
Entry point for the encrypted upload server and associated subcommands.

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
from functools import partial
from . import auth, bootstrap

def parse_args(config: RawConfigParser) -> Namespace:
    """
    Parse command line arguments for subcommands.
    """

    parser = ArgumentParser(description='Encrypted upload server and tools')
    subparsers = parser.add_subparsers(title='Subcommands',
                                       description='Server and related tools',
                                       help='Select server or tool to run',
                                       required=True)

    server = subparsers.add_parser('server',
                                   description='Run upload listener server',
                                   help='Run upload listener')
    bootstrap.add_args(server, config)
    server.set_defaults(callback=partial(bootstrap.bootstrap, config))

    modify = subparsers.add_parser('auth',
                                   description='Modify keyring credentials',
                                   help='Add, edit or remove authentication')
    auth.add_args(modify, config)
    modify.set_defaults(callback=auth.handle_command)

    return parser.parse_args()

def main() -> None:
    """
    Main entry point.
    """

    config = RawConfigParser()
    config.read('upload.cfg')
    args = parse_args(config)
    if not callable(args.callback):
        raise KeyError('No valid callback specified for subcommand')

    args.callback(args)

if __name__ == '__main__':
    main()
