"""
Module for bootstrapping the encrypted upload server.

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
from pathlib import Path
from typing import Callable
import cherrypy
import keyring
from . import __version__ as VERSION
from .application import Upload
from .hash import ha1_nonce

def get_ha1_keyring(name: str) -> Callable[[str, str], str]:
    """
    Retrieve a function that provides an encoded variable containing the
    username, realm and password for digest authentication. The `name` is
    the keyring collection name.
    """

    def get_ha1(_: str, username: str) -> str:
        """
        Retrieve the HA1 variable for a username from the keyring.
        """

        return str(keyring.get_password(name, username))

    return get_ha1

def add_args(parser: ArgumentParser, config: RawConfigParser) -> None:
    """
    Add command line arguments for the server to an argument parser.
    """

    work_dir = Path.cwd()
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Output traces on web')
    parser.add_argument('--listen', default=None,
                        help='Bind address (default: 0.0.0.0, 127.0.0.1 in debug)')
    parser.add_argument('--port', default=9090, type=int,
                        help='Port to listen to (default: 9090)')
    parser.add_argument('--log-path', dest='log_path', default=str(work_dir),
                        help='Path to store logs at in production')
    parser.add_argument('--daemonize', action='store_true', default=False,
                        help='Run the server as a daemon')
    parser.add_argument('--pidfile', help='Store process ID in file')

    parser.add_argument('--engine', default=config['server']['engine'],
                        help='GPG engine path')
    parser.add_argument('--upload-path', dest='upload_path',
                        default=str(work_dir / 'upload'),
                        help='Upload path')
    parser.add_argument('--accepted-files', dest='accepted_files', nargs='*',
                        default=config['server']['files'].split(' '),
                        type=set, help='List of filenames allowed for upload')
    parser.add_argument('--database', default=config['import']['database'],
                        help='Database host to import dumps into')
    parser.add_argument('--import-dump', default=config['import']['dump'],
                        dest='import_dump', help='File to import to a database')
    parser.add_argument('--import-path', default=config['import']['path'],
                        dest='import_path', help='Path to the MonetDB importer')
    parser.add_argument('--import-script', default=config['import']['script'],
                        dest='import_script', help='Path to the import script')
    parser.add_argument('--key', default=config['server']['key'],
                        help='Fingerprint of server key pair')
    parser.add_argument('--keyring', default=config['server']['keyring'],
                        help='Name of keyring containing authentication')
    parser.add_argument('--realm', default=config['server']['realm'],
                        help='Name of Digest authentication realm')
    parser.add_argument('--accepted-keys', dest='accepted_keys', nargs='*',
                        default=set(config['client'].values()),
                        type=set, help='List of accepted names for public keys')
    parser.add_argument('--loopback', action='store_true',
                        help='Use loopback pinhole to read passphrase from keyring')

    server = parser.add_mutually_exclusive_group()
    server.add_argument('--fastcgi', action='store_true', default=False,
                        help='Start a FastCGI server instead of HTTP')
    server.add_argument('--scgi', action='store_true', default=False,
                        help='Start a SCGI server instead of HTTP')
    server.add_argument('--cgi', action='store_true', default=False,
                        help='Start a CGI server instead of HTTP')

def bootstrap(config: RawConfigParser, args: Namespace) -> None:
    """
    Set up the upload server.
    """

    if args.listen is not None:
        bind_address = str(args.listen)
    elif args.debug:
        bind_address = '127.0.0.1'
    else:
        bind_address = '0.0.0.0'

    auth_key = config['server'].get('secret', '')
    auth = dict((str(key), str(value)) for key, value in config['auth'].items())
    symm = dict((str(key), str(value)) for key, value in config['symm'].items())
    if args.keyring:
        keyring_name = str(args.keyring)
        auth_keyring = keyring.get_password(f'{keyring_name}-secret', 'server')
        if auth_keyring is not None:
            auth_key = auth_keyring
        elif auth_key != '':
            keyring.set_password(f'{keyring_name}-secret', 'server', auth_key)
        else:
            raise ValueError('No server secret auth key provided')

        for user, password in auth.items():
            keyring.set_password(keyring_name, user,
                                 ha1_nonce(user, args.realm, password))
        for user, passphrase in symm.items():
            keyring.set_password(f'{keyring_name}-symmetric', user, passphrase)

        ha1 = get_ha1_keyring(keyring_name)
    else:
        ha1 = cherrypy.lib.auth_digest.get_ha1_dict_plain(auth)

    if args.debug:
        server = f'gros-upload/{VERSION} CherryPy/{cherrypy.__version__}'
    else:
        server = 'gros-upload CherryPy'

    conf = {
        'global': {
        },
        '/': {
            'error_page.default': Upload.json_error,
            'response.headers.server': server,
            'tools.auth_digest.on': True,
            'tools.auth_digest.realm': str(args.realm),
            'tools.auth_digest.get_ha1': ha1,
            'tools.auth_digest.key': str(auth_key)
        }
    }
    log_path = Path(args.log_path)
    cherrypy.config.update({
        'server.max_request_body_size': 1000 * 1024 * 1024,
        'server.socket_host': bind_address,
        'server.socket_port': args.port,
        'request.show_tracebacks': args.debug,
        'log.screen': args.debug,
        'log.access_file': '' if args.debug else str(log_path / 'access.log'),
        'log.error_file': '' if args.debug else str(log_path / 'error.log'),
    })

    # Start the application and server daemon.
    cherrypy.tree.mount(Upload(args, config), '/upload', conf)
    cherrypy.daemon.start(daemonize=args.daemonize, pidfile=args.pidfile,
                          fastcgi=args.fastcgi, scgi=args.scgi, cgi=args.cgi)
