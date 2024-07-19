"""
Listener server which accepts uploaded PGP-encrypted files.

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
import datetime
from hashlib import md5
import json
from pathlib import Path
import shutil
from subprocess import Popen
import tempfile
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Union, \
    TYPE_CHECKING
import cherrypy
import cherrypy.daemon
from cherrypy._cpreqbody import Part
import gpg
from gpg_exchange import Exchange
import keyring
if TYPE_CHECKING:
    from gpg_exchange.exchange import Passphrase
else:
    Passphrase = Any

class Upload:
    """
    Upload listener.
    """

    VERSION = "0.0.3"

    PGP_ARMOR_MIME = "application/pgp-encrypted"
    PGP_BINARY_MIME = "application/x-pgp-encrypted-binary"
    PGP_ENCRYPT_SUFFIX = ".gpg"

    def __init__(self, args: Namespace, config: RawConfigParser):
        self.args = args
        self.config = config

        if self.args.keyring and self.args.loopback:
            passphrase = self._get_passphrase
        else:
            passphrase = None

        self._gpg = Exchange(engine_path=self.args.engine,
                             passphrase=passphrase)

    def _get_passphrase(self, hint: str, desc: str, prev_bad: int,
                        hook: Optional[Any] = None) -> str:
        # pylint: disable=unused-argument
        return keyring.get_password(f'{self.args.keyring}-secret', 'privkey')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def exchange(self) -> Dict[str, str]:
        """
        Exchange public keys.
        """

        data = cherrypy.request.json
        if not isinstance(data, dict):
            raise ValueError('Must provide a JSON object')
        if 'pubkey' not in data:
            raise ValueError('Must provide a pubkey')
        pubkey = str(data['pubkey'])

        temp_dir = tempfile.mkdtemp()
        with Exchange(home_dir=temp_dir, engine_path=self.args.engine) as import_gpg:
            try:
                key = import_gpg.import_key(pubkey)[0]
                login = cherrypy.request.login
                if login and self.config.has_option('client', login):
                    if key.uids[0].name != self.config.get('client', login):
                        raise ValueError('Public key must match client')

                if key.uids[0].name not in self.args.accepted_keys:
                    raise ValueError('Must be an acceptable public key')
            finally:
                # Clean up temporary directory
                shutil.rmtree(temp_dir)

        # Actual import
        client_key = self._gpg.import_key(pubkey)[0]

        # Retrieve our own GPG key and encrypt it with the client key so that
        # it cannot be intercepted by others (and thus others cannot send
        # encrypted files in name of the client).
        server_key = self._gpg.export_key(str(self.args.key))
        ciphertext = self._gpg.encrypt_text(server_key, client_key,
                                            always_trust=True)

        return {
            'pubkey': ciphertext.decode('utf-8') \
                if isinstance(ciphertext, bytes) else ciphertext
        }

    def _upload_gpg_file(self, input_file: Optional[BinaryIO], path: Path,
                         binary: Optional[bool] = None,
                         passphrase: Optional[Passphrase] = None) -> None:
        if input_file is None:
            raise ValueError(f'No upload file for {path}')

        try:
            with open(path, 'wb') as output_file:
                self._gpg.decrypt_file(input_file, output_file,
                                       armor=binary, passphrase=passphrase)
        except (gpg.errors.GpgError, ValueError) as error:
            # Write the (possibly encrypted) data to a separate file
            with open(f"{path}.enc", 'wb') as output_file:
                input_file.seek(0)
                buf = b'\0'
                while buf:
                    buf = input_file.read(1024)
                    if buf:
                        output_file.write(buf)

            raise ValueError(f'Decryption to {path} failed: {error}') from error

    @staticmethod
    def _extract_filename(index: int, upload_file: Part) -> str:
        if upload_file.filename is None:
            raise ValueError(f'No filename provided for file #{index}')

        name = upload_file.filename.split('/')[-1]
        if name == '':
            raise ValueError(f'No name provided for file #{index}')

        return name

    @classmethod
    def _extract_binary_mime(cls, upload_file: Part) -> Optional[bool]:
        if upload_file.content_type is None:
            return None

        if upload_file.content_type.value == cls.PGP_ARMOR_MIME:
            return False
        if upload_file.content_type.value == cls.PGP_BINARY_MIME:
            return True

        return None

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def upload(self, files: Optional[Union[Part, List[Part]]] = None) \
            -> Dict[str, bool]:
        """
        Perform an upload and import of GPG-encrypted files from a client
        which has performed a key exchange.
        """

        if files is None:
            raise ValueError('Files required')
        if not isinstance(files, list):
            files = [files]

        login = str(cherrypy.request.login)
        date = datetime.datetime.now().strftime('%Y-%m-%d')
        directory = Path(self.args.upload_path) / login / date
        directory.mkdir(mode=0o770, parents=True, exist_ok=True)

        for index, upload_file in enumerate(files):
            name = self._extract_filename(index, upload_file)
            passphrase = None

            if name.endswith(self.PGP_ENCRYPT_SUFFIX):
                name = name[:-len(self.PGP_ENCRYPT_SUFFIX)]
                if self.args.keyring:
                    passphrase = \
                        keyring.get_password(f'{self.args.keyring}-symmetric',
                                             login)
                else:
                    passphrase = self.config['symm'][login]
            if name not in self.args.accepted_files:
                raise ValueError(f'File #{index}: name {name} is unacceptable')

            binary = self._extract_binary_mime(upload_file)

            try:
                self._upload_gpg_file(upload_file.file, directory / name,
                                      binary=binary, passphrase=passphrase)
            except ValueError as error:
                raise ValueError(f'File {name}: {error}') from error
            if name == self.args.import_dump:
                process_args: List[str] = [
                    '/bin/bash', self.args.import_script, login, date,
                    self.args.database
                ]
                path = Path(self.args.import_path) / 'Scripts'
                with Popen(process_args, stdout=None, stderr=None, cwd=path):
                    pass

        return {
            'success': True
        }

    @classmethod
    def json_error(cls, status: str, message: str, traceback: str,
                   version: str) -> str:
        """
        Handle HTTP errors by formatting the exception details as JSON.
        """

        cherrypy.response.headers['Content-Type'] = 'application/json'
        return json.dumps({
            'success': False,
            'error': {
                'status': status,
                'message': message,
                'traceback': traceback if cherrypy.request.show_tracebacks else None
            },
            'version': {
                'upload': cls.VERSION,
                'cherrypy': version
            } if cherrypy.request.show_tracebacks else {}
        })

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

    work_dir = Path.cwd()
    parser = ArgumentParser(description='Run upload listener')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Output traces on web')
    parser.add_argument('--listen', default=None,
                        help='Bind address (default: 0.0.0.0, 127.0.0.1 in debug')
    parser.add_argument('--port', default=9090, type=int,
                        help='Port to listen to (default: 9090')
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

    return parser.parse_args()

def main() -> None:
    """
    Main entry point.
    """

    config = RawConfigParser()
    config.read('upload.cfg')
    args = parse_args(config)
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
        server = f'gros-upload/{Upload.VERSION} CherryPy/{cherrypy.__version__}'
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


if __name__ == '__main__':
    main()
