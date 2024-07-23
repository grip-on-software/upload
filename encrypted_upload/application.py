"""
Listener server which accepts uploaded PGP-encrypted files.

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

from argparse import Namespace
from configparser import RawConfigParser
import datetime
import json
from pathlib import Path
import shutil
from subprocess import Popen
import tempfile
from typing import Any, BinaryIO, Dict, List, Optional, Union, TYPE_CHECKING
import cherrypy
import cherrypy.daemon
from cherrypy._cpreqbody import Part
import gpg
from gpg_exchange import Exchange
import keyring
from . import __version__ as VERSION
if TYPE_CHECKING:
    from gpg_exchange.exchange import Passphrase
else:
    Passphrase = Any

class Upload:
    """
    Upload listener.
    """

    PGP_ARMOR_MIME = "application/pgp-encrypted"
    PGP_BINARY_MIME = "application/x-pgp-encrypted-binary"
    PGP_ENCRYPT_SUFFIX = ".gpg"

    def __init__(self, args: Namespace, config: RawConfigParser):
        self.args = args
        self.config = config

        self._keyring = ''
        passphrase: Optional[Passphrase] = None

        if self.args.keyring:
            self._keyring = str(self.args.keyring)
            if self.args.loopback:
                passphrase = self._get_passphrase

        self._gpg = Exchange(engine_path=self.args.engine,
                             passphrase=passphrase)

    def _get_passphrase(self, hint: str, desc: str, prev_bad: int,
                        hook: Optional[Any] = None) -> str:
        # pylint: disable=unused-argument
        return keyring.get_password(f'{self._keyring}-secret', 'privkey')

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
                if self._keyring:
                    passphrase = \
                        keyring.get_password(f'{self._keyring}-symmetric',
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
                    # Let the import process run but no longer care about it.
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
                'upload': VERSION,
                'cherrypy': version
            } if cherrypy.request.show_tracebacks else {}
        })
