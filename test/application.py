"""
Tests for listener server which accepts uploaded PGP-encrypted files.

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

from argparse import Namespace
from configparser import RawConfigParser
from datetime import datetime
from email.message import EmailMessage
from email.policy import HTTP
import json
import os
from pathlib import Path
import shutil
import tempfile
from typing import Any, Dict, List, Literal, Optional, Tuple, Union, overload
from unittest.mock import MagicMock, patch
import cherrypy
from cherrypy.test import helper
from gpg_exchange import Exchange
from encrypted_upload.application import Upload

class UploadTest(helper.CPWebCase):
    """
    Tests for upload listener.
    """

    server_key_fpr: str = 'MISSING'
    server_pubkey: Union[str, bytes]
    client_key_fpr: str = 'MISSING'
    client_pubkey: Union[str, bytes]
    temp_dir: str
    gpg: Exchange
    client_gpg: Exchange
    get_password: MagicMock
    popen: MagicMock

    @classmethod
    def _get_passphrase(cls, hint: str, desc: str, prev_bad: int,
                        hook: Optional[Any] = None) -> str:
        # pylint: disable=unused-argument
        return 'pass'

    @classmethod
    def setup_server(cls) -> None:
        """
        Set up the application server.
        """

        # Pre-generate a key so we can actually make proper encrypted responses
        cls.gpg = Exchange(passphrase=cls._get_passphrase)
        try:
            cls.server_key_fpr = cls.gpg.find_key('GROS upload server test').fpr
        except KeyError:
            key = cls.gpg.generate_key('GROS upload server test',
                                       'upload@gros.test',
                                       comment='GROS upload server key')
            cls.server_key_fpr = key.fpr
        cls.server_pubkey = cls.gpg.export_key(cls.server_key_fpr)

        cls.temp_dir = tempfile.mkdtemp()
        cls.client_gpg = Exchange(home_dir=cls.temp_dir,
                                  passphrase=cls._get_passphrase)
        try:
            cls.client_key_fpr = cls.client_gpg.find_key('GROS TEST').fpr
        except KeyError:
            key = cls.client_gpg.generate_key('GROS TEST', 'test@gros.test',
                                              comment='GROS upload client key')
            cls.client_key_fpr = key.fpr
        cls.client_pubkey = cls.client_gpg.export_key(cls.client_key_fpr)
        cls.client_gpg.import_key(cls.server_pubkey)

        keyring_patcher = patch('keyring.get_password', return_value='pass')
        cls.get_password = keyring_patcher.start()
        cls.addClassCleanup(keyring_patcher.stop)

        subprocess_patcher = patch('encrypted_upload.application.Popen')
        cls.popen = subprocess_patcher.start()
        cls.addClassCleanup(subprocess_patcher.stop)

        args = Namespace()
        args.engine = None
        args.upload_path = 'test/sample/upload'
        args.accepted_files = ('dump.tar.gz', 'message.txt')
        args.database = 'localhost'
        args.import_dump = 'dump.tar.gz'
        args.import_path = 'test/sample'
        args.import_script = 'import.sh'
        args.key = cls.server_key_fpr
        args.keyring = 'gros-uploader'
        args.realm = 'upload'
        args.accepted_keys = ('GROS TEST', 'GROS EX')
        args.loopback = True

        config = RawConfigParser()
        config['client'] = {}
        config['client']['test'] = 'GROS TEST'
        config['symm'] = {}
        config['symm']['test'] = 'pass'

        cherrypy.tree.mount(Upload(args, config), '/upload', {
            'global': {},
            '/': {
                'error_page.default': Upload.json_error
            }
        })

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls.gpg.delete_key(cls.server_key_fpr, secret=True)
        except KeyError: # pragma: no cover
            pass
        del cls.gpg

        try:
            cls.client_gpg.delete_key(cls.client_key_fpr, secret=True)
        except KeyError: # pragma: no cover
            pass
        try:
            cls.client_gpg.delete_key(cls.server_key_fpr)
        except KeyError: # pragma: no cover
            pass
        del cls.client_gpg
        shutil.rmtree(cls.temp_dir)

    def tearDown(self) -> None:
        try:
            self.gpg.delete_key(self.client_key_fpr)
        except KeyError: # pragma: no cover
            pass

    def perform_exchange_request(self, data: Dict[str, str]) -> None:
        """
        Perform a request to the exchange JSON endpoint.
        """

        body = json.dumps(data)
        self.getPage('/upload/exchange',
                     headers=[('Content-Type', 'application/json'),
                              ('Content-Length', str(len(body)))],
                     method='POST', body=body)

    @overload
    def check_json(self, key: str) -> str:
        ...

    @overload
    def check_json(self, key: Literal[True]) -> None:
        ...

    def check_json(self, key) -> Optional[str]:
        """
        Check if the response headers/body indicate correct JSON and has proper
        object keys. For the 'error' key, we check additional error response
        structure, namely the 'success' key; the error traceback is returned.
        If `key` is True, then the 'success' key is checked for the non-error
        response. Otherwise, the actual value of the object key is returned.
        """

        self.assertHeader('Content-Type', 'application/json')
        data: Dict[str, Union[Dict[str, str], str]] = json.loads(self.body)
        self.assertIn('success' if key is True else key, data)
        if key == 'error':
            self.assertFalse(data['success'])
            error = data[key]
            if not isinstance(error, dict):
                raise AssertionError(f'Expected object data for {key}: {error}')
            actual = error['traceback']
        elif key is True:
            self.assertTrue(data['success'])
            return None
        else:
            value = data[key]
            if not isinstance(value, str):
                raise AssertionError(f'Expected string data for {key}: {value}')
            actual = value

        return actual

    def test_exchange(self) -> None:
        """
        Test exchanging public keys.
        """

        self.perform_exchange_request({
            'pubkey': self.client_pubkey.decode('utf-8') \
                if isinstance(self.client_pubkey, bytes) else self.client_pubkey
        })
        pubkey = self.check_json('pubkey')
        self.assertEqual(self.client_gpg.decrypt_text(pubkey.encode('utf-8'),
                                                      verify=False),
                         self.server_pubkey)
        self.assertIsNotNone(self.gpg.find_key(self.client_key_fpr))

        # Unknown public keys are not accepted.
        with open('test/sample/other.gpg', encoding='utf-8') as pubkey_file:
            other_pubkey = pubkey_file.read()

        self.perform_exchange_request({
            'pubkey': other_pubkey
        })
        self.assertIn('Must be an acceptable public key',
                      self.check_json('error'))

        # Provide invalid JSON objects
        self.getPage('/upload/exchange', method='POST',
                     headers=[('Content-Type', 'application/json'),
                              ('Content-Length', '2')],
                     body=json.dumps([]))
        self.assertIn('Must provide a JSON object', self.check_json('error'))

        self.perform_exchange_request({})
        self.assertIn('Must provide a pubkey', self.check_json('error'))

    def _encrypt_upload(self, path_name: str, upload_name: Optional[str],
                        armor: bool, message: EmailMessage) -> bytes:
        key = self.client_gpg.find_key(self.server_key_fpr)
        mime_type = Upload.PGP_ARMOR_MIME if armor else Upload.PGP_BINARY_MIME
        with open(f'test/sample/{path_name}', 'rb') as upload_file:
            if upload_name is None:
                # Keep unencrypted
                upload_name = path_name
                encrypted_payload = upload_file.read()
            else:
                with tempfile.TemporaryFile() as temp_file:
                    self.client_gpg.encrypt_file(upload_file, temp_file, key,
                                                 always_trust=True, armor=armor)
                    temp_file.seek(0, os.SEEK_SET)
                    encrypted_payload = temp_file.read()

            form_data = EmailMessage(policy=HTTP)
            form_data.add_header('Content-Type', mime_type)
            form_data.add_header('Content-Disposition', 'form-data',
                                 name='files', filename=upload_name)
            form_data.set_payload(encrypted_payload)
            message.attach(form_data)

        return encrypted_payload

    def _make_upload_body(self, message: EmailMessage,
                          payloads: List[bytes]) -> bytes:
        encoded_parts = message.as_bytes().split(b'\r\n\r\n', maxsplit=1)[1]
        boundary = message.get_boundary('1234567890').encode('ascii')
        body = b'--' + boundary
        for part, payload in zip(encoded_parts.split(b'--' + boundary)[1:-1],
                                 payloads):
            body += part.split(b'\r\n\r\n', maxsplit=1)[0] + \
                    b'\r\n\r\n' + payload + b'\r\n--' + boundary
        body += b'--'
        return body

    def perform_upload_request(self, *files: str,
                               names: Optional[Tuple[Optional[str], ...]] = None,
                               armor: bool = False) -> None:
        """
        Perform a request to the upload endpoint.
        """

        if names is None:
            names = files

        message = EmailMessage(policy=HTTP)
        message.add_header('Content-Type', 'multipart/form-data')
        payloads = []
        for path_name, upload_name in zip(files, names):
            encrypted_payload = self._encrypt_upload(path_name, upload_name,
                                                     armor, message)
            payloads.append(encrypted_payload)

        body = self._make_upload_body(message, payloads)
        self.getPage('/upload/upload', method='POST',
                     headers=[('Content-Type', message['Content-Type']),
                              ('Content-Length', str(len(body)))],
                     body=body)

    def test_upload(self) -> None:
        """
        Test performing an upload and import of GPG-encrypted files.
        """

        date = datetime.now().strftime('%Y-%m-%d')

        # Pretend an exchange has taken place.
        self.gpg.import_key(self.client_pubkey)

        self.perform_upload_request('message.txt')
        self.check_json(True)
        upload_path = Path(f'test/sample/upload/None/{date}/message.txt')
        self.assertTrue(upload_path.exists())

        self.perform_upload_request('dump.tar.gz', armor=True)
        self.check_json(True)
        self.popen.assert_called_once_with([
            '/bin/bash', 'import.sh', 'None', date, 'localhost'
        ], stdout=None, stderr=None, cwd=Path('test/sample/Scripts'))

        # Zero files
        self.getPage('/upload/upload', method='POST')
        self.assertIn('Files required', self.check_json('error'))

        # Multiple files
        self.perform_upload_request('message.txt', 'dump.tar.gz',
                                    names=('message.txt.gpg', 'dump.tar.gz'))
        self.check_json(True)

        # Files without names
        self.perform_upload_request('message.txt', names=('/',))
        self.assertIn('No name provided for file #0', self.check_json('error'))

        # Unaccepted filenames
        self.perform_upload_request('message.txt', names=('other.txt',))
        self.assertIn('File #0: name other.txt is unacceptable',
                      self.check_json('error'))

        # Decryption problems
        self.perform_upload_request('message.txt', names=(None,))
        self.assertRegex(self.check_json('error'),
                         r'.*File message\.txt: Decryption to .* failed: .*')
