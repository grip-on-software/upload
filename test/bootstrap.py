"""
Tests for module that bootstraps the encrypted upload server.

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

from argparse import ArgumentParser
from configparser import RawConfigParser
import unittest
from unittest.mock import patch, MagicMock
from encrypted_upload.bootstrap import get_ha1_keyring, add_args, bootstrap

class BootstrapTest(unittest.TestCase):
    """
    Tests for bootstrap methods.
    """

    def setUp(self) -> None:
        self.config = RawConfigParser()
        self.config.read("upload.cfg.example")

        self.parser = ArgumentParser()

    @patch('keyring.get_password', return_value='pass')
    def test_get_ha1_keyring(self, get_password: MagicMock) -> None:
        """
        Test providing digest authentication via keyring.
        """

        get_ha1 = get_ha1_keyring('domain')
        self.assertEqual(get_ha1('REALM', 'user'), 'pass')
        get_password.assert_called_once_with('domain', 'user')

    def test_add_args(self) -> None:
        """
        Test adding command line arguments for the server.
        """

        add_args(self.parser, self.config)
        args = self.parser.parse_args(['--port', '8080'])
        self.assertEqual(args.port, 8080)

    @patch('keyring.get_password', return_value='pass')
    @patch('keyring.set_password')
    @patch('cherrypy.daemon.start')
    def test_bootstrap(self, daemon: MagicMock, set_password: MagicMock,
                       get_password: MagicMock) -> None:
        """
        Test setting up the upload server.
        """

        self.config['server']['keyring'] = ''
        add_args(self.parser, self.config)
        args = self.parser.parse_args(['--keyring', 'domain', '--daemonize'])
        bootstrap(self.config, args)
        get_password.assert_called_with('domain-secret', 'server')
        set_password.assert_called_with('domain-symmetric',
                                        '$CLIENT_ID'.lower(),
                                        '$CLIENT_PASSPHRASE')
        daemon.assert_called_once_with(daemonize=True, pidfile=None,
                                       fastcgi=False, scgi=False, cgi=False)

        get_password.reset_mock()
        set_password.reset_mock()

        args = self.parser.parse_args(['--listen', '127.0.0.2', '--debug'])
        bootstrap(self.config, args)
        get_password.assert_not_called()
        set_password.assert_not_called()

        get_password.configure_mock(return_value=None)
        args = self.parser.parse_args(['--keyring', 'set', '--debug'])
        bootstrap(self.config, args)
        set_password.assert_any_call('set-secret', 'server', '$SERVER_SECRET')

        self.config['server']['secret'] = ''
        with self.assertRaisesRegex(ValueError,
                                    'No server secret auth key provided'):
            bootstrap(self.config, args)
