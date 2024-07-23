"""
Tests for subcommand to add, modify or delete client authentication.

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
from encrypted_upload.auth import add_args, get_password, handle_command
from encrypted_upload.hash import ha1_nonce

class AuthTest(unittest.TestCase):
    """
    Tests for authentication subcommand.
    """

    def setUp(self) -> None:
        self.parser = ArgumentParser()
        self.config = RawConfigParser()
        self.config.read('upload.cfg.example')

    def test_add_args(self) -> None:
        """
        Test adding command line arguments.
        """

        add_args(self.parser, self.config)
        args = self.parser.parse_args(['--add'])
        self.assertTrue(args.add)
        self.assertFalse(args.modify)

    @patch('encrypted_upload.auth.getpass', return_value='pass')
    def test_get_password(self, getpass: MagicMock) -> None:
        """
        Test retrieving the password to be set.
        """

        add_args(self.parser, self.config)
        args = self.parser.parse_args(['--add', '--user', 'user'])
        self.assertEqual(get_password(args, hashed=False), 'pass')
        getpass.assert_called_once_with('New password: ')

        getpass.reset_mock()
        self.assertEqual(get_password(args, hashed=True, prompt='PWD:'),
                         ha1_nonce('user', '$SERVER_REALM', 'pass'))
        getpass.assert_called_once_with('PWD:')

        getpass.reset_mock()
        args = self.parser.parse_args([
            '--add', '--user', 'user', '--realm', 'REALM', '--password', 'other'
        ])
        self.assertEqual(get_password(args, hashed=False), 'other')
        self.assertEqual(get_password(args, hashed=True),
                         ha1_nonce('user', 'REALM', 'other'))
        getpass.assert_not_called()

    @patch('keyring.get_password', return_value='pass')
    @patch('keyring.set_password')
    @patch('keyring.delete_password')
    def test_handle_command(self, delete_password: MagicMock,
                            set_password: MagicMock, get: MagicMock) -> None:
        """
        Test performin a modification to the keyring.
        """

        add_args(self.parser, self.config)

        args = self.parser.parse_args(['--delete', '--user', 'user'])
        handle_command(args)
        delete_password.assert_called_once_with('$SERVER_KEYRING', 'user')
        get.return_value = None
        with self.assertRaises(KeyError):
            handle_command(args)

        args = self.parser.parse_args([
            '--add', '--user', 'user', '--password', 'mypass',
            '--realm', 'ex', '--keyring', 'ring'
        ])
        handle_command(args)
        set_password.assert_called_once_with('ring', 'user',
                                             ha1_nonce('user', 'ex', 'mypass'))
        get.return_value = 'mypass'
        with self.assertRaises(KeyError):
            handle_command(args)

        set_password.reset_mock()
        args = self.parser.parse_args([
            '--modify', '--user', 'user', '--password', 'newpass',
            '--realm', 'ex', '--keyring', 'domain'
        ])
        handle_command(args)
        set_password.assert_called_once_with('domain', 'user',
                                             ha1_nonce('user', 'ex', 'newpass'))
        get.return_value = None
        with self.assertRaises(KeyError):
            handle_command(args)

        set_password.reset_mock()
        args = self.parser.parse_args([
            '--secret', '--password', 'token', '--keyring', 'domain'
        ])
        handle_command(args)
        set_password.assert_called_once_with('domain-secret','server', 'token')

        set_password.reset_mock()
        args = self.parser.parse_args([
            '--private', '--password', 'priv', '--keyring', 'domain'
        ])
        handle_command(args)
        set_password.assert_called_once_with('domain-secret', 'privkey', 'priv')
