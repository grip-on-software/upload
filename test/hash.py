"""
Tests for Digest hash functions.

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

from hashlib import md5
import unittest
from encrypted_upload.hash import md5_hex, ha1_nonce

class HashTest(unittest.TestCase):
    """
    Tests for Digest hash functions.
    """

    def test_md5_hex(self) -> None:
        """
        Test encoding as MD5.
        """

        self.assertEqual(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(md5_hex("test"), md5(b'test').hexdigest())

    def test_ha1_nonce(self) -> None:
        """
        Test creating an encoded variant of a user password in a realm.
        """

        self.assertEqual(ha1_nonce('user', 'realm', 'pass'),
                         md5(b'user:realm:pass').hexdigest())
