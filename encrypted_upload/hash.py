"""
Digest hash functions.

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
