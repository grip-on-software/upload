"""
Listener server which accepts uploaded PGP-encrypted files.
"""

import argparse
import configparser
import datetime
from hashlib import md5
import json
import os
import shutil
from subprocess import Popen
import tempfile
import cherrypy
import cherrypy.daemon
import gpg
from gpg_exchange import Exchange
import keyring

class Upload(object):
    # pylint: disable=no-self-use
    """
    Upload listener.
    """

    PGP_ARMOR_MIME = "application/pgp-encrypted"
    PGP_BINARY_MIME = "application/x-pgp-encrypted-binary"

    def __init__(self, args, config):
        self.args = args
        self.config = config

        if self.args.keyring and self.args.loopback:
            passphrase = self._get_passphrase
        else:
            passphrase = None

        self._gpg = Exchange(engine_path=self.args.engine, passphrase=passphrase)

    def _get_passphrase(self, hint, desc, prev_bad, hook=None):
        return keyring.get_password(self.args.keyring + '-secret', 'privkey')

    @cherrypy.expose
    @cherrypy.tools.json_in()
    @cherrypy.tools.json_out()
    def exchange(self):
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
                if login != '' and self.config.has_option('client', login):
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
            'pubkey': str(ciphertext)
        }

    def _upload_gpg_file(self, input_file, directory, filename, binary):
        path = os.path.join(directory, filename)
        with open(path, 'wb') as output_file:
            try:
                self._gpg.decrypt_file(input_file, output_file, armor=binary)
            except (gpg.errors.GpgError, ValueError) as error:
                raise ValueError('File {} could not be decrypted: {}'.format(filename, str(error)))

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def upload(self, files):
        """
        Perform an upload and import of GPG-encrypted files from a client
        which has performed a key exchange.
        """

        if not isinstance(files, list):
            files = [files]

        login = cherrypy.request.login
        date = datetime.datetime.now().strftime('%Y-%m-%d')
        directory = os.path.join(self.args.upload_path, login, date)
        if not os.path.exists(directory):
            os.makedirs(directory, 0o770)

        for index, upload_file in enumerate(files):
            name = upload_file.filename.split('/')[-1]
            if name == '':
                raise ValueError('No name provided for file #{}'.format(index))
            if name not in self.args.accepted_files:
                raise ValueError('File #{}: name {} is unacceptable'.format(index, name))

            if upload_file.content_type.value == self.PGP_ARMOR_MIME:
                binary = False
            elif upload_file.content_type.value == self.PGP_BINARY_MIME:
                binary = True
            else:
                binary = None

            self._upload_gpg_file(upload_file.file, directory, name, binary)
            if name == self.args.import_dump:
                process_args = [
                    '/bin/bash', self.args.import_script, login, date,
                    self.args.database
                ]
                Popen(process_args, stdout=None, stderr=None,
                      cwd=os.path.join(self.args.import_path, 'Scripts'))

        return {
            'success': True
        }

    @classmethod
    def json_error(cls, status, message, traceback, version):
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
            }
        })

def get_ha1_keyring(name):
    def get_ha1(realm, username):
        return str(keyring.get_password(name, username))

    return get_ha1

def md5_hex(nonce):
    """
    Encode as MD5.
    """

    return md5(nonce.encode('ISO-8859-1')).hexdigest()

def ha1_nonce(username, realm, password):
    """
    Create an encoded variant for the user's password in the realm.
    """

    return md5_hex('%s:%s:%s' % (username, realm, password))

def parse_args(config):
    """
    Parse command line arguments.
    """

    work_dir = os.getcwd()
    parser = argparse.ArgumentParser(description='Run upload listener')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Output traces on web')
    parser.add_argument('--listen', default=None,
                        help='Bind address (default: 0.0.0.0, 127.0.0.1 in debug')
    parser.add_argument('--port', default=9090, type=int,
                        help='Port to listen to (default: 9090')
    parser.add_argument('--log-path', dest='log_path', default=work_dir,
                        help='Path to store logs at in production')
    parser.add_argument('--daemonize', action='store_true', default=False,
                        help='Run the server as a daemon')
    parser.add_argument('--pidfile', help='Store process ID in file')

    parser.add_argument('--engine', default=config['server']['engine'],
                        help='GPG engine path')
    parser.add_argument('--upload-path', dest='upload_path',
                        default=os.path.join(work_dir, 'upload'),
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

def main():
    """
    Main entry point.
    """

    config = configparser.RawConfigParser()
    config.read('upload.cfg')
    args = parse_args(config)
    if args.listen is not None:
        bind_address = args.listen
    elif args.debug:
        bind_address = '127.0.0.1'
    else:
        bind_address = '0.0.0.0'

    auth_key = config['server'].get('secret', '')
    auth = dict((str(key), str(value)) for key, value in config['auth'].items())
    if args.keyring:
        auth_keyring = keyring.get_password(args.keyring + '-secret', 'server')
        if auth_keyring is not None:
            auth_key = auth_keyring
        elif auth_key != '':
            keyring.set_password(args.keyring + '-secret', 'server', auth_key)
        else:
            raise ValueError('No server secret auth key provided')

        for user, password in auth.items():
            keyring.set_password(args.keyring, user,
                                 ha1_nonce(user, args.realm, password))

        ha1 = get_ha1_keyring(args.keyring)
    else:
        ha1 = cherrypy.lib.auth_digest.get_ha1_dict_plain(auth)

    conf = {
        'global': {
        },
        '/': {
            'error_page.default': Upload.json_error,
            'response.headers.server': 'Cherrypy/{}'.format(cherrypy.__version__) if args.debug else 'Cherrypy',
            'tools.auth_digest.on': True,
            'tools.auth_digest.realm': str(args.realm),
            'tools.auth_digest.get_ha1': ha1,
            'tools.auth_digest.key': str(auth_key)
        }
    }
    cherrypy.config.update({
        'server.max_request_body_size': 1000 * 1024 * 1024,
        'server.socket_host': bind_address,
        'server.socket_port': args.port,
        'request.show_tracebacks': args.debug,
        'log.screen': args.debug,
        'log.access_file': '' if args.debug else os.path.join(args.log_path, 'access.log'),
        'log.error_file': '' if args.debug else os.path.join(args.log_path, 'error.log'),
    })

    # Start the application and server daemon.
    cherrypy.tree.mount(Upload(args, config), '/upload', conf)
    cherrypy.daemon.start(daemonize=args.daemonize, pidfile=args.pidfile,
                          fastcgi=args.fastcgi, scgi=args.scgi, cgi=args.cgi)


if __name__ == '__main__':
    main()
