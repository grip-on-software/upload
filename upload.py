"""
Listener server which accepts uploaded PGP-encrypted files.
"""

import argparse
import io
import json
import logging
import os.path
import shutil
import tempfile
import cherrypy
import cherrypy.daemon
import gpgme

class Upload(object):
    # pylint: disable=no-self-use
    """
    Upload listener.
    """

    def __init__(self, args):
        self.args = args
        self._gpg = gpgme.Context()
        self._gpg.armor = True

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
        import_gpg = gpgme.Context()
        import_gpg.set_engine_info(import_gpg.protocol, self.args.engine,
                                   temp_dir)

        try:
            result = import_gpg.import_(io.BytesIO(pubkey))
            if result.considered != 1:
                raise ValueError('Exactly one public key must be provided')
            if result.imported != 1:
                raise ValueError('Given public key must be valid')

            # Validate import source to match expected list
            try:
                fpr = result.imports[0][0]
                key = import_gpg.keylist(fpr).next()
                if key.uids[0].name not in self.args.accepted_keys:
                    raise ValueError('Must be an acceptable public key')
            except (StopIteration, IndexError, AttributeError) as error:
                raise ValueError('Could not import key: {}'.format(error))
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir)

        # Actual import
        self._gpg.import_(io.BytesIO(pubkey))

        # Return our own GPG key
        server_key = io.BytesIO()
        self._gpg.export(self.args.key, server_key)
        return {
            'pubkey': str(server_key.getvalue())
        }

    def _upload_gpg_file(self, input_file, filename):
        path = os.path.join(self.args.upload_path, filename)
        with open(path, 'wb') as output_file:
            try:
                self._gpg.decrypt(input_file, output_file)
            except gpgme.GpgmeError as error:
                if error.code == gpgme.ERR_NO_DATA:
                    raise ValueError('File {} is not encrypted'.format(filename)
)
                else:
                    raise ValueError('File {} could not be decrypted: {}'.format(filename, str(error)))

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def upload(self, files):
        if not isinstance(files, list):
            files = [files]

        for upload_file in files:
            name = upload_file.filename.split('/')[-1]
            if name == '':
                raise ValueError('No name provided for file')
            output_file = self._upload_gpg_file(upload_file.file, name)

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

def parse_args():
    """
    Parse command line arguments.
    """

    parser = argparse.ArgumentParser(description='Run upload listener')
    parser.add_argument('--debug', action='store_true', default=False,
                        help='Output traces on web')
    parser.add_argument('--listen', default=None,
                        help='Bind address (default: 0.0.0.0, 127.0.0.1 in debug')
    parser.add_argument('--port', default=9090, type=int,
                        help='Port to listen to (default: 9090')
    parser.add_argument('--log-path', dest='log_path', default='.',
                        help='Path to store logs at in production')
    parser.add_argument('--daemonize', action='store_true', default=False,
                        help='Run the server as a daemon')
    parser.add_argument('--pidfile', help='Store process ID in file')

    parser.add_argument('--upload-path', dest='upload_path',
                        default='/home/upload', help='Upload path')
    parser.add_argument('--engine', default='/usr/bin/gpg2',
                        help='GPG engine path')
    parser.add_argument('--key', help='Fingerprint of server key pair')
    parser.add_argument('--accepted-keys', dest='accepted_keys', nargs='*',
                        help='List of accepted names for public keys')

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

    args = parse_args()
    if args.listen is not None:
        bind_address = args.listen
    elif args.debug:
        bind_address = '127.0.0.1'
    else:
        bind_address = '0.0.0.0'

    config = {
        'global': {
            'request.show_tracebacks': args.debug,
            'log.screen': args.debug,
            'log.access_file': '' if args.debug else os.path.join(args.log_path, 'access.log'),
            'log.error_file': '' if args.debug else os.path.join(args.log_path, 'error.log'),
        },
        '/': {
            'error_page.default': Upload.json_error,
            'response.headers.server': 'Cherrypy/{}'.format(cherrypy.__version__) if args.debug else 'Cherrypy'
        }
    }
    cherrypy.config.update({
        'server.socket_host': bind_address,
        'server.socket_port': args.port
    })

    # Start the application and server daemon.
    cherrypy.tree.mount(Upload(args), '/upload', config)
    cherrypy.daemon.start(daemonize=args.daemonize, pidfile=args.pidfile,
                          fastcgi=args.fastcgi, scgi=args.scgi, cgi=args.cgi)


if __name__ == '__main__':
    main()
