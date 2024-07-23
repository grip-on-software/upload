# Encrypted file upload server

[![PyPI](https://img.shields.io/pypi/v/gros-upload.svg)](https://pypi.python.org/pypi/gros-upload)
[![Build 
status](https://github.com/grip-on-software/upload/actions/workflows/upload-tests.yml/badge.svg)](https://github.com/grip-on-software/upload/actions/workflows/upload-tests.yml)
[![Coverage 
Status](https://coveralls.io/repos/github/grip-on-software/upload/badge.svg?branch=master)](https://coveralls.io/github/grip-on-software/upload?branch=master)
[![Quality Gate
Status](https://sonarcloud.io/api/project_badges/measure?project=grip-on-software_upload&metric=alert_status)](https://sonarcloud.io/project/overview?id=grip-on-software_upload)
[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.12784820.svg)](https://doi.org/10.5281/zenodo.12784820)

This repository includes a service for running a HTTP server which accepts 
uploads of GPG-encrypted files. Although available as a package, it is mostly 
meant to run as a standalone program or service. The application uses 
a keychain to keep GPG passphrases which can be modified using a subcommand. 
Certain uploaded files can be used to import a database dump. Usual deployment 
setups would host this service behind a reverse proxy such as NGINX or Apache 
which handles SSL termination and additional access control over the 
Digest-based user authentication in this server.

## Installation

The [GPG exchange](https://github.com/lhelwerd/gpg-exchange) library is 
required to be in a working state. Follow the instructions there to install the 
GPG dependencies first. Then, to install the latest release version of the 
packaged program from PyPI, run the following command:

```
pip install gros-upload
```

Another option is to build the program from this repository, which allows using 
the most recent development code. Run `make setup` to install the dependencies. 
The upload server itself may then be installed with `make install`, which 
places the package in your current environment. We recommend using a virtual 
environment during development.

## Configuration

Configure server settings in `upload.cfg` by copying `upload.cfg.example` or 
the example file below:
```ini
[server]
key = $SERVER_KEY
engine = $SERVER_ENGINE
files = $SERVER_FILES
secret = $SERVER_SECRET
keyring = $SERVER_KEYRING
realm = $SERVER_REALM

[import]
database = $IMPORT_DATABASE
dump = $IMPORT_DUMP
path = $IMPORT_PATH
script = $IMPORT_SCRIPT

[client]
$CLIENT_ID=$CLIENT_NAME

[auth]
$CLIENT_ID=$CLIENT_AUTH

[symm]
$CLIENT_ID=$CLIENT_PASSPHRASE
```
Replace the variables with actual values. The following configuration sections 
and items are known:

- `server`: Configuration of the listener server.
  - `key`: Fingerprint of the GPG key pair to be used by the server to identify 
    itself toward the uploaders.
  - `engine`: Path to the GPG utility for GPG tasks, e.g. `/usr/bin/gpg2`.
  - `files`: Space-separated list of file names that the server accepts in the
    upload, for example `dump.sql.gz` to allow a database dump from the example
    tasks of the `export-exchange` repository.
  - `secret`: Secret string to use for the hash algorithm for the digest 
    authentication to challenge the uploader to provide a known username and 
    password in encrypted format.
  - `keyring`: Name of the keyring in which authentication data is stored.
  - `realm`: Name of the realm to use within the digest authentication.
- `import`: Configuration of the file-specific import. Normally, uploaded files 
  are simply placed in subdirectories below the current working directory; in 
  nesting order 'upload', the login name of the client and the current date. 
  For a specific file name, an import script can be started to load a database 
  from scratch with data from an uploaded dump file.
  - `database`: The name of the database to import dumps into. Provided as 
    a third parameter to the import script; ignored by the standard `import.sh` 
    script since the database name is determined by the organizational user.
  - `dump`: Name of the uploaded file that is considered for the import script. 
    Other files do not trigger the import script. The standard `import.sh` 
    script expects there to be a file called `dump.tar.gz`.
  - `path`: Path to the 
    [monetdb-import](https://github.com/grip-on-software/monetdb-import) 
    repository where further import scripts are located. The `Scripts` 
    directory within this repository is used as working directory for the 
    import script.
  - `script`: Path to the script to run when a specific dump file is uploaded. 
    If the script is placed elsewhere than the currrent working directory, use 
    an absolute path. The standard `import.sh` script performs database 
    recreation, archive extraction, import, update and schema publication.
- `client`: Accepted logins and public key names. Each item has a configuration 
  key which has the login name of a uploader client, and the value is the name 
  registered in the public key that the uploader must provide in order to be 
  accepted.
- `auth`: Accepted logins with usernames as keys and passwords as values in the 
  configuration items. The usernames and passwords are imported to the keyring 
  if possible, so that they can be removed from the configuration once imported 
  (assuming the `secret` remains the same).
- `symm`: Usernames and passphrases for symmetric decryption of uploaded data, 
  respectively as keys and values in the configuration items. The usernames and 
  passphrases are imported to the keyring if possible, so that they can be 
  removed from the configuration once imported.

## Running

The upload server can be started directly using the following command:

```
gros-upload server
```

The subcommand takes various options that can be reviewed by using the 
`gros-upload server --help` argument, including debugging instances and 
different CGI deployment options. Uploads are stored beneath the "upload" 
subdirectory structured of the current working directory.

A `gros-uploader.service` file is provided for installing as a systemd service. 
One can also use the `upload-session.sh` file to start the service within 
a GNOME keyring context, preset to store uploads in `/home/upload/upload` and 
logs in `/var/log/upload`, using a `virtualenv` setup shared with the 
[controller](https://gros.liacs.nl/data-gathering/api.html#controller-api) of 
the agent-based data gathering setup. The script requires a password to unlock 
the keyring. In combination with the service, a root user needs to input 
a keyring password using a systemd Password Agent, for example by running the 
`systemd-tty-ask-password-agent` command, before the server actually starts 
under the `upload` user. Some pointers on the advanced setup can be found in 
[installation](https://gros.liacs.nl/data-gathering/installation.html#controller) 
of the controller environment.

In order to adjust client authentication credentials, the subcommand 
`gros-upload auth [--add|--modify|--delete] --user ... [--password ...]` may be 
used. Additional arguments shown in `gros-upload auth --help` allow setting the 
secret Digest token and the private key passphrase. Configuring credentials is 
also possible for users and the Digest token using the `auth` section and 
`secret` option of the `server` section in the [configuration](#configuration) 
file, respectively.

## Development and testing

To run tests, first install the test dependencies with `make setup_test` which 
also installs all dependencies for the upload server. Then `make coverage` 
provides test results in the output and in XML versions compatible with, e.g., 
JUnit and SonarQube available in the `test-reports/` directory. If you do not 
need XML outputs, then run `make test` to just report on test successes and 
failures or `make cover` to also have the terminal report on hits and misses in 
statements and branches.

[GitHub Actions](https://github.com/grip-on-software/upload/actions) is used to 
run the unit tests and report on coverage on commits and pull requests. This 
includes quality gate scans tracked by 
[SonarCloud](https://sonarcloud.io/project/overview?id=grip-on-software_upload) 
and [Coveralls](https://coveralls.io/github/grip-on-software/upload) for 
coverage history.

The Python module conforms to code style and typing standards which can be 
checked using Pylint with `make pylint` and mypy with `make mypy`, after 
installing the pylint and mypy dependencies using `make setup_analysis`; typing 
reports are XML formats compatible with JUnit and SonarQube placed in the 
`mypy-report/` directory. To also receive the HTML report, use `make mypy_html` 
instead.

We publish releases to [PyPI](https://pypi.org/project/gros-upload/) using 
`make setup_release` to install dependencies and `make release` which performs 
multiple checks: unit tests, typing, lint and version number consistency. The 
release files are also published on 
[GitHub](https://github.com/grip-on-software/upload/releases) and from there 
are archived on [Zenodo](https://zenodo.org/doi/10.5281/zenodo.12784819).

## License

GROS encrypted file upload server is licensed under the Apache 2.0 License.
