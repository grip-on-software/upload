# Encrypted file upload server

This repository includes a service for running a HTTP server which accepts 
uploads of GPG-encrypted files. The service uses a keychain to keep GPG 
passphrases. Certain uploaded files can be used to import a database dump. 
Usual deployment setups would host this service behind a reverse proxy such as 
NGINX or Apache which handles SSL termination and access control.

## Requirements

A working version of the [GPG 
exchange](https://github.com/lhelwerd/gpg-exchange) library is required. Follow 
the instructions there to install the GPG dependencies.

Then install all Python dependencies using the following command:

`pip install -r requirements.txt`

## Configuration

Configure server settings in `upload.cfg` by copying `upload.cfg.example` and 
replacing the variables with actual values. The following configuration 
sections and items are known:

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
    [monetdb-import]https://github.com/grip-on-software/monetdb-import) 
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

A `gros-uploader.service` file is provided for installing as a systemd service. 
One can also use the `upload-session.sh` file to start the service within 
a GNOME keyring context with pre-set virtual environments and arguments, or 
directly use the `python upload.py` script to run the server. The script takes 
various options that can be reviewed by using the `--help` argument, including 
debugging instances. Uploads are stored beneath the "upload" subdirectory 
structured of the current working directory.
