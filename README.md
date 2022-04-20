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

## Running

Configure server settings in `upload.cfg` by copying `upload.cfg.example` and 
replacing the variables with actual values.

A `gros-uploader.service` file is provided for installing as a systemd service. 
One can also use the `upload-session.sh` file to start the service within 
a GNOME keyring context with pre-set virtual environments, or directly use the 
`python upload.py` script to run the server. The script takes various options 
that can be reviewed by using the `--help` argument, including debugging 
instances.
