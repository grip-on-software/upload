# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) 
and we adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Unit tests added.

### Changed

- The entry point of the program is now a Python script `gros-upload` with 
  subcommands for upload server (`gros-upload server`) and keyring 
  authentication adjustments (`gros-upload auth`) after installation instead of 
  separate `upload.py` and `auth.py` files, respectively.

### Fixed

- When deleting a user from the keyring, the user must exist instead of the 
  other way around.
- When adding or modifying a user's password from the keyring, only ask for the 
  new password if the existence check succeeds.
- Import script will no longer attempt to copy the schema files from a dump if 
  the target directory does not exist.
- Server header now reports modules in decreasing order of significance, with 
  no versions specified outside debug.

## [0.0.3] - 2024-07-19

### Added

- Initial release of version as used during the GROS research project. 
  Previously, versions were rolling releases based on Git commits.

[Unreleased]: https://github.com/grip-on-software/upload/compare/v0.0.3...HEAD
[0.0.3]: https://github.com/grip-on-software/upload/releases/tag/v0.0.3
