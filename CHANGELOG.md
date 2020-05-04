# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [Unreleased]



## [1.3] - 2020-05-04

### Added

- Changelog

### Changed

- Default server certificate path
- Location of temporary run directory (for client key and certificate)
- Fix temporary run directory permissions
- Fix logger deprecation warnings


## [1.2.1] - 2020-05-03

### Added

- `--verbose` command-line argument

### Changed

- Default logging severity to *info*


## [1.2] - 2020-04-24

### Added

- Compatibility with msgpack >= 1.0

### Changed

- Fixed tier-down of monitor socket
- Update documentation and license
- Improve error messages


## [1.1.2] - 2020-04-16

### Changed

- Default location of public key


## [1.1.1] - 2020-01-24

### Changed

- Add support files for distribution


## [1.1] - 2019-11-21

### Changed

- `--ipset` command-line argument
- License file


## [1.0] - 2017-07-17

### Changed

- Initial release
- Prototype moved from DynFW repository
- Refactoring

### Added

- Monitor socket to detect handshake failures
