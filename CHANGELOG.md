# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).



## [1.4.0] - 2020-08-06
### Added
- Argument `--renew` that automatically receives latest version of server
  certificate on client startup
- Argument `--cert-url` to specify URL used to get server's certificate when
  `--renew` is used


## [1.3.1] - 2020-06-09
### Added
- Filter for IPv4 addresses (invalid ones are dropped)


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
