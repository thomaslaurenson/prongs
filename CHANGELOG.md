# Changelog

## 0.6.0 - 2026-09-16

### Added

- Show scan progress on stderr, suppressed when stderr is not a terminal
- Add a --debug flag reporting what was resolved and probed
- Complete scanner names and output formats in the shell

### Changed

- Send findings to stdout and everything else to stderr, so a redirected scan captures only findings
- Mark human-readable output with the standard [*] and [!] prefixes
- Stop a scan cleanly on Ctrl-C, exiting 130 without a message
- Reject --all together with --scanner, and a concurrency below one

### Fixed

- Point the release workflow at the gpipe action that exists, so a tagged release publishes
- Stop an unresponsive SSH host holding a worker for the rest of the scan
- Queue scan work as it runs rather than up front, so a large range no longer exhausts memory

### Updated

- Raise the minimum Go version to 1.27

## 0.5.0 - 2026-07-22

### Added

- Add insecure-http scanner detecting websites served over plaintext HTTP

### Fixed

- Correct the documented default for the accessible-rdp scanner

## 0.4.5 - 2026-07-22

### Updated

- Made target input for CLI clearer with more examples

## 0.4.4 - 2026-07-17

### Updated

- Package bump

## 0.4.3 - 2026-06-23

### Fixed

- Target parsing bug

### Changed

- Scan subcommand now separates `target` or `target-file`

## 0.4.2 - 2026-06-23

### Added

- Version subcommand

## 0.4.1 - 2026-06-17

### Fixed

- Parse target CIDR list and file bug

## 0.4.0 - 2026-05-27

### Added

- Full rewrite in golang

## 0.3.2 - 2026-03-03

### Fixed

- Fixed Docker run method and examples

## 0.3.1 - 2026-02-27

### Fixed

- Fixed Python package install method

## 0.3.0 - 2026-02-13

### Added

- Container release on ghcr.io

### Fixed

- Container image to use correct entrypoint

## 0.2.0 - 2026-01-07

### Added

- Support for `uv`
- Improved linting

### Changed

- Moved to `pyproject.toml`

### Fixed

- Timestamp and timezone issues

## 0.1.0 - 2025-04-11

### Added

- Scanners for SSH, RDP and DB
