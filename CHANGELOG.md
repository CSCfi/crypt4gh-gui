# Changelog
Format updates according to [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
Update version according to [Calendar Versioning](https://calver.org/).

Always place latest update on top.

## [Unreleased]

## [2024.02.2] - 2024-02-06

### Removed
- remove leading zero from calver in windows build only (merge commit)
- remove leading zero only from first instance, which is always the month number

## [2024.02.1] - 2024-02-06

### Changed
- make it possible to trigger buils using calver (merge commit)
- make it possible to trigger buils using calver

## [2024.02.0] - 2024-02-06

### Added
- add tox
- codeql track main

### Removed
- remove extra spaces

### Changed
- Update .gitlab-ci.yml file (merge commit)

## [v1.4.0] - 2023-07-04

### Added
- Add workflows for windows executable versioning and signing

### Changed
- Refactor version parsing

## [v1.3.3] - 2023-05-08

### Changed
- better fix for noconsole bug

### Fixed
- Fix windows noconsole bug


## [v1.3.2] - 2023-04-27

### Fixed
- Fix windows noconsole bug

## [v1.3.1] - 2023-04-20

### Changed
- compromise fix for windows build: display cmd behind gui app


## [v1.3.0] - 2023-02-22

### Fixed
- fix misses in syntax linting

### Changed
- switch to python 3.10

## [v1.3.0-rc0] - 2023-02-22

### Fixed
- address mypy issues
- fix misses in syntax linting
- fix deprecated syntax for set-output

### Changed
- switch to python 3.10

## [v1.2.1] - 2022-09-05

### Changed
- Bump crypt4gh from 1.5 to 1.6
- Bump pynacl from 1.4.0 to 1.5.0
- reformatted file for length

### Fixed
- fix mypy issues
- fix any window type

## [v1.2.0] - 2022-01-05

### Added
- add missing brackets to workflow file

### Changed
- correct artifact name
- fail_on_unmatched_files to true
- update error message
- update readme
- update activity log instructions
- update deprecated release action

### Removed
- remove deprecated key from workflow

## [v1.1.0] - 2021-07-15

### Added
- add requirements to release

### Changed
- better error description
- catch error on key password & overwritting existing key
- update crypt4gh support

### Fixed
- fix release install
- fix styles and add tox checks

## [sds-1.0.0] - 2021-06-17
## [sds-v0.1.0] - 2021-06-17
## [sds-v1.0.0] - 2021-06-17

### Added
- add setup.py
- add sds release file
- add github action for release on tag

### Changed
- confirm password on generation by typing it twice
- Create crypt4SDS_gui.py
- Create dependabot.yml
- Create codeql-analysis.yml
- try to make build work and update gh actions

### Fixed
- fix crypt4gh
- fix name for installer source

## [feature/icon] - 2020-04-22
## [master] - 2020-04-22
## 1.0.0 - 2020-04-22

### Added
- add os-dependent layout config
- add license

### Changed
- display module errors in activity log 
- edit file label
- make sender public key optional for file decryption
- rename window title
- update readme

[Unreleased]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/2024.02.2...HEAD
[2024.02.2]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/2024.02.1...2024.02.2
[2024.02.1]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/2024.02.0...2024.02.1
[2024.02.0]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/v1.4.0...2024.02.0
[v1.4.0]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/v1.3.3...v1.4.0
[v1.3.3]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/v1.3.2...v1.3.3
[v1.3.2]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/v1.3.1...v1.3.2
[v1.3.1]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/v1.3.0...v1.3.1
[v1.3.0]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/v1.3.0-rc0...v1.3.0
[v1.3.0-rc0]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/v1.2.1...v1.3.0-rc0
[v1.2.1]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/v1.2.0...v1.2.1
[v1.2.0]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/v1.1.0...v1.2.0
[v1.1.0]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/sds-1.0.0...v1.1.0
[sds-1.0.0]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/sds-v0.1.0...sds-1.0.0
[sds-v0.1.0]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/sds-v1.0.0...sds-v0.1.0
[sds-v1.0.0]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/feature/icon...sds-v1.0.0
[feature/icon]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/master...feature/icon
[master]: https://gitlab.ci.csc.fi:10022/sds-dev/crypt4gh-gui/compare/1.0.0...master
