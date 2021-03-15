# @digitalbazaar/ezcap-express Changelog

## 2.0.0 - TBD

### Added
- Add optional `onError` handler for customizable error handling.

### Changed
- **BREAKING**: Replace `expectedTarget` parameter with `getExpectedTarget`.
  `getExpectedTarget` is an async function used to return the expected
  target(s) for the invoked capability.
- **BREAKING**: Remove the `logger` parameter. Errors may now be logged by the
  `onError` handler.

## 1.0.1 - 2021-03-02

### Fixed
- Use `http-signature-zcap-verify@4`.

## 1.0.0 - 2021-03-02

### Added
- Initial commit, see individual commits for history.
