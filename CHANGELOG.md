# @digitalbazaar/ezcap-express Changelog

## 3.3.0 - 2021-05-xx

### Added
- Verify http digest header when body/content-type is present.

## 3.2.0 - 2021-05-13

### Added
- Add ability to specify an `inspectCapabilityChain` hook.

## 3.1.0 - 2021-05-11

### Added
- Add optional `getExpectedAction({req})` hook to provide expected action
  based on, e.g., request body vs. HTTP method.

## 3.0.1 - 2021-04-06

### Fixed
- **BREAKING**: Change the default signature suite in `authorizeZcapInvocation`
  to `Ed25519Signature2020` (was `Ed25519Signature2018` before). This change
  should have been included in the 3.0 release.

### Changed
- Remove `jsonld-signatures` dependency.

## 3.0.0 - 2021-04-01

### Changed
- **BREAKING**: Use `http-signature-zcap-verify@5` which only supports
  `Ed25519Signature2020` proofs.

## 2.0.0 - 2021-03-29

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
