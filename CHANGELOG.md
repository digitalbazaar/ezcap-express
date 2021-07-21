# @digitalbazaar/ezcap-express Changelog

## 4.1.1 - 2021-07-xx

### Changed
- Updated dependencies.

## 4.1.0 - 2021-07-11

### Changed
- Updated http-signature-zcap-verify to 8.1.x to bring in optimizations
  for controllers that use DID Documents.

## 4.0.1 - 2021-07-10

### Fixed
- Fix http-signature-zcap-verify dependency to use 8.x to function
  properly with updated ed25519 libs.

## 4.0.0 - 2021-07-10

### Changed
- **BREAKING**: Updated to use `@digitalbazaar/ed25519-signature-2020` 3.x
  and related libraries. These changes include breaking fixes to key
  formats.

## 3.4.2 - 2021-07-10

### Fixed
- Fix bug with erroneously detecting request bodies. Some body
  parsing middleware for express/connect (e.g., the main body-parser
  npm package) will set a request body to an empty object even when
  no body is present. This previously caused an error to be thrown
  because no body digest header was present. The code has been updated
  to check for http body headers per the spec now (instead of trusting
  the `req.body` value) and it will set the `req.body` value to
  `undefined` if it is not present.

## 3.4.1 - 2021-07-10

### Fixed
- Fix error handling bugs. Http signature errors thrown by the
  middleware created via `authorizeZcapInvocation` will now be
  properly passed to the `onError` handler.

## 3.4.0 - 2021-06-28

### Added
- Add missing `allowTargetAttenuation` option that defaults to `true`
  to support RESTful-based attenuated delegation as the documentation
  describes.

## 3.3.0 - 2021-05-19

### Added
- Verify HTTP "digest" header when a "content-type" header or body is present.

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
