# @digitalbazaar/ezcap-express Changelog

## 5.1.0 - 2022-01-14

### Added
- Use zcap@7.1 and http-signature-zcap-verify@10.1 to include
  `dereferencedChain` in verification results and `req.zcap`.

## 5.0.1 - 2022-01-11

### Changed
- Update dependencies.

## 5.0.0 - 2022-01-11

### Added
- Add optional parameters `maxChainLength`, `maxDelegationTtl`, and
  `maxTimestampDelta` to allow for more fine grained control. These parameters
  all have defaults in `@digitalbazaar/zcap` that could previously not be set
  to other values at this layer.
- **BREAKING**: Add required `getVerifier` async function parameter. The
  function will be passed `{keyId, documentLoader}` to verify an HTTP signature
  and must return `{verifier, verificationMethod}`. The `verifier` object must
  have a `verify` function that takes `{data, signature}` and returns a
  boolean indicating whether the `Uint8Array` `signature` is verified
  against the `Uint8Array` `data` -- or throws an error if there is a reason
  the cryptographic signature verification check cannot be run.
- Include `capabilityChain` in `req.zcapRevocation` when using revocation
  middleware. This property includes the entire dereferenced chain.

### Changed
- **BREAKING**: Replace broken-out expected value parameters (e.g.,
  `expectedHost`, `expectedTarget`), including duplicative / optional
  parameters (e.g., `expectedAction`, `getExpectedAction`) with a single
  async function `getExpectedValues({req})` that returns all required (and any
  optional) expected values. This removes some optionality and simplifies
  function signatures -- also allowing callers to decide how they want
  to provide this information (e.g., by calling individual functions from
  within `getExpectedValues` or whatever else).
- **BREAKING**: The `authorizeZcapRevocation` middleware may now only be used
  on routes ending in `/revocations/:revocationId`. The API params have also
  changed as the only expected value that is needed from the user is
  `expectedHost`. The rest of the expected values are hard coded according to
  a conventional pattern for supporting revocation of any zcaps delegated from
  a root capability for a service object. The service object's root capability
  MUST have an invocation target that matches the service object's URL (aka its
  "ID", `<serviceObjectId>`). So for the absolute URL:

  `<serviceObjectId>/revocations/:revocationId`

  A zcap can only be revoked using the middleware if its chain has a root
  zcap with an invocation target that is prefixed with `<serviceObjectId>`.
  The middleware will use the `expectedHost` value to construct the absolute
  URL.
- **BREAKING**: Require `suiteFactory` parameter, no default cryptosuites are
  included with this package to ensure it is decoupled from particular
  cryptosuites.

### Fixed
- **BREAKING**: HTTP status error codes have been fixed so that client errors
  will result in 4xx status codes instead of 5xx status codes.

### Remove
- **BREAKING**: Remove `getExpectedRootCapabilityId` as there have been no
  use cases that have needed it.
- **BREAKING**: Remove deprecated `suite` param, use `suiteFactory` instead.

## 4.5.0 - 2021-12-17

### Fixed
- Add `_createGetRevocationRootController` wrapper around
  `_getRevocationRootController` and pass `getRootController` to it.

### Added
- Add tests for `authorizeZcapRevocation`.

## 4.4.0 - 2021-12-15

### Added
- Add additional tests.

## 4.3.1 - 2021-12-13

### Fixed
- Fix `expectedAction` to be `write` for `DELETE` method.
- Throw error when no `expectedAction` is given for a given HTTP method and
  provide defaults for all common HTTP methods.

## 4.3.0 - 2021-12-10

### Added
- Allow any controller in a delegated zcap's chain to revoke it. This authority
  is inherent in delegation and is now reflected in code. This feature gives
  delegators more fine-grained control to revoke zcaps that they did not
  delegate directly but one of their delegates did, allowing them to stop
  specific zcap usage without having to revoke more of the chain. It also
  gives zcap controllers the ability to revoke their own zcaps (if desired)
  and adds a sanity check to prevent the revocation of root zcaps that use
  the `urn:zcap:root:` ID scheme.

## 4.2.0 - 2021-08-26

### Added
- Add `suiteFactory` parameter to middleware creation functions. A
  `suiteFactory` function should be passed and return the supported LD proof
  suite (or an array of supported LD proof suites) that is supported for
  authorizing zcap invocations and verifying capability chains.
- Add `authorizeZcapRevocation` middleware that can be attached to root
  container/object endpoints to enable revocation of zcaps that have been
  delegated to use them. This version assumes that the revocations endpoint
  will follow this RESTful format: `<rootObjectUrl>/revocations/<zcapId>`
  and that the body will be JSON and include a `capability` member with
  the zcap to revoke. Future versions may allow for greater flexibility.

### Changed
- Deprecate passing a `suite` to any middleware creation functions. Instead,
  `suiteFactory` should be passed. The next major version will remove `suite`.
  This approach allows this library to remove npm dependencies that provide
  cryptographic suites preventing this library from being affected when those
  dependencies need to change.

## 4.1.1 - 2021-07-21

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
