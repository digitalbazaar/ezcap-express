/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import * as jsigs from 'jsonld-signatures';
import assert from 'assert-plus';
import asyncHandler from 'express-async-handler';
import {authorizeZcapInvocationAfterParse} from './authorize.js';
import {CapabilityDelegation} from '@digitalbazaar/zcap';

/**
 * Authorizes a request to submit a zcap revocation.
 *
 * This middleware is opinionated; it MUST be attached to an endpoint that
 * terminates in `/revocations/:revocationId`. This to enable the middleware to
 * automatically generate expected values for running zcap checks and to
 * support a common, conventional revocation API pattern.
 *
 * The pattern is in support of controlled objects on a service, aka
 * "service objects". Each object's controller is used to populate the root
 * zcap for the object's controller field. This root zcap has an invocation
 * target that matches the URL for the service object, aka its
 * "serviceObjectId".
 *
 * Therefore, any route that matches an invocation target for a root zcap for
 * a service SHOULD attach this middleware to:
 *
 * `<serviceObjectId>/revocations/:revocationId`.
 *
 * This middleware will compute `serviceObjectId` by combining the expected
 * host with the subpath from the request URL that occurs before
 * `/revocations/`. It assumes that the request URL will have this pattern
 * if the middleware code has been reached. IOW, `serviceObjectId` will
 * be set using:
 *
 * `https://<expectedHost>/<URL subpath before "/revocations/">`.
 *
 * Note: This middleware does NOT support having `/revocations/` appear
 * multiple places in the request URL.
 *
 * Attaching this middleware will enable any zcaps delegated from the service
 * object's root zcap to be revoked without having to issue an additional zcap
 * to use the revocation endpoint. This middleware makes that possible by
 * supporting the invocation of a dynamically generated root zcap with an
 * invocation target of:
 *
 * `<serviceObjectId>/revocations/:revocationId`.
 *
 * This middleware will set the `controller` of this root zcap to all
 * controllers in the to-be-revoked zcap's delegation chain, permitting any
 * participant to revoke it. An error will be thrown prior to populating this
 * `controller` field if the root zcap in the to-be-revoked zcap's chain does
 * not have `<serviceObjectId>` as its invocation target (or a prefix of it).
 * This ensures that the only zcaps that have been delegated from a root zcap
 * using the service object's ID as part of its invocation target can be
 * revoked at its `/revocations` route, i.e., other zcaps intended for other
 * service objects -- or entirely other services -- cannot be revoked via this
 * middleware.
 *
 * This middleware will automatically generate two sets of expects values: one
 * for checking the invocation to revoke a capability and one for verifying the
 * delegation chain of the capability that is to be revoked. Only the expected
 * host value can and must be given as a parameter.
 *
 * The expected values for checking the capability invocation will be:
 *
 * host: `<expectedHost>`,
 * rootInvocationTarget: [
 *   // root zcap with this target, RZ1, can be delegated w/target attenuation
 *   // to allow delegates to revoke any zcap, Z1, with RZ1 as the root in its
 *   // chain, even if the delegate is not a controller in Z1's chain
 *   `<serviceObjectId>`,
 *   // root zcap that this target, RZ2, can be used to revoke a zcap, Z2,
 *   // with an "id" of `revocationId`; RZ2's controller will be populated
 *   // using all controllers from Z2's chain, enabling any controller in that
 *   // zcap's chain to invoke RZ2 to revoke Z2
 *   `<serviceObjectId>/revocations/<revocationId>`,
 * ],
 * action: 'write'
 * .
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.documentLoader - Document loader used to load
 *   DID Documents, capability documents, and JSON-LD Contexts.
 * @param {string} options.expectedHost - The expected host header value
 *   when checking the zcap invocation.
 * @param {Function} options.getRootController - Used to get the controller
 *   of the root capability for the service object.
 * @param {Function<Promise>} options.getVerifier - An async function to
 *   call to get a verifier and verification method for the key ID.
 * @param {Function} [options.inspectCapabilityChain] - A function that can
 *   inspect a capability chain, e.g., to check for revocations; it will be
 *   used when verifying the invocation and the delegation chain for the
 *   to-be-revoked capability.
 * @param {Function} [options.onError] - An error handler handler for
 *   customizable error handling.
 * @param {object} options.suiteFactory - A factory for creating the
 *   supported suite(s) to use when verifying zcap delegation chains; this is
 *   different from `getVerifier` which is used to produce a verifier for
 *   verifying HTTP signatures used to invoke zcaps.
 *
 * @returns {Function} Returns an Express.js style middleware route handler.
 */
export function authorizeZcapRevocation({
  documentLoader, expectedHost, getRootController, getVerifier,
  inspectCapabilityChain, onError, suiteFactory
}) {
  // other middleware created below checks other params
  assert.string(expectedHost, 'options.expectedHost');

  /* Note: Here we wrap `getRootController` to support the aforementioned
  zcap-specific root zcap. This will be used for checking both the invocation
  and the revocation, though the revocation has an additional check below to
  ensure that the submitted revocation's chain has a root zcap with an
  acceptable invocation target. See the note below in
  `getRevocationRootController`. */
  getRootController = _wrapGetRootController({expectedHost, getRootController});

  // computes expected values for the invocation
  async function getExpectedValues({req}) {
    const serviceObjectId = _parseServiceObjectId({req, expectedHost});
    const {revocationId} = req.params;
    return {
      host: expectedHost,
      rootInvocationTarget: [
        serviceObjectId,
        `${serviceObjectId}/revocations/${encodeURIComponent(revocationId)}`
      ]
    };
  }

  async function getRevocationRootController(
    {req, rootCapabilityId, rootInvocationTarget}) {
    /* Note: This check prevents the client from successfully submitting
    revocations for unrelated service objects or services that could then use
    update storage in a revocation database. */
    const serviceObjectId = _parseServiceObjectId({req, expectedHost});
    if(!(rootInvocationTarget === serviceObjectId ||
      rootInvocationTarget.startsWith(`${serviceObjectId}/`))) {
      const error = new Error(
        `The root capability from the revocation's delegation chain must ` +
        `have an invocation target that starts with "${serviceObjectId}".`);
      error.name = 'NotAllowedError';
      error.httpStatusCode = 403;
      throw error;
    }
    return getRootController({req, rootCapabilityId, rootInvocationTarget});
  }

  return [
    asyncHandler(async function(req, res, next) {
      // ensure middleware is attached to opinionated route
      if(!req.originalUrl.includes('/revocations/') ||
        !req.params.revocationId) {
        const error = new Error(
          'Revocation middleware must be attached to a route ending in ' +
          '"/revocations/:revocationId".');
        error.httpStatusCode = 500;
        return helpers.handleError({res, error, onError});
      }
      // proceed to next middleware on next tick to prevent subsequent
      // middleware from potentially throwing here
      process.nextTick(next);
    }),
    helpers.createExpectationMiddleware({getExpectedValues, onError}),
    createCheckRevocationMiddleware({
      documentLoader, getRootController: getRevocationRootController,
      inspectCapabilityChain, onError, suiteFactory
    }),
    authorizeZcapInvocationAfterParse({
      // target attenuation is always allowed on this endpoint
      allowTargetAttenuation: true,
      documentLoader, getRootController, getVerifier,
      inspectCapabilityChain, onError, suiteFactory
    })
  ];
}

function createCheckRevocationMiddleware({
  documentLoader, getRootController, inspectCapabilityChain,
  onError, suiteFactory
}) {
  return asyncHandler(async function verifyRevocation(req, res, next) {
    const {body: capability} = req;

    // early-disallow revocation of root zcaps
    if(capability.id.startsWith(helpers.ZCAP_ROOT_PREFIX)) {
      const error = new Error('A root capability cannot be revoked.');
      error.name = 'NotAllowedError';
      error.httpStatusCode = 400;
      return helpers.handleError({res, error, onError});
    }

    // verify CapabilityDelegation
    let delegator;
    const capture = {};
    const chainControllers = [];
    try {
      const results = await _verifyDelegation({
        req,
        capability,
        documentLoader: helpers.createRootCapabilityLoader({
          documentLoader, getRootController, req
        }),
        inspectCapabilityChain: _captureChainControllers({
          inspectCapabilityChain,
          chainControllers,
          capture
        }),
        suiteFactory
      });
      ({delegator} = results[0].purposeResult);
      delegator = delegator.id || delegator;
    } catch(e) {
      const error = new Error('The provided capability delegation is invalid.');
      error.name = 'DataError';
      error.cause = e;
      error.httpStatusCode = 400;
      return helpers.handleError({res, error, onError});
    }

    const {capabilityChain} = capture;
    req.zcapRevocation = {delegator, capabilityChain, chainControllers};

    // proceed to next middleware on next tick to prevent subsequent
    // middleware from potentially throwing here
    process.nextTick(next);
  });
}

async function _verifyDelegation({
  req, capability, documentLoader, inspectCapabilityChain, suiteFactory
}) {
  // the expected values for the invocation are the same as those for checking
  // the revocation delegation chain per the reasoning given in notes above
  const {expectedRootCapability} = req.ezcap;
  /* Note: We build the `expectedRootCapability` for the revoked capability
  from the capability invocation expected values here. This is ok because the
  revocation middleware feature presumes that the only zcaps that may be
  revoked using it are rooted in the same authority... FIXME */
  const {verified, error, results} = await jsigs.verify(capability, {
    documentLoader,
    purpose: new CapabilityDelegation({
      /* Note: Path-based target attenuation must always be true to support the
      convention described above. This is not a security problem even if the
      to-be-revoked zcap cannot be invoked (because the invocation endpoint
      doesn't allow such attenuation). It just means zcaps that can be
      delegated with attenuation rules that aren't supported by the invocation
      endpoint can still be revoked. */
      allowTargetAttenuation: true,
      expectedRootCapability,
      inspectCapabilityChain,
      suite: await suiteFactory({req})
    }),
    suite: await suiteFactory({req})
  });
  if(!verified) {
    throw error;
  }
  return results;
}

function _wrapGetRootController({expectedHost, getRootController}) {
  return async function _getRootController({
    req, rootCapabilityId, rootInvocationTarget
  }) {
    const serviceObjectId = _parseServiceObjectId({req, expectedHost});
    const {revocationId} = req.params;
    const zcapSpecificRootTarget =
      `${serviceObjectId}/revocations/${encodeURIComponent(revocationId)}`;

    // if `rootInvocationTarget` doesn't match the zcap-specific root
    // invocation target, then use user-provided `getRootController` to provide
    // the controller
    if(rootInvocationTarget !== zcapSpecificRootTarget) {
      return getRootController({req, rootCapabilityId, rootInvocationTarget});
    }

    /* Note: If the root invocation target is a zcap-specific revocation
    endpoint, we use all zcap controllers from the to-be-revoked zcap's chain
    as the root controller. This applies to populating the controller for the
    root zcap in the invoked zcap's chain and for the root zcap in the
    to-be-revoked zcap's chain.

    This approach allows any party that has delegated a zcap or received one
    (where the root zcap includes `serviceObjectId` as a prefix in its
    invocation target) to be able to send it for revocation. Other code
    (in the revocation route handler) will confirm that the delegation is
    proper and the zcap from which it was delegated has not itself been
    revoked.

    As an example, if the delegation chain is:

    root -> A -> B

    Any zcap controller in the chain of B may invoke a root zcap with an
    `invocationTarget` of `<baseUrl>/revocations/<ID of B>` (and an ID of
    `urn:zcap:root:encodeURIComponent(<baseUrl>/revocations/<ID of B>)`). This
    means that `root`, `A`, or `B` may revoke `B`.

    As long no other zcap in the chain of `B` (e.g., `A`) has already been
    revoked, then `B` will be revoked and stored as a revocation (storage must
    be done via custom code after this middleware) until `B` expires. */

    // use all `chainControllers`
    // presumes `verifyCapabilityDelegation` middleware already called
    return req.zcapRevocation.chainControllers;
  };
}

function _captureChainControllers({
  inspectCapabilityChain, chainControllers, capture
}) {
  return async function _inspectCapabilityChain(chainDetails) {
    // collect every controller in the chain
    const {capabilityChain} = chainDetails;
    capture.capabilityChain = capabilityChain;
    for(const capability of capabilityChain.values()) {
      chainControllers.push(..._getCapabilityControllers({capability}));
    }
    return inspectCapabilityChain(chainDetails);
  };
}

function _getCapabilityControllers({capability}) {
  const {controller} = capability;
  return Array.isArray(controller) ? controller : [controller];
}

function _parseServiceObjectId({req, expectedHost}) {
  // `serviceObjectId` is full URL prior to `/revocations/`
  const idx = req.originalUrl.indexOf('/revocations/');
  const path = req.originalUrl.substring(0, idx);
  return `https://${expectedHost}${path}`;
}
