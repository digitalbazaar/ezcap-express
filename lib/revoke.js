/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import * as jsigs from 'jsonld-signatures';
import assert from 'assert-plus';
import asyncHandler from 'express-async-handler';
import {authorizeZcapInvocationAfterParse} from './authorize.js';
import {CapabilityDelegation} from '@digitalbazaar/zcapld';

/**
 * Authorizes a request to submit a zcap revocation.
 *
 * This middleware is opinionated; it MUST be attached to an endpoint that
 * terminates in `/revocations/:zcapId`. This to enable the middleware to
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
 * `<serviceObjectId>/revocations/:zcapId`
 *
 * This middleware will compute `serviceObjectId` by combining the expected
 * host with the subpath from the request URL that occurs before
 * `/revocations/`. It *assumes* that the request URL will have this pattern
 * if the middleware code has been reached. IOW, `serviceObjectId` will
 * be set using:
 *
 * `https://<expectedHost>/<URL subpath before "/revocations/">`
 *
 * Attaching this middleware will enable any zcaps delegated from the service
 * object's root zcap to be revoked without having to issue an additional zcap
 * to use the revocation endpoint. This middleware makes that possible by
 * supporting the invocation of a dynamically generated root zcap with an
 * invocation target of:
 *
 * `<serviceObjectId>/revocations/:zcapId`
 *
 * This middleware will set the `controller` of this root zcap to all
 * controllers in the to-be-revoked zcap's delegation chain, permitting any
 * participant to revoke it. An error will be thrown prior to populating this
 * `controller` field if the root zcap in the to-be-revoked zcap's chain does
 * not have `<serviceObjectId>` as its invocation target. This ensures that
 * the only zcaps that have been delegated from the service object's root zcap
 * can be revoked at its `/revocations` route.
 *
 * This middleware will automatically generate two sets of expects values: one
 * for checking the invocation to revoke a capability and one for verifying the
 * delegation chain of the capability that is to be revoked. Only the expected
 * host value can and must be given as a parameter.
 *
 * This middleware he `serviceObjectId` will be determined by
 *
 * The expected values for checking the capability invocation will be:
 *
 * host: `<expectedHost>`
 * rootInvocationTarget: [
 *   // root zcap with this target, RZ1, can be delegated w/target attenuation
 *   // to allow delegates to revoke any zcap, Z1, with RZ1 as the root in its
 *   // chain, even if the delegate is not a controller in Z1's chain
 *   `<serviceObjectId>`,
 *   // root zcap that this target, RZ2, can be used to revoke a zcap, Z2,
 *   // with an "id" of `zcapId`; RZ2's controller will be populated using all
 *   // controllers from Z2's chain, enabling any controller in that zcap's
 *   // chain to invoke RZ2 to revoke Z2
 *   `<serviceObjectId>/revocations/<zcapId>`,
 * ],
 * action: 'write'
 *
 * @typedef VerifyRevocationOptions
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.documentLoader - Document loader used to load
 *   DID Documents, capability documents, and JSON-LD Contexts.
 * @param {string} options.expectedHost - The expected host header value
 *   when checking the zcap invocation.
 * @param {Function} options.getRootController - Used to get the controller
 *   of the root capability for the service object.
 * @param {Function} options.suiteFactory - A factory for creating the
 *   supported suite(s) to use when verifying digital signatures.
 * @param {Function} [options.inspectCapabilityChain] - A function that can
 *   inspect a capability chain, e.g., to check for revocations; it will be
 *   used when verifying the invocation and the delegation chain for the
 *   to-be-revoked capability.
 * @param {Function} [options.onError] - An error handler handler for
 *   customizable error handling.
 *
 * @returns {Function} Returns an Express.js style middleware route handler.
 */
export function authorizeZcapRevocation({
  documentLoader, expectedHost, getRootController,
  inspectCapabilityChain, onError, suiteFactory
}) {
  // `helpers.createExpectationMiddleware` handles type checks on other params
  assert.func(suiteFactory, 'options.suiteFactory');

  return [
    // ensure middleware is attached to opinionated route
    function(req, res, next) {
      if(!req.url.indexOf('/revocations/') || !req.params.zcapId) {
        const error = new Error(
          'Revocation middleware must be attached to "/revocations/:zcapId" ' +
          'route.');
        error.httpStatusCode = 500;
        return next(error);
      }
      next();
    },
    helpers.createExpectationMiddleware({getExpectedValues, onError}),
    // FIXME: need to include an `expectedRootCapability` for the *zcap to
    // be revoked* that is separate from the `expectedRootCapability` for
    // zcap that is invoked to do the revocation... and perhaps may need
    // to specify a different `_getRootController` to allow for
    // any root zcap provided that the controller is `X`
    verifyCapabilityDelegation({
      documentLoader, verifyRevocationOptions, suiteFactory, onError
    }),
    authorizeZcapInvocationAfterParse({
      documentLoader,
      getRootController: _createGetRevocationRootController(
        {getRootController}),
      suiteFactory, allowTargetAttenuation, inspectCapabilityChain, onError
    })
  ];
}

function verifyCapabilityDelegation({
  documentLoader, verifyRevocationOptions, suiteFactory, onError
}) {
  return asyncHandler(async function getDelegator(req, res, next) {
    const {body: capability} = req;

    // early-disallow revocation of root zcaps
    if(capability.id.startsWith(helpers.ZCAP_ROOT_PREFIX)) {
      const error = new Error('A root capability cannot be revoked.');
      error.name = 'NotAllowedError';
      error.httpStatusCode = 400;
      return helpers.handleError({res, error, onError});
    }

    // get expected values for the revocation
    const {
      getExpectedValues, getRootController,
      allowTargetAttenuation, inspectCapabilityChain
    } = verifyRevocationOptions;
    // FIXME: it seems we don't need to parameterize `getExpectedValues`
    //try {
      // FIXME: `expectedHost` MUST be the same
      // ... should we force expectedRootCapability as well?
      //const expected = await getExpectedValues({req});
    //}
    // FIXME: it should also be the case that the same `getRootController`
    // can be used ... so we can avoid having to pass two... a note in the
    // docs should indicate that the same function will be used for both the
    // invoked zcap and the to-be-revoked zcap

    // verify CapabilityDelegation
    let delegator;
    const chainControllers = [];
    try {
      const results = await _verifyDelegation({
        capability,
        documentLoader: helpers.createRootCapabilityLoader({
          documentLoader, getRootController, req
        }),
        inspectCapabilityChain: _captureChainControllers({
          inspectCapabilityChain,
          chainControllers
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

    req.zcapRevocation = {delegator, chainControllers};

    // proceed to next middleware on next tick to prevent subsequent
    // middleware from potentially throwing here
    process.nextTick(next);
  });
}

async function _verifyDelegation({
  req, capability, documentLoader, inspectCapabilityChain, suiteFactory
}) {
  // FIXME: the `expectedRootCapability` for the delegation needn't be
  // the same as the one used in the invocation; we may want a separate
  // function for checking / providing acceptable root zcaps for the
  // zcap that is being revoked?
  const {expectedRootCapability} = req.ezcap;
  /* Note: We build the `expectedRootCapability` for the revoked capability
  from the capability invocation expected values here. This is ok because the
  revocation middleware feature presumes that the only zcaps that may be
  revoked using it are rooted in the same authority... FIXME


  const {verified, error, results} = await jsigs.verify(capability, {
    documentLoader,
    purpose: new CapabilityDelegation({
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

function _createGetRevocationRootController({
  getRootController, revocationsSubPath = '/revocations/'
}) {
  return async function _getRevocationRootController({
    req, rootCapabilityId, rootInvocationTarget
  }) {
    // if `revocations` is not in the root invocation target, then defer to
    // `getRootController` to try and provide the root controller
    if(!rootInvocationTarget.includes(revocationsSubPath)) {
      return getRootController({req, rootCapabilityId, rootInvocationTarget});
    }

    /* Note: If the invocation target is a zcap-specific revocation endpoint,
      we use all zcap controllers from the submitted zcap's chain as the root
      controller value for the target.
      This approach allows any party that has delegated a zcap or received one
      to be able to send it for revocation. Subsequent code (in the revocation
      route handler) will confirm that the delegation is proper and the zcap
      from which it was delegated has not itself been revoked.
      To be clear, if the delegation chain is:
      root -> A -> B
      Any zcap controller in the chain of B may invoke a root zcap with a
      `target` of `<baseUrl>/revocations/<ID of B>` (and an ID of
      `urn:zcap:root:encodeURIComponent(<baseUrl>/revocations/<ID of B>)`). This
      means that `root`, `A`, or `B` may revoke `B`.
      As long no other zcap in the chain of `B` (e.g., `A`) has already been
      revoked, then `B` will be revoked and stored as a revocation until `B`
      expires. */

    // FIXME: since the controllers are determined by the zcap that is
    // submitted, there needs to be an additional check to ensure that the
    // zcap to be revoked has a root zcap with an invocation target that
    // is a prefix of the revocation URL -- or similar, to prevent zcaps
    // for unrelated services from being stored... may need to force the
    // expected `rootInvocationTarget` to be a particular value rather than
    // letting the middleware creator specify it; maybe acceptable options
    // are always: `<baseUrl>`, `<baseUrl>/revocations`, and
    // `<baseUrl>/revocations/<ID of B>`
    // FIXME: for the last option, ensure that `<baseUrl>/revocations/<ID of B>`

    // use all `chainControllers`
    // presumes `verifyCapabilityDelegation` middleware already called
    return req.zcapRevocation.chainControllers;
  };
}

function _captureChainControllers({inspectCapabilityChain, chainControllers}) {
  return async function _inspectCapabilityChain(chainDetails) {
    // collect every controller in the chain
    const {capabilityChain} = chainDetails;
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

function _assertVerifyRevocationOptions({verifyRevocationOptions}) {
  const baseName = 'options.verifyRevocationOptions';
  assert.object(verifyRevocationOptions, baseName);
  const {
    getExpectedValues,
    getRootController,
    allowTargetAttenuation,
    inspectCapabilityChain
  } = verifyRevocationOptions;
  assert.func(getExpectedValues, `${baseName}.getExpectedValues`);
  assert.func(getRootController, `${baseName}.getRootController`);
  assert.optionalBoolean(
    allowTargetAttenuation, `${baseName}.allowTargetAttenuation`);
  assert.optionalFunc(
    inspectCapabilityChain, `${baseName}.inspectCapabilityChain`);
}

// documentation typedefs

/**
 * @typedef GetExpectedValues - See helpers.js.
 */

/**
 * @typedef VerifyRevocationOptions
 * @param {GetExpectedValues} options.getExpectedValues - Used to get the
 *   expected values when checking the zcap invocation.
 * @param {Function} getRootController - Used to get the controller of the root
 *   capability for to-be-revoked capability's chain.
 * @param {boolean} [options.allowTargetAttenuation=true] - Allow the
 *   invocationTarget of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 * @param {Function} [options.inspectCapabilityChain] - A function that can
 *   inspect a capability chain, e.g., to check for revocations.
 */
