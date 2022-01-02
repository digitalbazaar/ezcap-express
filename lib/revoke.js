/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import asyncHandler from 'express-async-handler';
import {CapabilityDelegation} from '@digitalbazaar/zcapld';
import * as helpers from './helpers.js';
import * as jsigs from 'jsonld-signatures';
import {authorizeZcapInvocationAfterParse} from './authorize.js';

/**
 * Authorizes a request to submit a zcap revocation.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.documentLoader - Document loader used to load
 *   DID Documents, capability documents, and JSON-LD Contexts.
 * @param {string} options.expectedHost - The expected host for the invoked
 *   capability.
 * @param {Function} options.getExpectedTarget - Used to return the expected
 *   target(s) for the invoked capability.
 * @param {Function} options.getRootController - Used to get the root
 *   capability controller for the given root capability ID.
 * @param {Function} options.suiteFactory - A factory for creating the
 *   supported suite(s) to use when verifying digital signatures.
 * @param {boolean} [options.allowTargetAttenuation=true] - Allow the
 *   invocationTarget of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 * @param {Function} [options.getExpectedRootCapabilityId] - Used to return the
 *   expected root capability identifiers for the expected targets.
 * @param {Function} [options.inspectCapabilityChain] - A function that can
 *   inspect a capability chain, e.g., to check for revocations.
 * @param {Function} [options.onError] - An error handler handler for
 *   customizable error handling.
 *
 * @returns {Function} Returns an Express.js style middleware route handler.
 */
export function authorizeZcapRevocation({
  documentLoader, expectedHost, getExpectedTarget, getRootController,
  allowTargetAttenuation = true, getExpectedRootCapabilityId,
  inspectCapabilityChain, onError, suiteFactory
}) {
  assert.func(suiteFactory, 'options.suiteFactory');

  // expected action is always `write` for submitting a revocation
  const expectedAction = 'write';
  return [
    helpers.createExpectationMiddleware({
      expectedHost, expectedAction, getExpectedTarget,
      getExpectedRootCapabilityId, onError
    }),
    // FIXME: need to include an `expectedRootCapability` for the *zcap to
    // be revoked* that is separate from the `expectedRootCapability` for
    // zcap that is invoked to do the revocation... and perhaps may need
    // to specify a different `_getRootController` to allow for
    // any root zcap provided that the controller is `X`
    // FIXME:
    // note that presently this code depends on `getRootController` only
    // resolving a root zcap that matches the request URL -- this ensures that
    // only zcaps that are related to the request URL can be revoked at it --
    // but this is via indirectly failing to verify the capability delegation;
    // determine if this is ok because it's hidden behind the main function or
    // if there should be some extra check / enforcement somewhere; i.e., the
    // revocation endpoint will only verify a delegation that is rooted in
    // a zcap with a root controller for the related object (based on the URL)
    // ... new zcapld version may help here
    verifyCapabilityDelegation({
      documentLoader, getRootController, suiteFactory, inspectCapabilityChain,
      onError
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
  documentLoader, getRootController, inspectCapabilityChain, suiteFactory,
  onError
}) {
  return asyncHandler(async function getDelegator(req, res, next) {
    const {
      expectedAction, expectedHost, expectedTarget, expectedRootCapability
    } = req.ezcap;

    const {body: capability} = req;

    // early-disallow revocation of root zcaps that follow ID convention
    if(capability.id.startsWith(helpers.ZCAP_ROOT_PREFIX)) {
      const error = new Error('A root capability cannot be revoked.');
      error.name = 'NotAllowedError';
      return helpers.handleError({error, onError});
    }

    // verify CapabilityDelegation
    let delegator;
    const chainControllers = [];
    try {
      const results = await _verifyDelegation({
        capability,
        documentLoader: helpers.wrappedDocumentLoader({
          req, documentLoader, expectedHost, expectedTarget, expectedAction,
          getRootController
        }),
        expectedRootCapability,
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
      return helpers.handleError({error, onError});
    }

    req.zcapRevocation = {delegator, chainControllers};

    // proceed to next middleware on next tick to prevent subsequent
    // middleware from potentially throwing here
    process.nextTick(next);
  });
}

async function _verifyDelegation({
  req, capability, documentLoader,
  expectedRootCapability, inspectCapabilityChain, suiteFactory
}) {
  const {verified, error, results} = await jsigs.verify(capability, {
    suite: await suiteFactory({req}),
    purpose: new CapabilityDelegation({
      allowTargetAttenuation: true,
      expectedRootCapability,
      inspectCapabilityChain,
      suite: await suiteFactory({req})
    }),
    documentLoader
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

    // FIXME: make sure that not just anyone can send a zcap to fill up
    // revocation storage ... any zcap to be revoked needs to itself have
    // an expected root zcap that, ultimately, has the same root controller
    // as the service object; better clarity in params passed to the authz
    // middleware for revocation endpoints may help

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
  const {controller, id} = capability;
  const result = controller || id;
  if(!result) {
    return [];
  }
  return Array.isArray(result) ? result : [result];
}
