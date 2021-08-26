/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import asyncHandler from 'express-async-handler';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import * as helpers from './helpers.js';
import {parseSignatureHeader} from 'http-signature-header';
import {verifyHeaderValue} from '@digitalbazaar/http-digest-header';
import {verifyCapabilityInvocation} from 'http-signature-zcap-verify';

/**
 * Authorizes an incoming request.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.documentLoader - Document loader used to load
 *   DID Documents, capability documents, and JSON-LD Contexts.
 * @param {string} options.expectedHost - The expected host for the invoked
 *   capability.
 * @param {Function} options.getExpectedTarget - Used to return the expected
 *   target(s) for the invoked capability.
 * @param {Function} options.getRootController - Used to get the root capability
 *   controller for the given root capability ID.
 * @param {boolean} [options.allowTargetAttenuation=true] - Allow the
 *   invocationTarget of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 * @param {string} [options.expectedAction] - The expected action for the
 *   invoked capability; use this or `getExpectedAction`, not both.
 * @param {Function} [options.getExpectedAction] - Used to return the
 *   expected action for the invoked capability; use this or `expectedAction`,
 *   not both; if neither are provided, then the expected action will be
 *   determined based on the HTTP method from the request -- which is only safe
 *   provided that the handler code path is also determined based on the HTTP
 *   method in the request (i.e., typical method-based express/connect routing);
 *   if the handler code path is determined by some other means, e.g., the
 *   request body, then `getExpectedAction` MUST be used.
 * @param {Function} [options.getExpectedRootCapabilityId] - Used to return the
 *   expected root capability identifiers for the expected targets.
 * @param {Function} [options.inspectCapabilityChain] - A function that can
 *   inspect a capability chain, e.g., to check for revocations.
 * @param {Function} [options.onError] - An error handler handler for
 *   customizable error handling.
 * @param {object} [options.suite] - The expected cryptography suite to use when
 *   verifying digital signatures.
 *
 * @returns {Function} Returns an Express.js style middleware route handler.
 */
export function authorizeZcapInvocation({
  documentLoader, expectedHost, getExpectedTarget, getRootController,
  allowTargetAttenuation = true, expectedAction, getExpectedAction,
  getExpectedRootCapabilityId, inspectCapabilityChain,
  onError, suite = new Ed25519Signature2020()
} = {}) {
  // `helpers.createExpectationMiddleware` handles type checks on other params
  assert.func(documentLoader, 'options.documentLoader');
  assert.func(getRootController, 'options.getRootController');
  assert.optionalFunc(inspectCapabilityChain, 'options.inspectCapabilityChain');

  return [
    helpers.createExpectationMiddleware({
      expectedHost, expectedAction, getExpectedAction, getExpectedTarget,
      getExpectedRootCapabilityId, onError
    }),
    // FIXME: expose this middleware in `helpers` so it can be reused
    // in delegation.js
    asyncHandler(async (req, res, next) => {
      const {
        expectedAction, expectedRootCapability, expectedTarget,
        signature: {params: {keyId}}
      } = req.ezcap;

      // retrieves the root capability that was invoked
      async function getInvokedCapability({id}) {
        let rootCapabilityId;
        if(Array.isArray(expectedRootCapability)) {
          rootCapabilityId = expectedRootCapability.find(_id => id === _id);
        } else if(id === expectedRootCapability) {
          rootCapabilityId = expectedRootCapability;
        }
        if(!rootCapabilityId) {
          const error = new Error(
            `The given capability "${id}" is not an expected root ` +
            `capability "${expectedRootCapability}".`);
          error.details = {
            actual: id,
            expected: expectedRootCapability,
          };
          return helpers.handleError({error, onError});
        }
        return helpers.getRootCapability({
          getRootController, req, expectedHost, expectedTarget,
          expectedAction, rootCapabilityId
        });
      }

      // perform the capability invocation...
      // `originalUrl` must be used to support nested express routers
      const {originalUrl: url, method, headers} = req;
      const result = await verifyCapabilityInvocation({
        url,
        method,
        suite,
        headers,
        expectedHost,
        documentLoader: helpers.wrappedDocumentLoader({
          documentLoader,
          expectedAction,
          expectedHost,
          expectedTarget,
          getRootController,
          req,
        }),
        getInvokedCapability,
        expectedTarget,
        expectedAction,
        expectedRootCapability,
        inspectCapabilityChain,
        keyId,
        allowTargetAttenuation
      });

      // return HTTP 403 if verification fails
      if(!result.verified) {
        helpers.handleError({error: result.error, onError, throwError: false});
        return res.status(403).send();
      }

      // provide zcap verification results if verification succeeds
      req.zcap = result;

      // call `next` on the next tick to ensure the promise from this function
      // resolves and does not reject because some subsequent middleware throws
      // an error
      process.nextTick(next);
    })
  ];
}
