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

const {ZCAP_ROOT_PREFIX} = helpers;

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
 * @returns {Function} Returns an Express.js middleware route handler.
 */
export function authorizeZcapInvocation({
  documentLoader, expectedHost, getExpectedTarget, getRootController,
  allowTargetAttenuation = true, expectedAction, getExpectedAction,
  getExpectedRootCapabilityId, inspectCapabilityChain,
  onError, suite = new Ed25519Signature2020()
} = {}) {
  assert.func(documentLoader, 'options.documentLoader');
  assert.optionalString(expectedAction, 'options.expectedAction');
  assert.optionalFunc(
    getExpectedAction, 'options.getExpectedAction');
  assert.string(expectedHost, 'options.expectedHost');
  assert.func(getExpectedTarget, 'options.getExpectedTarget');
  assert.func(getRootController, 'options.getRootController');
  assert.optionalFunc(
    getExpectedRootCapabilityId, 'options.getExpectedRootCapabilityId');
  assert.optionalFunc(inspectCapabilityChain, 'options.inspectCapabilityChain');
  assert.optionalFunc(onError, 'options.onError');

  if(getExpectedAction && expectedAction !== undefined) {
    throw new Error('Use "getExpectedAction" or "expectedAction", not both.');
  }

  return asyncHandler(async (req, res, next) => {
    // originalUrl must be used to support nested express routers
    const {originalUrl: url, method, headers} = req;
    let params;
    try {
      ({params} = parseSignatureHeader(headers.authorization));
    } catch(e) {
      const error = new Error('Missing or invalid "authorization" header.');
      error.name = 'DataError';
      error.cause = e;
      return helpers.handleError({error, onError});
    }
    const {keyId} = params;

    // if body is present, ensure header digest value matches digest of body
    if(helpers.hasBody({req})) {
      const {digest: expectedDigest} = headers;
      if(!expectedDigest) {
        const error = new Error(
          'A "digest" header must be present when an HTTP body is present.');
        error.name = 'DataError';
        error.httpStatusCode = 400;
        return helpers.handleError({error, onError});
      }
      const {verified} = await verifyHeaderValue({
        data: req.body, headerValue: expectedDigest});
      if(!verified) {
        const error = new Error(
          'The "digest" header value does not match digest of body.');
        error.name = 'DataError';
        error.httpStatusCode = 400;
        return helpers.handleError({error, onError});
      }
    } else {
      // prevent any unhandled `req.body` from being erroneously used
      req.body = undefined;
    }

    // use `getExpectedAction` if provided
    if(getExpectedAction) {
      expectedAction = await getExpectedAction({req});
    }

    let expectedTarget;
    try {
      // getExpectedTarget may throw an error
      ({expectedTarget} = await getExpectedTarget({req}));
      if(!(typeof expectedTarget === 'string' ||
        Array.isArray(expectedTarget))) {
        throw new Error(
          'Return value from "getExpectedTarget" must be an object with ' +
          '"expectedTarget" set to a string or an array.');
      }
    } catch(error) {
      return helpers.handleError({error, onError});
    }

    let _expectedAction = expectedAction;

    // set expected action if it has not been specified
    /* Note: This is safe as long as the server's request handling
    infrastructure differentiates based on HTTP method (as is typical practice
    with express/connect routing. So, while the client specifies the HTTP
    method, the server specifies the handler for that HTTP method. For example,
    this middleware will ensure that if a client specifies "POST" then it
    must be invoking a zcap that grants "write" action authority. Then, provided
    that the server's router ensures that only the "POST" handler will be
    executed (typical routing practice), all is well. If the handler code is
    chosen via some other means, e.g., via the request body, then the caller
    MUST provide the expected action and not rely on default behavior. */
    if(_expectedAction === undefined) {
      _expectedAction = 'read';
      if(req.method === 'POST') {
        _expectedAction = 'write';
      }
    }

    let expectedRootCapability;
    try {
      if(getExpectedRootCapabilityId) {
        // retrieve the root capability given the request and expected params
        // return value can be a string or an array of strings
        expectedRootCapability = await getExpectedRootCapabilityId({
          req, expectedHost, expectedTarget,
          expectedAction: _expectedAction
        });
      } else if(Array.isArray(expectedTarget)) {
        expectedRootCapability = expectedTarget.map(
          t => `${ZCAP_ROOT_PREFIX}${encodeURIComponent(t)}`);
      } else {
        expectedRootCapability =
          `${ZCAP_ROOT_PREFIX}${encodeURIComponent(expectedTarget)}`;
      }
    } catch(error) {
      return helpers.handleError({error, onError});
    }

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
        expectedAction: _expectedAction, rootCapabilityId
      });
    }

    // perform the capability invocation
    const result = await verifyCapabilityInvocation({
      url,
      method,
      suite,
      headers,
      expectedHost,
      documentLoader: helpers.wrappedDocumentLoader({
        documentLoader,
        expectedAction: _expectedAction,
        expectedHost,
        expectedTarget,
        getRootController,
        req,
      }),
      getInvokedCapability,
      expectedTarget,
      expectedAction: _expectedAction,
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
  });
}
