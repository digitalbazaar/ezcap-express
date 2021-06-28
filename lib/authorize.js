/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import asyncHandler from 'express-async-handler';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {parseSignatureHeader} from 'http-signature-header';
import {verifyHeaderValue} from '@digitalbazaar/http-digest-header';
import * as sec from 'security-context';
import {verifyCapabilityInvocation} from 'http-signature-zcap-verify';

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

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

  return asyncHandler(async (req, res, next) => {
    // originalUrl must be used to support nested express routers
    const {originalUrl: url, method, headers} = req;
    let params;
    try {
      ({params} = parseSignatureHeader(headers.authorization));
    } catch(e) {
      throw new Error('Missing or invalid "authorization" header.');
    }
    const {keyId} = params;

    // if body is present, ensure header digest value matches digest of body
    if(req.get('content-type') || req.body) {
      const {digest: expectedDigest} = headers;
      if(!expectedDigest) {
        const error = new Error(
          'A "digest" header must be present when an HTTP body is present.');
        error.name = 'DataError';
        error.httpStatusCode = 400;
        throw error;
      }
      const {verified} = await verifyHeaderValue({
        data: req.body, headerValue: expectedDigest});
      if(!verified) {
        const error = new Error(
          'The "digest" header value does not match digest of body.');
        error.name = 'DataError';
        error.httpStatusCode = 400;
        throw error;
      }
    }

    // use `getExpectedAction` if provided
    if(getExpectedAction) {
      if(expectedAction !== undefined) {
        throw new Error(
          'Use "getExpectedAction" or "expectedAction", not both.');
      }
      expectedAction = await getExpectedAction({req});
    }

    let expectedTarget;
    try {
      // getExpectedTarget may throw an error
      ({expectedTarget} = await getExpectedTarget({req}));
      if(!(typeof expectedTarget === 'string' ||
        Array.isArray(expectedTarget))) {
        throw new Error(
          'Return value from "getExpectedTarget" must be a ' +
          'string or an array.');
      }
    } catch(error) {
      return _handleError({error, onError});
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
    if(getExpectedRootCapabilityId) {
      // retrieve the root capability given the request and expected params
      // return value can be a string or an array of strings
      expectedRootCapability = await getExpectedRootCapabilityId({
        req, expectedHost, expectedTarget,
        expectedAction: _expectedAction
      });
    } else if(Array.isArray(expectedTarget)) {
      expectedRootCapability = expectedTarget.map(
        t => `urn:zcap:root:${encodeURIComponent(t)}`);
    } else {
      expectedRootCapability =
        `urn:zcap:root:${encodeURIComponent(expectedTarget)}`;
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

        return _handleError({error, onError});
      }
      return _getRootCapability({
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
      documentLoader: _wrappedDocumentLoader({
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
      _handleError({error: result.error, onError, throwError: false});
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

function _handleError({error, onError, throwError = true}) {
  if(onError) {
    return onError({error});
  }
  if(throwError) {
    throw error;
  }
}

function _wrappedDocumentLoader({
  req, documentLoader, expectedHost, expectedTarget, expectedAction,
  getRootController
}) {
  return async url => {
    if(url.startsWith(ZCAP_ROOT_PREFIX)) {
      const document = await _getRootCapability({
        getRootController, req, expectedHost, expectedTarget, expectedAction,
        rootCapabilityId: url
      });

      return {
        contextUrl: null,
        documentUrl: url,
        document,
      };
    }

    return documentLoader(url);
  };
}

async function _getRootCapability({
  getRootController, req, expectedHost, expectedTarget, expectedAction,
  rootCapabilityId
}) {
  const rootInvocationTarget = decodeURIComponent(
    rootCapabilityId.substr(ZCAP_ROOT_PREFIX.length));
  const controller = await getRootController({
    req, expectedHost, expectedTarget, expectedAction,
    rootCapabilityId, rootInvocationTarget
  });
  return {
    '@context': sec.constants.SECURITY_CONTEXT_V2_URL,
    id: rootCapabilityId,
    invocationTarget: rootInvocationTarget,
    controller
  };
}
