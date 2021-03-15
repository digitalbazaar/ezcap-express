/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import asyncHandler from 'express-async-handler';
import {SECURITY_CONTEXT_V2_URL} from 'jsonld-signatures';
import {parseSignatureHeader} from 'http-signature-header';
import {suites} from 'jsonld-signatures';
import {verifyCapabilityInvocation} from 'http-signature-zcap-verify';
import noopLogger from './noopLogger.js';
const {Ed25519Signature2018} = suites;

const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

/**
 * Authorizes an incoming request.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.documentLoader - Document loader used to load
 *   DID Documents, capability documents, and JSON-LD Contexts.
 * @param {string} [options.expectedAction] - The expected action for the
 *   invoked capability.
 * @param {string} options.expectedHost - The expected host for the invoked
 *   capability.
 * @param {Function} options.getExpectedTarget - Used to return the expected
 *   target(s) for the invoked capability.
 * @param {Function} [options.getExpectedRootCapabilityId] - Used to return the
 *   expected root capability identifiers for the expected targets.
 * @param {Function} options.getRootController - Used to get the root capability
 *   controller for the given root capability ID.
 * @param {object} [options.logger] - The logger instance to use.
 * @param {Function} [options.onError] - An error handler to call. Allows for
 *   errors to be wrappped before being thrown.
 * @param {object} [options.suite] - The expected cryptography suite to use when
 *   verifying digital signatures.
 *
 * @returns {Function} Returns an Express.js middleware route handler.
 */
export function authorizeZcapInvocation({
  documentLoader, expectedAction, expectedHost, getExpectedRootCapabilityId,
  getExpectedTarget, getRootController, logger = noopLogger, onError,
  suite = new Ed25519Signature2018()
} = {}) {
  assert.func(documentLoader, 'options.documentLoader');
  assert.string(expectedHost, 'options.expectedHost');
  assert.func(getExpectedTarget, 'options.getExpectedTarget');
  assert.func(getRootController, 'options.getRootController');
  assert.optionalFunc(onError);

  if(getExpectedRootCapabilityId &&
    typeof getExpectedRootCapabilityId !== 'function') {
    throw new Error(
      '"options.getExpectedRootCapabilityId" must be a function.');
  }

  return asyncHandler(async (req, res, next) => {
    const {url, method, headers} = req;
    let params;
    try {
      ({params} = parseSignatureHeader(headers.authorization));
    } catch(e) {
      throw new Error('Missing or invalid "authorization" header.');
    }
    const {keyId} = params;
    const _expectedTarget = await getExpectedTarget({req});

    let _expectedAction = expectedAction;

    // set expected action if it has not been specified
    // TODO: is this dangerous considering the client has control over it and
    //       the server specifies the appropriate path?
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
        req, expectedHost, expectedTarget: _expectedTarget,
        expectedAction: _expectedAction
      });
    } else if(Array.isArray(_expectedTarget)) {
      expectedRootCapability = _expectedTarget.map(
        t => `urn:zcap:root:${encodeURIComponent(t)}`);
    } else {
      expectedRootCapability =
        `urn:zcap:root:${encodeURIComponent(_expectedTarget)}`;
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
          `Capability target "${id}" is not an expected root ` +
          `capability "${expectedRootCapability}".`);
        error.details = {
          actual: id,
          expected: expectedRootCapability,
        };

        return _handleError({error, onError});
      }
      return _getRootCapability({
        getRootController, req, expectedHost, expectedTarget: _expectedTarget,
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
        expectedTarget: _expectedTarget,
        getRootController,
        req,
      }),
      getInvokedCapability,
      expectedTarget: _expectedTarget,
      expectedAction: _expectedAction,
      expectedRootCapability,
      keyId
    });

    // return HTTP 403 if verification fails
    if(!result.verified) {
      const error = new Error('ZCAP authorization failed.');
      error.details = {url};
      error.cause = result.error;
      logger.error(error);
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

function _handleError({error, onError}) {
  if(onError) {
    return onError({error});
  }
  throw error;
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
    '@context': SECURITY_CONTEXT_V2_URL,
    id: rootCapabilityId,
    invocationTarget: rootInvocationTarget,
    controller
  };
}
