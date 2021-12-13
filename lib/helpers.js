/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import asyncHandler from 'express-async-handler';
import {constants as zCapConstants} from '@digitalbazaar/zcapld';
import * as helpers from './helpers.js';
import {parseSignatureHeader} from 'http-signature-header';
import {verifyHeaderValue} from '@digitalbazaar/http-digest-header';

const {ZCAP_CONTEXT_URL} = zCapConstants;

const DEFAULT_ACTION_FOR_METHOD = new Map([
  ['GET', 'read'],
  ['HEAD', 'read'],
  ['OPTIONS', 'read'],
  ['POST', 'write'],
  ['PUT', 'write'],
  ['PATCH', 'write'],
  ['DELETE', 'write'],
  ['CONNECT', 'write'],
  ['TRACE', 'write'],
  ['PATCH', 'write']
]);

export const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

// middleware used to collect expected values for zcap authorization
export function createExpectationMiddleware({
  expectedHost, getExpectedTarget,
  expectedAction, getExpectedAction,
  getExpectedRootCapabilityId, onError
}) {
  assert.string(expectedHost, 'options.expectedHost');
  assert.func(getExpectedTarget, 'options.getExpectedTarget');
  assert.optionalString(expectedAction, 'options.expectedAction');
  assert.optionalFunc(getExpectedAction, 'options.getExpectedAction');
  assert.optionalFunc(
    getExpectedRootCapabilityId, 'options.getExpectedRootCapabilityId');
  assert.optionalFunc(onError, 'options.onError');

  if(getExpectedAction && expectedAction !== undefined) {
    throw new Error('Use "getExpectedAction" or "expectedAction", not both.');
  }

  return asyncHandler(async (req, res, next) => {
    // cache ezcap express info
    req.ezcap = {expectedHost};

    const {headers} = req;
    try {
      const {params} = parseSignatureHeader(headers.authorization);
      req.ezcap.signature = {params};
    } catch(e) {
      const error = new Error('Missing or invalid "authorization" header.');
      error.name = 'DataError';
      error.cause = e;
      return helpers.handleError({error, onError});
    }

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

    try {
      // getExpectedTarget may throw an error
      req.ezcap.expectedTarget = await helpers.getExpectedTarget(
        {req, getExpectedTarget});
    } catch(error) {
      return helpers.handleError({error, onError});
    }

    // set expected action
    req.ezcap.expectedAction = expectedAction;

    // use `getExpectedAction` if provided
    if(getExpectedAction) {
      req.ezcap.expectedAction = await getExpectedAction({req});
    }

    /* Note: This is safe as long as the server's request handling
    infrastructure differentiates based on HTTP method (as is typical practice
    with express/connect routing). So, while the client specifies the HTTP
    method, the server specifies the handler for that HTTP method. For example,
    this middleware will ensure that if a client specifies "POST" then it
    must be invoking a zcap that grants "write" action authority. Then,
    provided that the server's router ensures that only the "POST" handler will
    be executed (typical routing practice), all is well. If the handler code is
    chosen via some other means, e.g., via the request body, then the caller
    MUST provide the expected action and not rely on default behavior. */
    if(req.ezcap.expectedAction === undefined) {
      req.ezcap.expectedAction = DEFAULT_ACTION_FOR_METHOD.get(req.method);
      if(req.ezcap.expectedAction === undefined) {
        const error = new Error(
          `The HTTP method ${req.method} has no expected capability action.`);
        error.name = 'NotSupportedError';
        error.httpStatusCode = 400;
        return helpers.handleError({error, onError});
      }
    }

    try {
      req.ezcap.expectedRootCapability = await helpers
        .getExpectedRootCapability({
          req, expectedHost,
          expectedTarget: req.ezcap.expectedTarget,
          expectedAction: req.ezcap.expectedAction,
          getExpectedRootCapabilityId
        });
    } catch(error) {
      return helpers.handleError({error, onError});
    }

    // call `next` on the next tick to ensure the promise from this function
    // resolves and does not reject because some subsequent middleware throws
    // an error
    process.nextTick(next);
  });
}

export function handleError({error, onError, throwError = true}) {
  if(onError) {
    return onError({error});
  }
  if(throwError) {
    throw error;
  }
}

export function wrappedDocumentLoader({
  req, documentLoader, expectedHost, expectedTarget, expectedAction,
  getRootController
}) {
  return async url => {
    if(url.startsWith(ZCAP_ROOT_PREFIX)) {
      const document = await getRootCapability({
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

export async function getExpectedRootCapability({
  req, expectedHost, expectedTarget, expectedAction,
  getExpectedRootCapabilityId
}) {
  if(getExpectedRootCapabilityId) {
    // retrieve the root capability given the request and expected params
    // return value can be a string or an array of strings
    return getExpectedRootCapabilityId({
      req, expectedHost, expectedTarget, expectedAction
    });
  }
  if(Array.isArray(expectedTarget)) {
    return expectedTarget.map(
      t => `${ZCAP_ROOT_PREFIX}${encodeURIComponent(t)}`);
  }
  return `${ZCAP_ROOT_PREFIX}${encodeURIComponent(expectedTarget)}`;
}

export async function getExpectedTarget({req, getExpectedTarget}) {
  const {expectedTarget} = await getExpectedTarget({req});
  if(!(typeof expectedTarget === 'string' ||
    Array.isArray(expectedTarget))) {
    throw new Error(
      'Return value from "getExpectedTarget" must be an object with ' +
      '"expectedTarget" set to a string or an array.');
  }
  return expectedTarget;
}

export async function getRootCapability({
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
    '@context': ZCAP_CONTEXT_URL,
    id: rootCapabilityId,
    invocationTarget: rootInvocationTarget,
    controller
  };
}

export function hasBody({req}) {
  // a request has a body if `transfer-encoding` or `content-length` headers
  // are set: http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.3
  return req.body &&
    (req.get('transfer-encoding') !== undefined ||
    req.get('content-length') !== undefined);
}
