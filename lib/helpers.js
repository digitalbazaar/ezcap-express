/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as helpers from './helpers.js';
import assert from 'assert-plus';
import asyncHandler from 'express-async-handler';
import {
  createRootCapability,
  constants as zcapConstants
} from '@digitalbazaar/zcap';
import {parseSignatureHeader} from 'http-signature-header';
import {verifyHeaderValue} from '@digitalbazaar/http-digest-header';

export const {ZCAP_ROOT_PREFIX} = zcapConstants;

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

// middleware used to collect expected values for zcap authorization
export function createExpectationMiddleware({
  getExpectedValues, onError
}) {
  assert.func(getExpectedValues, 'options.getExpectedValues');
  assert.optionalFunc(onError, 'options.onError');

  return asyncHandler(async (req, res, next) => {
    // cache ezcap express info
    req.ezcap = {};

    // parse signature header for zcap invocation
    const {headers} = req;
    try {
      const {params} = parseSignatureHeader(headers.authorization);
      req.ezcap.signature = {params};
    } catch(e) {
      const error = new Error('Missing or invalid "authorization" header.');
      error.name = 'DataError';
      error.cause = e;
      error.httpStatusCode = 400;
      return helpers.handleError({res, error, onError});
    }

    // if body is present, ensure header digest value matches digest of body
    if(helpers.hasBody({req})) {
      const {digest: expectedDigest} = headers;
      if(!expectedDigest) {
        const error = new Error(
          'A "digest" header must be present when an HTTP body is present.');
        error.name = 'DataError';
        error.httpStatusCode = 400;
        return helpers.handleError({res, error, onError});
      }
      const {verified} = await verifyHeaderValue({
        data: req.body, headerValue: expectedDigest});
      if(!verified) {
        const error = new Error(
          'The "digest" header value does not match digest of body.');
        error.name = 'DataError';
        error.httpStatusCode = 400;
        return helpers.handleError({res, error, onError});
      }
    } else {
      // prevent any unhandled `req.body` from being erroneously used
      req.body = undefined;
    }

    // get all expected values
    let expected;
    try {
      // `getExpectedValues` may throw
      expected = await getExpectedValues({req});
      _checkExpectedValues({expected});
    } catch(error) {
      return helpers.handleError({res, error, onError});
    }

    // default expected target is always the full request URL
    if(expected.target === undefined) {
      expected.target = `https://${expected.host}${req.originalUrl}`;
    }

    // get default expected action
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
    if(expected.action === undefined) {
      expected.action = DEFAULT_ACTION_FOR_METHOD.get(req.method);
      if(expected.action === undefined) {
        const error = new Error(
          `The HTTP method ${req.method} has no expected capability action.`);
        error.name = 'NotSupportedError';
        error.httpStatusCode = 400;
        return helpers.handleError({res, error, onError});
      }
    }

    // produce expected root capability from expected root invocation target
    let expectedRootCapability;
    const {rootInvocationTarget} = expected;
    if(Array.isArray(rootInvocationTarget)) {
      expectedRootCapability = rootInvocationTarget.map(
        t => `${ZCAP_ROOT_PREFIX}${encodeURIComponent(t)}`);
    } else {
      expectedRootCapability =
        `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootInvocationTarget)}`;
    }

    // save expected values
    req.ezcap.expectedAction = expected.action;
    req.ezcap.expectedHost = expected.host;
    req.ezcap.expectedRootCapability = expectedRootCapability;
    req.ezcap.expectedTarget = expected.target;

    // call `next` on the next tick to ensure the promise from this function
    // resolves and does not reject because some subsequent middleware throws
    // an error
    process.nextTick(next);
  });
}

export function handleError({res, error, onError, throwError = true}) {
  if(error.httpStatusCode) {
    res.status(error.httpStatusCode);
  } else if(res.status < 400) {
    res.status(500);
  }
  if(onError) {
    return onError({error});
  }
  if(throwError) {
    throw error;
  }
}

export function createRootCapabilityLoader({
  documentLoader, getRootController, req
}) {
  return async function rootCapabilityLoader(...args) {
    const [url] = args;
    if(url.startsWith(ZCAP_ROOT_PREFIX)) {
      const document = await getRootCapability({
        getRootController, req, rootCapabilityId: url
      });
      return {
        contextUrl: null,
        documentUrl: url,
        document,
      };
    }
    return documentLoader(...args);
  };
}

export async function getRootCapability({
  getRootController, req, rootCapabilityId
}) {
  const rootInvocationTarget = decodeURIComponent(
    rootCapabilityId.substr(ZCAP_ROOT_PREFIX.length));
  const controller = await getRootController({
    req, rootCapabilityId, rootInvocationTarget
  });
  return createRootCapability({
    controller, invocationTarget: rootInvocationTarget
  });
}

export function hasBody({req}) {
  // a request has a body if `transfer-encoding` or `content-length` headers
  // are set: http://www.w3.org/Protocols/rfc2616/rfc2616-sec4.html#sec4.3
  return req.body &&
    (req.get('transfer-encoding') !== undefined ||
    req.get('content-length') !== undefined);
}

function _checkExpectedValues({expected}) {
  if(!(expected && typeof expected === 'object')) {
    throw new TypeError('"getExpectedValues" must return an object.');
  }

  const {action, host, rootInvocationTarget, target} = expected;

  // expected `action` is optional
  if(!(action === undefined || typeof action === 'string')) {
    throw new TypeError('Expected "action" must be a string.');
  }

  // expected `host` is required
  if(typeof host !== 'string') {
    throw new TypeError('Expected "host" must be a string.');
  }

  // expected `rootInvocationTarget` is required
  if(!_checkExpectedRootInvocationTarget({rootInvocationTarget})) {
    throw new Error(
      'Expected "rootInvocationTarget" must be a string or an array of ' +
      'strings, each of which expresses an absolute URI.');
  }

  // expected `target` is optional
  if(target !== undefined && !(typeof target === 'string') &&
    target.includes(':')) {
    throw new Error(
      'Expected "target" must be a string that expresses an absolute ' +
      'URI.');
  }
}

function _checkExpectedRootInvocationTarget({rootInvocationTarget}) {
  // must be a string or an array of strings each of which represents an
  // absolute URI
  if(typeof rootInvocationTarget === 'string') {
    return rootInvocationTarget.includes(':');
  }
  if(Array.isArray(rootInvocationTarget) && rootInvocationTarget.length > 0) {
    return rootInvocationTarget.every(
      s => typeof s === 'string' && s.includes(':'));
  }
  return false;
}

// documentation typedefs

/**
 * A function for returning expected values when checking a zcap invocation.
 *
 * @typedef {Function} GetExpectedValues
 * @param {object} options - The options passed to the function.
 * @param {object} options.req - The express request.
 * @returns {ExpectedValues} - The expected values.
 */

/**
 * The expected values for checking a zcap invocation performed via an HTTP
 * request.
 *
 * @typedef {object} ExpectedValues
 * @property {string} [action] - The expected capability action; if no action
 *   is specified during an invocation check, then a default action will be
 *   determined based on the HTTP method from the request -- which is only safe
 *   provided that the handler code path is also determined based on the HTTP
 *   method in the request (i.e., typical method-based express/connect
 *   routing); if the handler code path is determined by some other means,
 *   e.g., the request body, then `action` MUST be set.
 * @property {string} host - The expected host in the request header.
 * @property {string|Array} rootInvocationTarget - The expected invocation
 *   target for every acceptable root capability; each string must express an
 *   absolute URI.
 * @property {string} [target] - The expected invocation target; if no target
 *   is specified during an invocation check, then the target will default to
 *   the absolute URL computed from the relative request URL and expected host
 *   value.
 */
