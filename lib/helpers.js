/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import * as sec from 'security-context';

// FIXME: replace security/v2 context with zcap context
// import {CONTEXT_URL as ZCAP_CONTEXT_URL} from 'zcap-context';

export const ZCAP_ROOT_PREFIX = 'urn:zcap:root:';

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
  let expectedRootCapability;
  if(getExpectedRootCapabilityId) {
    // retrieve the root capability given the request and expected params
    // return value can be a string or an array of strings
    expectedRootCapability = await getExpectedRootCapabilityId({
      req, expectedHost, expectedTarget, expectedAction
    });
  } else if(Array.isArray(expectedTarget)) {
    expectedRootCapability = expectedTarget.map(
      t => `${ZCAP_ROOT_PREFIX}${encodeURIComponent(t)}`);
  } else {
    expectedRootCapability =
      `${ZCAP_ROOT_PREFIX}${encodeURIComponent(expectedTarget)}`;
  }
  return expectedRootCapability;
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
    // FIXME: change to zcap context
    '@context': sec.constants.SECURITY_CONTEXT_V2_URL,
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
