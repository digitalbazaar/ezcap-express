/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import * as authorization from 'auth-header';
import {httpClient} from '@digitalbazaar/http-client';
import noopLogger from './noopLogger.js';
import {parseSignatureHeader} from 'http-signature-header';
import {suites} from 'jsonld-signatures';
import {verifyCapabilityInvocation} from 'http-signature-zcap-verify';
const {Ed25519Signature2018} = suites;

/**
 * Authorizes an incoming request.
 *
 * @param {object} options - Options hashmap.
 * @param {object} [options.logger] - Optional logger.
 * @param {object} options.httpsAgent - httpsAgent.
 *
 * @returns {Function} Returns an Express.js middleware route handler.
 */
export function authorizeZcapInvocation({
  expectedHost, expectedTarget = undefined, expectedAction = undefined,
  suite = Ed25519Signature2018, getRootCapability, documentLoader,
  logger = noopLogger
}) {
  return async (req, res) => {
    const {url, method, headers} = req;
    const {params} = parseSignatureHeader(headers.authorization);
    const {keyId} = params;

    // set expected action if it has not been specified
    // TODO: is this dangerous considering the client has control over it and
    //       the server specifies the appropriate path?
    if(expectedAction === undefined) {
      if(req.method === 'get') {
        expectedAction = 'read';
      } else if(req.method === 'post') {
        expectedAction = 'write';
      }
    }

    // retrieve the root capability given the request and expected params
    const expectedRootCapability = await getRootCapability(
      {req, expectedHost, expectedTarget, expectedAction}
    );

    // TODO: Temporary, eventually remove?
    async function getInvokedCapability({id, targetCapability}) {
      console.log('GET INVOKED CAPABILITY CALLED', id, targetCapability);
    }

    const result = await verifyCapabilityInvocation({
      url,
      method,
      suite,
      headers,
      expectedHost,
      documentLoader,
      getInvokedCapability,
      expectedTarget: expectedTarget || url,
      expectedAction,
      expectedRootCapability,
      keyId
    });

    if(!result.verified) {
      return res.status(403).send();
    }

    req.zcap = result;
  };
}

function _assertString(arg, msg) {
  if(typeof (arg) !== 'string') {
    throw new TypeError(`"${msg}" must be a string.`);
  }
}

function _assertOk(arg, msg) {
  if(!arg) {
    throw new TypeError(`"${msg}" is required.`);
  }
}
