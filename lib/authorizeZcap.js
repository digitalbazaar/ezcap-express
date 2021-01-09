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
export function authorizeZcap({
  expectedHost, expectedTarget = undefined, suite = Ed25519Signature2018,
  getInvokedCapability, documentLoader, logger = noopLogger
}) {

  return async (req, res) => {
    const {url, method, headers} = req;
    const {params} = parseSignatureHeader(headers.authorization);
    const {keyId} = params;

    console.log('AUTHORIZE ZCAP', {method, url, headers, keyId});

    const result = await verifyCapabilityInvocation({
      url,
      method,
      suite,
      headers,
      expectedHost,
      getInvokedCapability,
      documentLoader,
      expectedTarget: expectedTarget | url,
      keyId
    });

    console.log('AUTHORIZE ZCAP', result);

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
