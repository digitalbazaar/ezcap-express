/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import assert from 'assert-plus';
import {CryptoLD} from 'crypto-ld';
import asyncHandler from 'express-async-handler';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import * as helpers from './helpers.js';
import {verifyCapabilityInvocation} from 'http-signature-zcap-verify';

// FIXME: this is temporary; decouple crypto-ld from this lib
const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);

/**
 * Authorizes an incoming request.
 *
 * @typedef GetExpectedValues - See helpers.js.
 *
 * @param {object} options - Options hashmap.
 * @param {boolean} [options.allowTargetAttenuation=true] - Allow the
 *   invocationTarget of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 * @param {object} options.documentLoader - Document loader used to load
 *   DID Documents, capability documents, and JSON-LD Contexts.
 * @param {GetExpectedValues} options.getExpectedValues - Used to get the
 *   expected values when checking the zcap invocation.
 * @param {Function} options.getRootController - Used to get the controller
 *   of the root capability in the invoked capability's chain.
 * @param {Function} [options.inspectCapabilityChain] - A function that can
 *   inspect a capability chain, e.g., to check for revocations.
 * @param {number} [options.maxChainLength=10] - The maximum length of the
 *   capability delegation chain.
 * @param {number} [options.maxClockSkew=300] - A maximum number of seconds
 *   that clocks may be skewed when checking capability expiration date-times
 *   against `date`, when comparing invocation proof creation time against
 *   delegation proof creation time, and when comparing the capability
 *   invocation expiration time against `now`.
 * @param {number} [options.maxDelegationTtl=1000*60*60*24*90] - The maximum
 *   milliseconds to live for a delegated zcap as measured by the time
 *   difference between `expires` and `created` on the delegation proof.
* @param {Function} [options.onError] - An error handler handler for
 *   customizable error handling.
 * @param {object} [options.suiteFactory] - A factory for creating the
 *   supported suite(s) to use when verifying digital signatures.
 *
 * @returns {Function} Returns an Express.js style middleware route handler.
 */
export function authorizeZcapInvocation({
  allowTargetAttenuation = true,
  documentLoader, getExpectedValues, getRootController,
  inspectCapabilityChain,
  maxChainLength = 10,
  // 300 second clock skew permitted by default
  maxClockSkew = 300,
  // 90 day max TTL by default
  maxDelegationTtl = 1000 * 60 * 60 * 24 * 90,
  onError,
  suiteFactory
} = {}) {
  // `helpers.createExpectationMiddleware` handles type checks on other params
  assert.bool(allowTargetAttenuation, 'options.allowTargetAttenuation');
  assert.func(documentLoader, 'options.documentLoader');
  assert.func(getRootController, 'options.getRootController');
  assert.number(maxChainLength, 'options.maxChainLength');
  assert.number(maxClockSkew, 'options.maxClockSkew');
  assert.number(maxDelegationTtl, 'options.maxDelegationTtl');
  assert.optionalFunc(inspectCapabilityChain, 'options.inspectCapabilityChain');
  assert.optionalFunc(suiteFactory, 'options.suiteFactory');

  // FIXME: make `suiteFactory` required
  if(!suiteFactory) {
    suiteFactory = () => new Ed25519Signature2020();
  }

  return [
    helpers.createExpectationMiddleware({
      getExpectedValues, onError
    }),
    authorizeZcapInvocationAfterParse({
      allowTargetAttenuation, documentLoader, getRootController,
      inspectCapabilityChain,
      maxChainLength, maxClockSkew, maxDelegationTtl,
      onError, suiteFactory
    })
  ];
}

export function authorizeZcapInvocationAfterParse({
  allowTargetAttenuation = true,
  documentLoader, getRootController, inspectCapabilityChain,
  maxChainLength = 10,
  // 300 second clock skew permitted by default
  maxClockSkew = 300,
  // 90 day max TTL by default
  maxDelegationTtl = 1000 * 60 * 60 * 24 * 90,
  onError, suiteFactory
} = {}) {
  return asyncHandler(async (req, res, next) => {
    const {
      expectedAction, expectedHost, expectedRootCapability, expectedTarget,
      signature: {params: {keyId}}
    } = req.ezcap;

    // perform the capability invocation...
    // `originalUrl` must be used to support nested express routers
    const {originalUrl: url, method, headers} = req;
    const result = await verifyCapabilityInvocation({
      url,
      method,
      suite: await suiteFactory({req}),
      headers,
      expectedHost,
      documentLoader: helpers.createRootCapabilityLoader({
        documentLoader, getRootController, req
      }),
      // FIXME: require `getVerifier` to be passed as a param
      getVerifier,
      expectedAction,
      expectedTarget,
      expectedRootCapability,
      inspectCapabilityChain,
      keyId,
      allowTargetAttenuation,
      maxChainLength,
      maxClockSkew,
      maxDelegationTtl
    });

    // return HTTP 403 if verification fails
    if(!result.verified) {
      res.status(403);
      helpers.handleError({
        res, error: result.error, onError, throwError: false
      });
      return res.send();
    }

    // provide zcap verification results if verification succeeds
    req.zcap = result;

    // call `next` on the next tick to ensure the promise from this function
    // resolves and does not reject because some subsequent middleware throws
    // an error
    process.nextTick(next);
  });
}

// FIXME: remove this
async function getVerifier({keyId, documentLoader}) {
  const key = await cryptoLd.fromKeyId({id: keyId, documentLoader});
  const verificationMethod = await key.export(
    {publicKey: true, includeContext: true});
  const verifier = key.verifier();
  return {verifier, verificationMethod};
}
