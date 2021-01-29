/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import {SECURITY_CONTEXT_V2_URL} from 'jsonld-signatures';
import {parseSignatureHeader} from 'http-signature-header';
import {suites} from 'jsonld-signatures';
import {verifyCapabilityInvocation} from 'http-signature-zcap-verify';
const {Ed25519Signature2018} = suites;

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
 * @param {string} [options.expectedAction] - The expected target for the
 *   invoked capability.
 * @param {Promise<string>} [options.getController] - Gets the controller URL
 *   for the invoked target. If this value isn't specified, getRootCapability
 *   must be specified.
 * @param {Promise} [options.getRootCapability] - The expected target for the
 *   invoked capability. If this value isn't specified, getController must be
 *   specified.
 * @param {class} [options.suite] - The expected cryptography suite to use when
 *   verifying digital signatures.
 *
 * @returns {Function} Returns an Express.js middleware route handler.
 */
export function authorizeZcapInvocation({
  documentLoader, expectedAction, expectedHost, expectedTarget,
  getCapabilityController, getRootCapability,
  suite = new Ed25519Signature2018()
} = {}) {
  _assertOk(documentLoader, 'options.documentLoader');
  _assertString(expectedHost, 'options.expectedHost');
  if(getCapabilityController === undefined && getRootCapability === undefined) {
    throw new Error('Either options.getController or ' +
      'options.getRootCapability must be provided');
  }

  return (req, res, next) => {
    // FIXME: Fix this so it doesn't generate a new go function every time
    go().then(next, next);

    async function go() {
      const {url, method, headers} = req;
      const {params} = parseSignatureHeader(headers.authorization);
      const {keyId} = params;
      const target =
        expectedTarget || req.protocol + '://' + req.get('host') + req.url;
      let action = expectedAction;

      // set expected action if it has not been specified
      // TODO: is this dangerous considering the client has control over it and
      //       the server specifies the appropriate path?
      if(action === undefined) {
        action = 'read';
        if(req.method === 'POST') {
          action = 'write';
        }
      }

      // get the controller if it is specified
      let expectedRootCapability;
      if(getCapabilityController) {
        // build the expected root capability if we can get the controller
        const invocationTarget = `https://${expectedHost}${req.url}`;
        const controller = await getCapabilityController({req});

        expectedRootCapability = {
          '@context': SECURITY_CONTEXT_V2_URL,
          id: 'urn:zcap:root:' + encodeURIComponent(invocationTarget),
          invocationTarget,
          controller
        };
      } else {
        // retrieve the root capability given the request and expected params
        expectedRootCapability = await getRootCapability(
          {req, expectedHost, expectedTarget, expectedAction}
        );
      }

      // retrieves the root capability that was invoked
      async function getInvokedCapability({id}) {
        // FIXME: handle expectedRootCapability being an array
        if(id !== expectedRootCapability.id) {
          throw new Error(
            `Capability target (${id}) does not match expected root ` +
            `capability (${expectedRootCapability.id}).`);
        }

        return expectedRootCapability;
      }

      // perform the capability invocation
      const result = await verifyCapabilityInvocation({
        url,
        method,
        suite,
        headers,
        expectedHost,
        documentLoader,
        getInvokedCapability,
        expectedTarget: target,
        expectedAction: action,
        expectedRootCapability: expectedRootCapability.id,
        keyId
      });

      // return HTTP 403 if verification fails
      if(!result.verified) {
        return res.status(403).send();
      }

      // provide zcap verification results if verification succeeds
      req.zcap = result;
    }
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
