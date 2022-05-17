/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {
  authorizeZcapInvocation, authorizeZcapRevocation
} from '../lib/index.js';
import {
  createRootCapability,
  constants as zcapConstants
} from '@digitalbazaar/zcap';
import {CryptoLD} from 'crypto-ld';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import express from 'express';
import {ZcapClient} from '@digitalbazaar/ezcap';
import {delegate, getInvocationSigner} from './helpers.js';
import {fileURLToPath} from 'node:url';
import {httpClient, DEFAULT_HEADERS} from '@digitalbazaar/http-client';
import fs from 'node:fs';
import https from 'node:https';
import path from 'node:path';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import {signCapabilityInvocation} from
  '@digitalbazaar/http-signature-zcap-invoke';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const loader = securityLoader();
loader.addStatic(
  zcapConstants.ZCAP_CONTEXT_URL, zcapConstants.ZCAP_CONTEXT);

const documentLoader = loader.build();

// set in _startServer
// host:port
let BASE_HOST;
// https://host:port
let BASE_URL;

const key = fs.readFileSync(__dirname + '/key.pem');
const cert = fs.readFileSync(__dirname + '/cert.pem');

// admin party / root controller used in tests
const ADMIN_SEED = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
const ROOT_CONTROLLER =
  'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR';

// delegate party used in tests
const DELEGATE_SEED = 'z1AnZce3gUvSfVbsbqpgH9LNtmBuve4zQdYwdpEp22YQzB4';
const DELEGATE_ID = 'did:key:z6Mki68HpLhwaUZub3dqbmGCiMm9GfjzX9pBiK8hvezxuCix';

// HTTPS agent that ignores TLS errors as test server has invalid cert
const agent = new https.Agent({rejectUnauthorized: false});

function _startServer({app}) {
  return new Promise(resolve => {
    const server = https.createServer({key, cert}, app);
    server.listen(0, () => {
      BASE_HOST = `localhost:${server.address().port}`;
      BASE_URL = `https://${BASE_HOST}`;
      console.log(`Test server listening at ${BASE_URL}`);
      return resolve(server);
    });
  });
}

// set to `true` to debug errors
const DEBUG = false;
let _logError;
if(DEBUG) {
  _logError = function _logError({error}) {
    console.error(error);
    throw error;
  };
}

const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);
async function getVerifier({keyId, documentLoader}) {
  const key = await cryptoLd.fromKeyId({id: keyId, documentLoader});
  const verificationMethod = await key.export(
    {publicKey: true, includeContext: true});
  const verifier = key.verifier();
  return {verifier, verificationMethod};
}

const app = express();
app.use(express.json());

async function _setupApp() {
  // mount the test routes
  app.post('/documents',
    authorizeZcapInvocation({
      documentLoader,
      getExpectedValues() {
        return {
          host: BASE_HOST,
          rootInvocationTarget: [`${BASE_URL}/documents`]
        };
      },
      getRootController() {
        // root controller(Admin DID)
        return ROOT_CONTROLLER;
      },
      getVerifier,
      onError: _logError,
      suiteFactory() {
        return new Ed25519Signature2020();
      }
    }),
    // eslint-disable-next-line no-unused-vars
    (req, res, next) => {
      res.json({message: 'Post request was successful.'});
    });

  // this route tests a broken `getExpectedValues` with a bad return value
  app.get('/test/:id',
    authorizeZcapInvocation({
      documentLoader,
      getExpectedValues({req}) {
        const rootInvocationTarget =
          `${BASE_URL}/documents/${encodeURIComponent(req.params.id)}`;
        // intentionally set return value to not be an object
        return rootInvocationTarget;
      },
      getRootController() {
        // root controller(Admin DID)
        return ROOT_CONTROLLER;
      },
      getVerifier,
      onError: _logError,
      suiteFactory() {
        return new Ed25519Signature2020();
      }
    }),
    // eslint-disable-next-line no-unused-vars
    (req, res, next) => {
      res.json({message: 'Get request was successful.'});
    });

  app.post('/service-objects/:localId/zcaps/revocations/:revocationId',
    authorizeZcapRevocation({
      documentLoader,
      expectedHost: BASE_HOST,
      getRootController() {
        // root controller(Admin DID)
        return ROOT_CONTROLLER;
      },
      inspectCapabilityChain() {
        // checking previously revoked zcaps is not part of the tests
        return {valid: true};
      },
      getVerifier,
      onError: _logError,
      suiteFactory() {
        return new Ed25519Signature2020();
      }
    }),
    // eslint-disable-next-line no-unused-vars
    (req, res, next) => {
      const {revocationId} = req.params;
      if(!revocationId.includes(':')) {
        return next(new Error('Revocation ID must be an absolute URI.'));
      }
      res.json({message: 'Revocation was successful.'});
    });
  // eslint-disable-next-line no-unused-vars
  app.use(function(err, req, res, next) {
    if(res.statusCode < 400) {
      // default to 500 error code
      res.status(500);
    }
    res.send({message: err.message, name: err.name});
  });
}

let server;
before(async () => {
  server = await _startServer({app});
  await _setupApp(server);
});

after(async () => {
  server.close();
});
describe('ezcap-express', () => {
  describe('authorizeZcapInvocation', () => {
    it('should succeed if correct data is passed', async () => {
      const url = `${BASE_URL}/documents`;
      const invocationSigner = await getInvocationSigner({seed: ADMIN_SEED});

      const zcapClient = new ZcapClient({
        agent,
        SuiteClass: Ed25519Signature2020,
        invocationSigner
      });
      let res;
      let err;
      try {
        res = await zcapClient.write({url, json: {name: 'test'}});
      } catch(e) {
        err = e;
      }
      should.exist(res);
      should.not.exist(err);
      res.status.should.equal(200);
      res.data.message.should.equal('Post request was successful.');
    });
    it('should error if missing authorization header', async () => {
      let res;
      let err;
      try {
        res = await httpClient.post(`${BASE_URL}/documents`, {
          agent,
          json: {}
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.status.should.equal(400);
      err.data.name.should.equal('DataError');
      err.data.message.should.equal(
        'Missing or invalid "authorization" header.');
    });
    it('should throw forbidden error if the authorized invoker does not ' +
      'match the controller', async () => {
      const url = `${BASE_URL}/documents`;
      // Use a different seed
      const seed = 'z1AbCFiBWpN89ug5hcxUfa6TzpGoowH7DBidgL8zPu6v5RV';
      const invocationSigner = await getInvocationSigner({seed});

      const zcapClient = new ZcapClient({
        agent,
        SuiteClass: Ed25519Signature2020,
        invocationSigner
      });
      let res;
      let err;
      try {
        res = await zcapClient.write({url, json: {name: 'test'}});
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.status.should.equal(403);
      err.message.should.include('Forbidden');
    });
    it('should throw error if digest header is not present when http body is ' +
      'present', async () => {
      const url = `${BASE_URL}/documents`;
      // Use a different seed
      const seed = 'z1AbCFiBWpN89ug5hcxUfa6TzpGoowH7DBidgL8zPu6v5RV';
      const invocationSigner = await getInvocationSigner({seed});

      const zcapClient = new ZcapClient({
        agent,
        SuiteClass: Ed25519Signature2020,
        invocationSigner
      });
      let res;
      let err;
      try {
        res = await zcapClient.write({url});
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.status.should.equal(400);
      err.data.name.should.equal('DataError');
      err.data.message.should.equal(
        'A "digest" header must be present when an HTTP body is present.');
    });
    it('should throw error if digest header value does not match digest ' +
      'of body', async () => {
      const url = `${BASE_URL}/documents`;
      const invocationSigner = await getInvocationSigner({seed: ADMIN_SEED});

      const headers = await signCapabilityInvocation({
        url, method: 'post',
        headers: DEFAULT_HEADERS,
        capability: 'urn:zcap:root:' + encodeURIComponent(url),
        invocationSigner,
        capabilityAction: 'write',
        json: {name: 'test'}
      });

      let err;
      let res;
      try {
        res = await httpClient.post(url, {
          agent,
          headers,
          json: {name: 'not test'}
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.status.should.equal(400);
      err.data.name.should.equal('DataError');
      err.data.message.should.equal(
        'The "digest" header value does not match digest of body.');
    });
    it('should throw error if expected invocation target does not ' +
      'match capability invocation target', async () => {
      const url = `${BASE_URL}/documents`;
      const url2 = `${BASE_URL}/test/abc`;

      const invocationSigner = await getInvocationSigner({seed: ADMIN_SEED});

      const headers = await signCapabilityInvocation({
        url, method: 'post',
        headers: DEFAULT_HEADERS,
        capability: 'urn:zcap:root:' + encodeURIComponent(url2),
        invocationSigner,
        capabilityAction: 'write',
        json: {name: 'test'}
      });

      let err;
      let res;
      try {
        res = await httpClient.post(url, {
          agent,
          headers,
          json: {name: 'test'}
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.status.should.equal(403);
    });
    it('should throw error if return value from "getExpectedTarget" is not ' +
      'an object with "expectedTarget" set to string or array', async () => {
      const url = `${BASE_URL}/test/xyz`;

      const invocationSigner = await getInvocationSigner({seed: ADMIN_SEED});

      const zcapClient = new ZcapClient({
        agent,
        SuiteClass: Ed25519Signature2020,
        invocationSigner
      });
      let res;
      let err;
      try {
        res = await zcapClient.read({url});
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.status.should.equal(500);
      err.data.message.should.equal(
        '"getExpectedValues" must return an object.');
    });
  });
  describe('authorizeZcapRevocation', () => {
    describe('.../:localId/zcaps/revocations/:revocationId', () => {
      it('should succeed if correct data is passed', async () => {
        // delegate zcap to access a service object from admin to delegate
        const serviceObjectId = `${BASE_URL}/service-objects/123`;
        const delegatedZcap = await delegate({
          seed: ADMIN_SEED,
          rootInvocationTarget: serviceObjectId,
          controller: DELEGATE_ID
        });

        // revoke zcap
        const invocationSigner = await getInvocationSigner(
          {seed: DELEGATE_SEED});
        const zcapClient = new ZcapClient({
          agent,
          SuiteClass: Ed25519Signature2020,
          invocationSigner
        });
        let err;
        let res;
        try {
          const url = `${serviceObjectId}/zcaps/revocations/` +
            `${encodeURIComponent(delegatedZcap.id)}`;
          res = await zcapClient.write({url, json: delegatedZcap});
        } catch(e) {
          err = e;
        }
        should.not.exist(err);
        should.exist(res);
        res.status.should.equal(200);
        res.data.message.should.equal('Revocation was successful.');
      });
      it('throws error if capability id starts with ' +
        '"urn:zcap:root:"', async () => {
        // try to revoke root zcap
        const serviceObjectId = `${BASE_URL}/service-objects/123`;
        const rootCapability = createRootCapability({
          controller: ROOT_CONTROLLER,
          invocationTarget: serviceObjectId
        });

        const invocationSigner = await getInvocationSigner({seed: ADMIN_SEED});
        const zcapClient = new ZcapClient({
          agent,
          SuiteClass: Ed25519Signature2020,
          invocationSigner
        });
        let err;
        let res;
        try {
          const url = `${serviceObjectId}/zcaps/revocations/` +
            `${encodeURIComponent(rootCapability.id)}`;
          res = await zcapClient.write({url, json: rootCapability});
        } catch(e) {
          err = e;
        }
        should.not.exist(res);
        should.exist(err);
        err.data.name.should.equal('NotAllowedError');
        err.data.message.should.equal('A root capability cannot be revoked.');
      });
      it('throws error if capability is invalid', async () => {
        // delegate zcap to access a service object from admin to delegate
        const serviceObjectId = `${BASE_URL}/service-objects/123`;
        const delegatedZcap = await delegate({
          seed: ADMIN_SEED,
          rootInvocationTarget: serviceObjectId,
          controller: DELEGATE_ID
        });

        // make delegated zcap invalid by deleting its `proof`
        delete delegatedZcap.proof;

        // revoke zcap
        const invocationSigner = await getInvocationSigner(
          {seed: DELEGATE_SEED});
        const zcapClient = new ZcapClient({
          agent,
          SuiteClass: Ed25519Signature2020,
          invocationSigner
        });
        let err;
        let res;
        try {
          const url = `${serviceObjectId}/zcaps/revocations/` +
            `${encodeURIComponent(delegatedZcap.id)}`;
          res = await zcapClient.write({url, json: delegatedZcap});
        } catch(e) {
          err = e;
        }
        should.not.exist(res);
        should.exist(err);
        err.data.name.should.equal('DataError');
        err.data.message.should.equal(
          'The provided capability delegation is invalid.');
      });
      it('throws error if not authorized to use root capability for ' +
        'service object', async () => {
        // delegate zcap to access a service object from admin to delegate
        const serviceObjectId = `${BASE_URL}/service-objects/123`;
        const delegatedZcap = await delegate({
          seed: ADMIN_SEED,
          rootInvocationTarget: serviceObjectId,
          controller: DELEGATE_ID
        });

        // try to revoke zcap using root zcap for service object
        const rootCapability = createRootCapability({
          controller: ROOT_CONTROLLER,
          invocationTarget: serviceObjectId
        });
        const invocationSigner = await getInvocationSigner(
          {seed: DELEGATE_SEED});
        const zcapClient = new ZcapClient({
          agent,
          SuiteClass: Ed25519Signature2020,
          invocationSigner
        });
        let err;
        let res;
        try {
          const url = `${serviceObjectId}/zcaps/revocations/` +
            `${encodeURIComponent(delegatedZcap.id)}`;
          res = await zcapClient.write({
            url, capability: rootCapability, json: delegatedZcap
          });
        } catch(e) {
          err = e;
        }
        should.not.exist(res);
        should.exist(err);
        err.status.should.equal(403);
        err.message.should.include('Forbidden');
      });
      it('should succeed if authorized to use root capability for ' +
        'service object', async () => {
        // delegate zcap to access a service object from admin to delegate
        const serviceObjectId = `${BASE_URL}/service-objects/123`;
        const delegatedZcap = await delegate({
          seed: ADMIN_SEED,
          rootInvocationTarget: serviceObjectId,
          controller: DELEGATE_ID
        });

        // try to revoke zcap using root zcap for service object
        const rootCapability = createRootCapability({
          controller: ROOT_CONTROLLER,
          invocationTarget: serviceObjectId
        });
        const invocationSigner = await getInvocationSigner(
          {seed: ADMIN_SEED});
        const zcapClient = new ZcapClient({
          agent,
          SuiteClass: Ed25519Signature2020,
          invocationSigner
        });
        let err;
        let res;
        try {
          const url = `${serviceObjectId}/zcaps/revocations/` +
            `${encodeURIComponent(delegatedZcap.id)}`;
          res = await zcapClient.write({
            url, capability: rootCapability.id, json: delegatedZcap
          });
        } catch(e) {
          err = e;
        }
        should.not.exist(err);
        should.exist(res);
        res.status.should.equal(200);
        res.data.message.should.equal('Revocation was successful.');
      });
    });
  });
});
