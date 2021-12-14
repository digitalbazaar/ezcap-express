/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import {decodeSecretKeySeed} from 'bnid';
import express from 'express';
import {signCapabilityInvocation} from 'http-signature-zcap-invoke';
import * as didKey from '@digitalbazaar/did-method-key';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {ZcapClient} from '@digitalbazaar/ezcap';
import {httpClient, DEFAULT_HEADERS} from '@digitalbazaar/http-client';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import zcapCtx from 'zcap-context';
import {authorizeZcapInvocation} from '../lib';

const didKeyDriver = didKey.driver();
const loader = securityLoader();
loader.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);

const documentLoader = loader.build();

const TEST_SERVER_PORT = 5000;

function _startServer({app, port = TEST_SERVER_PORT}) {
  return new Promise(resolve => {
    const server = app.listen(port, () => {
      console.log(`Test server listening at http://localhost:${port}`);
      return resolve(server);
    });
  });
}

const app = express();
app.use(express.json());

// mount the test routes
app.post('/documents',
  authorizeZcapInvocation({
    documentLoader,
    getExpectedTarget() {
      return {
        expectedTarget: ['http://localhost:5000/documents']
      };
    },
    getRootController() {
    // root controller(Admin DID)
      return 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR';
    },
    expectedHost: 'localhost:5000'
  }),
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    res.json({message: 'Post request was successful.'});
  });

app.get('/test/:id',
  authorizeZcapInvocation({
    documentLoader,
    getRootController() {
      // root controller(Admin DID)
      return 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR';
    },
    getExpectedTarget({req}) {
      const expectedTarget =
        `http://localhost:5000/documents/${encodeURIComponent(req.params.id)}`;
      // intentionally set return value to not be an object
      return expectedTarget;
    },
    expectedHost: 'localhost:5000'
  }),
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    res.json({message: 'Get request was successful.'});
  });

// eslint-disable-next-line no-unused-vars
app.use(function(err, req, res, next) {
  res.status(500).send({message: err.message, name: err.name});
});

let server;
before(async () => {
  server = await _startServer({app});
  // do other stuff that you need to, or simply
  // return _startServer({app});
});

after(async () => {
  server.close();
});
describe('ezcap-express', () => {
  describe('authorizeZcapInvocation', () => {
    it('should succeed if correct data is passed', async () => {
      const url = 'http://localhost:5000/documents';
      // Admin seed
      const seed = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
      const decoded = decodeSecretKeySeed({secretKeySeed: seed});

      const {methodFor} = await didKeyDriver.generate({seed: decoded});
      const invocationCapabilityKeyPair = methodFor(
        {purpose: 'capabilityInvocation'});

      const zcapClient = new ZcapClient({
        SuiteClass: Ed25519Signature2020,
        invocationSigner: invocationCapabilityKeyPair.signer()
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
        res = await httpClient.post('http://localhost:5000/documents', {
          json: {}
        });
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.status.should.equal(500);
      err.data.name.should.equal('DataError');
      err.data.message.should.equal(
        'Missing or invalid "authorization" header.');
    });
    it('should throw forbidden error if the authorized invoker does not ' +
      'match the controller', async () => {
      const url = 'http://localhost:5000/documents';
      // Use a different seed
      const seed = 'z1AbCFiBWpN89ug5hcxUfa6TzpGoowH7DBidgL8zPu6v5RV';
      const decoded = decodeSecretKeySeed({secretKeySeed: seed});

      const {methodFor} = await didKeyDriver.generate({seed: decoded});
      const invocationCapabilityKeyPair = methodFor(
        {purpose: 'capabilityInvocation'});

      const zcapClient = new ZcapClient({
        SuiteClass: Ed25519Signature2020,
        invocationSigner: invocationCapabilityKeyPair.signer()
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
      err.message.should.equal('Forbidden');
    });
    it('should throw error if digest header is not present when HTTP body is ' +
      'present', async () => {
      const url = 'http://localhost:5000/documents';
      // Use a different seed
      const seed = 'z1AbCFiBWpN89ug5hcxUfa6TzpGoowH7DBidgL8zPu6v5RV';
      const decoded = decodeSecretKeySeed({secretKeySeed: seed});

      const {methodFor} = await didKeyDriver.generate({seed: decoded});
      const invocationCapabilityKeyPair = methodFor(
        {purpose: 'capabilityInvocation'});

      const zcapClient = new ZcapClient({
        SuiteClass: Ed25519Signature2020,
        invocationSigner: invocationCapabilityKeyPair.signer()
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
      err.status.should.equal(500);
      err.data.name.should.equal('DataError');
      err.data.message.should.equal(
        'A "digest" header must be present when an HTTP body is present.');
    });
    it('should throw error if digest header value does not match digest ' +
      'of body', async () => {
      const url = 'http://localhost:5000/documents';
      // Admin seed
      const seed = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
      const decoded = decodeSecretKeySeed({secretKeySeed: seed});

      const {methodFor} = await didKeyDriver.generate({seed: decoded});
      const invocationCapabilityKeyPair = methodFor(
        {purpose: 'capabilityInvocation'});

      const headers = await signCapabilityInvocation({
        url, method: 'post',
        headers: DEFAULT_HEADERS,
        capability: 'urn:zcap:root:' + encodeURIComponent(url),
        invocationSigner: invocationCapabilityKeyPair.signer(),
        capabilityAction: 'write',
        json: {name: 'test'}
      });

      let err;
      let res;
      try {
        res = await httpClient.post(url, {headers, json: {name: 'not test'}});
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.status.should.equal(500);
      err.data.name.should.equal('DataError');
      err.data.message.should.equal(
        'The "digest" header value does not match digest of body.');
    });
    it('should throw error if expected root capability does not match given ' +
      'capability', async () => {
      const url = 'http://localhost:5000/documents';
      const url2 = 'http://localhost:5000/test/abc';

      // Admin seed
      const seed = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
      const decoded = decodeSecretKeySeed({secretKeySeed: seed});

      const {methodFor} = await didKeyDriver.generate({seed: decoded});
      const invocationCapabilityKeyPair = methodFor(
        {purpose: 'capabilityInvocation'});

      const headers = await signCapabilityInvocation({
        url, method: 'post',
        headers: DEFAULT_HEADERS,
        capability: 'urn:zcap:root:' + encodeURIComponent(url2),
        invocationSigner: invocationCapabilityKeyPair.signer(),
        capabilityAction: 'write',
        json: {name: 'test'}
      });

      let err;
      let res;
      try {
        res = await httpClient.post(url, {headers, json: {name: 'test'}});
      } catch(e) {
        err = e;
      }
      should.not.exist(res);
      should.exist(err);
      err.status.should.equal(500);
      err.data.message.should.equal('The given capability ' +
        '"urn:zcap:root:http%3A%2F%2Flocalhost%3A5000%2Ftest%2Fabc" is not ' +
        'an expected root capability ' +
        '"urn:zcap:root:http%3A%2F%2Flocalhost%3A5000%2Fdocuments".');
    });
    it('should throw error if return value from "getExpectedTarget" is not ' +
      'an object with "expectedTarget" set to string or array', async () => {
      const url = 'http://localhost:5000/test/xyz';

      // Admin seed
      const seed = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
      const decoded = decodeSecretKeySeed({secretKeySeed: seed});

      const {methodFor} = await didKeyDriver.generate({seed: decoded});
      const invocationCapabilityKeyPair = methodFor(
        {purpose: 'capabilityInvocation'});

      const zcapClient = new ZcapClient({
        SuiteClass: Ed25519Signature2020,
        invocationSigner: invocationCapabilityKeyPair.signer()
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
      err.data.message.should.equal('Return value from "getExpectedTarget" ' +
        'must be an object with "expectedTarget" set to a string or an array.');
    });
  });
});
