/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import express from 'express';
import {signCapabilityInvocation} from 'http-signature-zcap-invoke';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {ZcapClient} from '@digitalbazaar/ezcap';
import {httpClient, DEFAULT_HEADERS} from '@digitalbazaar/http-client';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import zcapCtx from 'zcap-context';
import {authorizeZcapInvocation, authorizeZcapRevocation} from '../lib';
import {getInvocationSigner} from './helpers';
import https from 'https';
import fs from 'fs';
import ed25519 from 'ed25519-signature-2020-context';

const loader = securityLoader();
loader.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);

const documentLoader = loader.build();

const TEST_SERVER_PORT = 5000;
const BASE_URL = `https://localhost:${TEST_SERVER_PORT}`;

const key = fs.readFileSync(__dirname + '/key.pem');
const cert = fs.readFileSync(__dirname + '/cert.pem');

const agent = new https.Agent({
  rejectUnauthorized: false
});
function _startServer({app, port = TEST_SERVER_PORT}) {
  return new Promise(resolve => {
    const server = https.createServer({key, cert}, app);
    server.listen(port, () => {
      console.log(`Test server listening at ${BASE_URL}`);
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
        expectedTarget: [`${BASE_URL}/documents`]
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
        `${BASE_URL}/documents/${encodeURIComponent(req.params.id)}`;
      // intentionally set return value to not be an object
      return expectedTarget;
    },
    expectedHost: 'localhost:5000'
  }),
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    res.json({message: 'Get request was successful.'});
  });

app.post('/revocations/:id',
  authorizeZcapRevocation({
    documentLoader,
    suiteFactory() {
      return new Ed25519Signature2020();
    },
    getRootController() {
      // root controller(Admin DID)
      return 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR';
    },
    getExpectedTarget({req}) {
      return {
        expectedTarget: [
          `${BASE_URL}/revocations/${req.params.id}`
        ]
      };
    },
    expectedHost: 'localhost:5000',
    inspectCapabilityChain() {
      // checking previously revoked zcaps is not part of the tests
      return {valid: true};
    }
  }),
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    res.json({message: 'Revocation was successful.'});
  });
app.post('/revocations',
  authorizeZcapRevocation({
    documentLoader,
    suiteFactory() {
      return new Ed25519Signature2020();
    },
    getRootController() {
      // root controller(Admin DID)
      return 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR';
    },
    getExpectedTarget() {
      return {
        expectedTarget: [
          `${BASE_URL}/revocations`
        ]
      };
    },
    expectedHost: 'localhost:5000',
    inspectCapabilityChain() {
      // checking previously revoked zcaps is not part of the tests
      return {valid: true};
    }
  }),
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    res.json({message: 'Revocation was successful.'});
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
      const url = `${BASE_URL}/documents`;
      // Admin seed
      const seed = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
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
      err.status.should.equal(500);
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
      err.message.should.equal('Forbidden');
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
      err.status.should.equal(500);
      err.data.name.should.equal('DataError');
      err.data.message.should.equal(
        'A "digest" header must be present when an HTTP body is present.');
    });
    it('should throw error if digest header value does not match digest ' +
      'of body', async () => {
      const url = `${BASE_URL}/documents`;
      // Admin seed
      const seed = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
      const invocationSigner = await getInvocationSigner({seed});

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
      err.status.should.equal(500);
      err.data.name.should.equal('DataError');
      err.data.message.should.equal(
        'The "digest" header value does not match digest of body.');
    });
    it('should throw error if expected root capability does not match given ' +
      'capability', async () => {
      const url = `${BASE_URL}/documents`;
      const url2 = `${BASE_URL}/test/abc`;

      // Admin seed
      const seed = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
      const invocationSigner = await getInvocationSigner({seed});

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
      err.status.should.equal(500);
      err.data.message.should.equal('The given capability ' +
        '"urn:zcap:root:https%3A%2F%2Flocalhost%3A5000%2Ftest%2Fabc" is not ' +
        'an expected root capability ' +
        '"urn:zcap:root:https%3A%2F%2Flocalhost%3A5000%2Fdocuments".');
    });
    it('should throw error if return value from "getExpectedTarget" is not ' +
      'an object with "expectedTarget" set to string or array', async () => {
      const url = `${BASE_URL}/test/xyz`;

      // Admin seed
      const seed = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
      const invocationSigner = await getInvocationSigner({seed});

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
      err.data.message.should.equal('Return value from "getExpectedTarget" ' +
        'must be an object with "expectedTarget" set to a string or an array.');
    });
  });
  describe('authorizeZcapRevocation', () => {
    describe('/revocations/:id', () => {
      it('should succeed if correct data is passed', async () => {
        const url = `${BASE_URL}/revocations/some-id`;

        const bobSeed = 'z1AnZce3gUvSfVbsbqpgH9LNtmBuve4zQdYwdpEp22YQzB4';
        const invocationSigner = await getInvocationSigner({seed: bobSeed});

        const capability = {
          '@context': [
            zcapCtx.CONTEXT_URL,
            ed25519.CONTEXT_URL
          ],
          id: 'urn:zcap:delegated:zMdWQBpdnyg1m26Kx2HVya4',
          parentCapability: 'urn:zcap:root:' + encodeURIComponent(url),
          invocationTarget: 'https://localhost:5000/revocations/some-id',
          // eslint-disable-next-line max-len
          controller: 'did:key:z6Mki68HpLhwaUZub3dqbmGCiMm9GfjzX9pBiK8hvezxuCix',
          expires: '2022-12-16T22:03:14Z',
          allowedAction: [
            'write'
          ],
          proof: {
            type: 'Ed25519Signature2020',
            created: '2021-12-16T22:03:14Z',
            // eslint-disable-next-line max-len
            verificationMethod: 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR#z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR',
            proofPurpose: 'capabilityDelegation',
            capabilityChain: [
              'urn:zcap:root:' + encodeURIComponent(url)
            ],
            // eslint-disable-next-line max-len
            proofValue: 'z54VSEwtmS8HbEGe97h2fy2gHhyDw8aFwmgMZ2ENPjY4YLSf6gcJiE9zPJ1MxkDiKti5NkpAW5M7QotNNtUhRHBe1'
          }
        };
        const zcapClient = new ZcapClient({
          agent,
          SuiteClass: Ed25519Signature2020,
          invocationSigner
        });
        let err;
        let res;
        try {
          res = await zcapClient.write({url, json: capability});
        } catch(e) {
          err = e;
        }
        should.exist(res);
        res.status.should.equal(200);
        should.not.exist(err);
        res.data.message.should.equal('Revocation was successful.');
      });
      it('throws error if capability id starts with "urn:zcap:root"',
        async () => {
          const url = `${BASE_URL}/revocations/some-id`;

          const bobSeed = 'z1AnZce3gUvSfVbsbqpgH9LNtmBuve4zQdYwdpEp22YQzB4';
          const invocationSigner = await getInvocationSigner({seed: bobSeed});

          const rootCapability = {
            '@context': [
              zcapCtx.CONTEXT_URL,
              ed25519.CONTEXT_URL
            ],
            id: 'urn:zcap:root:zWH71D96BNXEZtKoL3i1oPx',
          };
          'urn:zcap:root:' + encodeURIComponent(url);
          const zcapClient = new ZcapClient({
            agent,
            SuiteClass: Ed25519Signature2020,
            invocationSigner
          });
          let err;
          let res;
          try {
            res = await zcapClient.write({url, json: rootCapability});
          } catch(e) {
            err = e;
          }
          should.not.exist(res);
          should.exist(err);
          err.data.name.should.equal('NotAllowedError');
          err.data.message.should.equal('A root capability cannot be revoked.');
        });
      it('throws error if capability is invalid',
        async () => {
          const url = `${BASE_URL}/revocations/some-id`;

          const bobSeed = 'z1AnZce3gUvSfVbsbqpgH9LNtmBuve4zQdYwdpEp22YQzB4';
          const invocationSigner = await getInvocationSigner({seed: bobSeed});

          // Invalid capability since it does not contain proof
          const invalidCapability = {
            '@context': [
              zcapCtx.CONTEXT_URL,
              ed25519.CONTEXT_URL
            ],
            id: 'urn:zcap:delegated:zWH71D96BNXEZtKoL3i1oPx',
            parentCapability: 'urn:zcap:root:' + encodeURIComponent(url),
            invocationTarget: 'https://localhost:5000/revoke',
            // eslint-disable-next-line max-len
            controller: 'did:key:z6MknBxrctS4KsfiBsEaXsfnrnfNYTvDjVpLYYUAN6PX2EfG',
            expires: '2022-12-15T22:19:48Z',
            allowedAction: [
              'write'
            ]
          };
          const zcapClient = new ZcapClient({
            agent,
            SuiteClass: Ed25519Signature2020,
            invocationSigner
          });
          let err;
          let res;
          try {
            res = await zcapClient.write({url, json: invalidCapability});
          } catch(e) {
            err = e;
          }
          should.not.exist(res);
          should.exist(err);
          err.data.name.should.equal('DataError');
          err.data.message.should.equal(
            'The provided capability delegation is invalid.');
        });
    });
    describe('/revocations', () => {
      it('should defer to "getRootController" if `/revocations/` is not in ' +
        'the root invocation target', async () => {

        const url = `${BASE_URL}/revocations`;

        const adminSeed = 'z1AZK4h5w5YZkKYEgqtcFfvSbWQ3tZ3ZFgmLsXMZsTVoeK7';
        const invocationSigner = await getInvocationSigner({seed: adminSeed});

        const capability = {
          '@context': [
            zcapCtx.CONTEXT_URL,
            ed25519.CONTEXT_URL
          ],
          id: 'urn:zcap:delegated:zAC5i8cRwdJYcsWSh2PUtZB',
          parentCapability: 'urn:zcap:root:' + encodeURIComponent(url),
          invocationTarget: 'https://localhost:5000/revocations',
          // eslint-disable-next-line max-len
          controller: 'did:key:z6Mki68HpLhwaUZub3dqbmGCiMm9GfjzX9pBiK8hvezxuCix',
          expires: '2022-12-17T01:42:39Z',
          allowedAction: [
            'write'
          ],
          proof: {
            type: 'Ed25519Signature2020',
            created: '2021-12-17T01:42:39Z',
            // eslint-disable-next-line max-len
            verificationMethod: 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR#z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR',
            proofPurpose: 'capabilityDelegation',
            capabilityChain: [
              'urn:zcap:root:' + encodeURIComponent(url)
            ],
            // eslint-disable-next-line max-len
            proofValue: 'z5S7BnH5S9sbLDsdR8iza2KeXrQRYKgocsmeEAz7E2dhdxcuyk3hWvZn64EkT7JjqtzSDt4QUezCkHkGKR2sEPiea'
          }
        };
        const zcapClient = new ZcapClient({
          agent,
          SuiteClass: Ed25519Signature2020,
          invocationSigner
        });
        let err;
        let res;
        try {
          res = await zcapClient.write({url, json: capability});
        } catch(e) {
          err = e;
        }
        should.exist(res);
        res.status.should.equal(200);
        should.not.exist(err);
        res.data.message.should.equal('Revocation was successful.');
      });
    });
  });
});
