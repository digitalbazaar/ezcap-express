/* eslint-disable max-len */
/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import {decodeSecretKeySeed} from 'bnid';
import express from 'express';
import * as didKey from '@digitalbazaar/did-method-key';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {ZcapClient} from '@digitalbazaar/ezcap';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import zcapCtx from 'zcap-context';
import {authorizeZcapInvocation} from '..';
import {httpClient} from '@digitalbazaar/http-client';

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
// mount the test routes
app.post('/documents',
  authorizeZcapInvocation({
    documentLoader,
    getExpectedTarget() {
      return {
        expectedTarget: [
          'http://localhost:5000', 'http://localhost:5000/documents'
        ]
      };
    },
    getRootController() {
    // root controller(Admin DID)
      return 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR';
    },
    expectedHost: 'http://localhost:5000'
  }),
  // eslint-disable-next-line no-unused-vars
  (req, res, next) => {
    res.json(req.clientMetadata);
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
      err.data.message.should.equal('Missing or invalid "authorization" header.');
    });
    it.skip('should succeed if  header is valid', async () => {
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
      const doc = {name: 'test'};

      try {
        const response = await zcapClient.write({url, json: doc});
        console.log(response);
      } catch(error) {
        console.log(error);
      }
    });
  });
});
