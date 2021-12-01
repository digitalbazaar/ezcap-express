/* eslint-disable max-len */
/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import chaiHttp from 'chai-http';
import express from 'express';
import {authorizeZcapInvocation} from '..';
import {securityLoader} from '@digitalbazaar/security-document-loader';
import zcapCtx from 'zcap-context';
import {ZcapClient, getCapabilitySigners} from '@digitalbazaar/ezcap';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import * as didKey from '@digitalbazaar/did-method-key';

const didKeyDriver = didKey.driver();
const loader = securityLoader();
loader.addStatic(zcapCtx.CONTEXT_URL, zcapCtx.CONTEXT);

const documentLoader = loader.build();

chai.use(chaiHttp);

describe('ezcap-express', () => {
  describe('authorizeZcapInvocation', () => {
    const app = express();

    // eslint-disable-next-line no-unused-vars
    function errorHandler(err, req, res, next) {
      res.status(500).send(err.message);
    }

    app.post('/documents',
      authorizeZcapInvocation({
        documentLoader,
        getExpectedTarget() {
          return {
            expectedTarget: [
              'https://example.com', 'https://example.com/documents'
            ]
          };
        },
        getRootController() {
          // root controller(Admin DID)
          return 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR';
        },
        expectedHost: 'https://example.com'
      }),
      // eslint-disable-next-line no-unused-vars
      (req, res, next) => {
        res.json(req.clientMetadata);
      }
    );
    app.use(errorHandler);

    let requester;
    before(async () => {
      requester = chai.request(app).keepOpen();
    });
    after(async () => {
      requester.close();
    });
    it('should error if missing authorization header', async () => {
      const res = await requester.post('/documents').send({});
      const {error} = res;
      error.status.should.equal(500);
      error.text.should.equal('Missing or invalid "authorization" header.');
    });
    it.skip('should error if authorization header is invalid', async () => {
      const url = 'https://example.com/documents';
      // Admin DID
      //   const did = 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR'
      //   const didDocument = await didKeyDriver.get({did});
      const {didDocument, keyPairs} = await didKeyDriver.generate();
      const {invocationSigner, delegationSigner} = getCapabilitySigners({
        didDocument, keyPairs});
      const zcapClient = new ZcapClient({
        SuiteClass: Ed25519Signature2020,
        invocationSigner, delegationSigner
      });

      try {
        const response = await zcapClient.write({url});
        console.log(response);
      } catch(error) {
        console.log(error);
      }
    });
  });
});
