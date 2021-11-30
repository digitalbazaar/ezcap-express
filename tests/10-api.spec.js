/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import chaiHttp from 'chai-http';
import express from 'express';
import {authorizeZcapInvocation} from '..';
import {wrappedDocumentLoader} from '../lib/helpers';

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
        documentLoader: wrappedDocumentLoader,
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
  });
});
