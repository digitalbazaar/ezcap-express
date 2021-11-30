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
        res.json(
          req.clientMetadata
        );
      }
    );
    let requester;
    before(async () => {
      requester = chai.request(app).keepOpen();
    });
    after(async () => {
      requester.close();
    });
    it('should throw internal server error', async () => {
    // eslint-disable-next-line no-unused-vars
    //   const zcap = {
    //     '@context': [
    //       'https://w3id.org/zcap/v1',
    //       'https://w3id.org/security/suites/ed25519-2020/v1'
    //     ],
    //     id: 'urn:zcap:delegated:z9gLKoFmKHwhxCzmo91Ywnh',
    // eslint-disable-next-line max-len
    //     parentCapability: 'urn:zcap:root:https%3A%2F%2Fexample.com%2Fdocuments',
    //     invocationTarget: 'https://example.com/documents',
    // eslint-disable-next-line max-len
    //     controller: 'did:key:z6MknBxrctS4KsfiBsEaXsfnrnfNYTvDjVpLYYUAN6PX2EfG',
    //     expires: '2022-11-28T20:53:06Z',
    //     allowedAction: [
    //       'read'
    //     ],
    //     proof: {
    //       type: 'Ed25519Signature2020',
    //       created: '2021-11-28T20:53:06Z',
    // eslint-disable-next-line max-len
    //       verificationMethod: 'did:key:z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR#z6Mkfeco2NSEPeFV3DkjNSabaCza1EoS3CmqLb1eJ5BriiaR',
    //       proofPurpose: 'capabilityDelegation',
    //       capabilityChain: [
    //         'urn:zcap:root:https%3A%2F%2Fexample.com%2Fdocuments'
    //       ],
    // eslint-disable-next-line max-len
    //       proofValue: 'z244yxzRuFMyGfK85QcE6UewEZ3JpGDDTCvBKuxNiwdnxF3AmsSAoVYTBPLvFpYV7SeeWB4tUBGMGTF7pka6xR3av'
    //     }
    //   };
      const res = await requester.post('/documents')
        .send({});
      res.status.should.equal(500);
    });
  });
});
