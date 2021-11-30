/* eslint-disable max-len */
/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import chaiHttp from 'chai-http';
import express from 'express';
import {authorizeZcapInvocation} from '..';
import didIo from 'did-io';
import didKeyDriver from 'did-method-key';
import jldl from 'jsonld-document-loader';

const _documentLoader = new jldl.JsonLdDocumentLoader();

didIo.use('key', didKeyDriver.driver());

async function documentLoader(url) {
  let document;
  if(url.startsWith('did:')) {
    document = await didIo.get({did: url, forceConstruct: true});
    return {
      contextUrl: null,
      documentUrl: url,
      document
    };
  }

  // finally, try the base document loader
  return _documentLoader(url);
}

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
      const res = await requester.post('/documents')
        .set('authorization', 'Signature keyId="did:key:z6MkmQAxh4enjD3hU9HF8E5L53LAB7ZVeyMPXmKMnSziHdWh#z6MkmQAxh4enjD3hU9HF8E5L53LAB7ZVeyMPXmKMnSziHdWh",headers="(key-id) (created) (expires) (request-target) host capability-invocation content-type digest",signature="/eYQL/op2qt9N9j0aJlaeYUJI5RAyUTM0uwYFsQOFwSOjk3RQ0WBDvG8+N2BMITWEw+4TPBSOqN/8gUZM9E8DA==",created="1638291177",expires="1638291777"')
        .set('capability-invocation', 'zcap capability="H4sIAAAAAAAAA72TW3OaQBSA_wudvMUSbqI8FSFMEsUxVTTaycMKR9hwWbK7oJDJf-9iYpK204c-NDM7zHLu5ztnn6RvISk4HLhk_ZASzktmyfJew9FXQmO5DVEp14p0_qeKQVhRzBuZVZgDkyFSDUMZ9tQL9aJzuT-XcCRZUkULqwtjtYqtKNOUYhXl-ipRw9Rx1t7daCmidzVQkmVAhUeEIyuFxmr7fprf2odEh-LB1ZJgeOUNLo2JoU3skblZQuPP7vKxX8xbfBWtEhGHwg4oFCFcR78FwqOaBP3DLE3zAPm1sfU2e-7SZnxTpYU9e3yAoV6YQ9W5aadf_tWhJ7L0RI9oizOB5LqoSYg4JoUoCWUZ2UNkh8d_S2I47sT4zWaBaAwC_9MLrxPoTKizhDBuKQNd1-Q0Z7JIwzihgnarDJv1oroMvJxO17mvuiZ365npH206NS9ipi4mNp7jBzADX5sXCduJzLwpQeS5fJnXEije4ZdKxtB00xM2ZbXNcGhnGLHP5Cg9i9RIDJA7bzA_rhAlhFtHQGeafaZ64rxhEpIjKCETqLrvCZa4_xVX16uIuuvw_wpmLuaEeEXhFUlIAXHoJiQESk9RetrFQulbhmoZ5kYY1B9I-sAT8qkreGpkVtGSsK6P9310IYP4tI_vYidBuOie_f_ke_9a1xJlVVdVa_PbFBu6YgSutt89xis90fVNNardAcw3q8mV9xgcdNVYu-WwnxMnwGFEExu5g8ArI2N9B9-3TgyeyfhmOlDNZD3wo9lYen7-CVSP-MvMBAAA",action="sign"')
        .send({});
      console.log(res, '<><><><>res');

    });
  });
});
