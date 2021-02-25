/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import * as middleware from '..';
import {authorizeZcapInvocation} from '..';

describe('ezcap-express', () => {
  describe('verify proper exports', () => {
    it(`should properly export authorize`, async () => {
      should.exist(authorizeZcapInvocation);
      authorizeZcapInvocation.should.be.a('function');
    });
    it(`should properly export functions from main.js`, async () => {
      should.exist(middleware.authorizeZcapInvocation);
      middleware.authorizeZcapInvocation.should.be.a('function');
    });
  });
});
