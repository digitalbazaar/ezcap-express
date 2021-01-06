/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import {authorize} from '../lib/authorize.js';
import * as middleware from '../lib/main.js';

describe('ezcap-express', () => {
  it(`should properly export authorize`, async () => {
    (typeof authorize === 'function').should.be.true;
  });
  it(`should properly export functions from main.js`, async () => {
    (typeof middleware.authorize === 'function').should.be.true;
  });
});
