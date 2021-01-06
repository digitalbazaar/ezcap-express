/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
export default new Proxy({}, {
  get() {
    return () => {};
  }
});
