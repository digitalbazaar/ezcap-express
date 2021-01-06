module.exports = {
  root: true,
  extends: ['eslint-config-digitalbazaar'],
  env: {
    mocha: true,
    node: true
  },
  globals: {
    assertNoError: true,
    should: true
  },
  parserOptions: {
  // this is required for dynamic import()
    ecmaVersion: 2020
  },
  ignorePatterns: ['node_modules']
};
