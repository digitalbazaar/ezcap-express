# ezcap express library (@digitalbazaar/ezcap-express)

[![Node.js CI](https://github.com/digitalbazaar/ezcap-express/workflows/Node.js%20CI/badge.svg)](https://github.com/digitalbazaar/ezcap-express/actions?query=workflow%3A%22Node.js+CI%22)

> A collection of Authorization Capability middleware for node.js express-based
> HTTP servers.

## Table of Contents

- [Background](#background)
- [Security](#security)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Background

This library provides node.js express middleware that can be used to protect
resources on HTTP servers using Authorization Capabilities (ZCAPs). The library
is configured with secure and sensible defaults to help developers get started
quickly and ensure that their server code is production-ready.

## Security

TBD

## Install

- Node.js 14+ is required.

```sh
git clone git@github.com:digitalbazaar/ezcap-express.git
cd ezcap-express
npm install
```

## Usage

This library exports the following functions:

* `authorize`

### `authorize()`

This is an Express.js middleware that returns an authorization route handler.

```js
import express from 'express';
import {authorize} from '@digitalbazaar/ezcap-express';

const app = express();

app.post('/foo',
  authorize({
      logger,
      httpsAgent,
      fn: async req => {
        // perform custom zcap authorization processing
        return response;
      })      
    }),
  async (req, res) => {
    // if code gets here, zcap invocation is valid
    const {invoker} = req.zcap; // provides root invoker of zcap
  }
);
```

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the Readme, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar
