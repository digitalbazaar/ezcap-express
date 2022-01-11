# ezcap express library (@digitalbazaar/ezcap-express)

[![Node.js CI](https://github.com/digitalbazaar/ezcap-express/workflows/Node.js%20CI/badge.svg)](https://github.com/digitalbazaar/ezcap-express/actions?query=workflow%3A%22Node.js+CI%22)

> zcap's gettin' you down? Get on the Ezcap Express! Woot WOoot! 🚇🎉

Connect middleware that provides easy Authorization Capability (zcap) support
for express.js HTTP servers and more.

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
resources on HTTP servers using Authorization Capabilities (zcaps). The library
is configured with secure and sensible defaults to help developers get started
quickly and ensure that their server code is production-ready.

## Security

The security characteristics of this library are largely influenced by design
decisions made by client and server software. For clients, implementers should
pay particular attention to secure private key management. For servers, security
characteristics are largely dependent on how carefully the server manages zcap
registrations, zcap invocations, and zcap delegations. Bugs or failures related
to client key management, or server zcap validity checking will lead to security
failures. It is imperative that implementers audit their implementations,
preferably via parties other than the implementer.

## Install

- Node.js 14+ is required.

```sh
git clone git@github.com:digitalbazaar/ezcap-express.git
cd ezcap-express
npm install
```

## Usage

* [Define getCapabilityController](#define-getcapabilitycontroller)
* [Define documentLoader](#define-documentloader)
* [Define authorizeMyZcapInvocation](#define-authorizemyzcapinvocation)
* [Use authorizeMyZcapInvocation](#use-authorizemyzcapinvocation)
* [Define getRootController](#define-getrootcontroller)

### Define getRootController

```js
// this will only be called if `rootInvocationTarget` matches
// one of the expected root invocation targets specified
async function getRootController({
  req, rootCapabilityId, rootInvocationTarget
}) {
  // get controller for a service object from a database
  let controller;
  try {
    const record = await database.getMyServiceObjectById({
      // typically, root invocation target is a service object ID
      id: rootInvocationTarget
    });
    controller = record.controller;
  } catch(e) {
    if(e.type === 'NotFoundError') {
      const url = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
      throw new Error(
        `Invalid capability identifier "${rootCapabilityId}" ` +
        `for URL "${url}".`);
    }
    throw e;
  }

  // return the service object's controller so it will be
  // added to the root capability for the service object
  return controller;
}
```

### Define documentLoader

```js
import didIo from 'did-io';
import didKeyDriver from 'did-method-key';
import jldl from 'jsonld-document-loader';

const _documentLoader = new jldl.JsonLdDocumentLoader();

// support did:key
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
```

### Define authorizeMyZcapInvocation

```js
const {authorizeZcapInvocation} = require('ezcap-express');

async function authorizeMyZcapInvocation({expectedAction} = {}) {
  return authorizeZcapInvocation({
    getExpectedValues({req}) {
      const expectedHost = 'ezcap.example';
      const {localId} = req.params;
      const serviceObjectId =
        `https://${expectedHost}/${encodeURIComponent(localId)}`;
      return {
        action: expectedAction,
        host: expectedHost,
        rootInvocationTarget: serviceObjectId
      };
    },
    getRootController
  });
};
```

### Use authorizeMyZcapInvocation

```js
import express from 'express';
import asyncHandler from 'express-async-handler';

const app = express();

app.post('/my-objects/:localId',
  authorizeMyZcapInvocation(),
  asyncHandler(async (req, res) => {
    // your code goes here
    // req.zcap is available to provide authz information
  }));
```

## API Reference

The ezcap approach is opinionated in order to make using zcaps a pleasant
experience for developers. To do this, it makes two fundamental assumptions
regarding the systems it interacts with:

* The systems are HTTP-based and REST-ful in nature.
* The REST-ful systems center around reading and writing resources.

If these assumptions do not apply to your system, the
[zcap](https://github.com/digitalbazaar/zcap) library might
be a better, albeit more complex, solution for you.

Looking at each of these core assumptions more closely will help explain how designing systems to these constraints make it much easier to think about
zcaps. Let's take a look at the first assumption:

> The systems are HTTP-based and REST-ful in nature.

Many modern systems tend to have HTTP-based interfaces that are REST-ful in
nature. That typically means that most resource URLs are organized by namespaces, collections, and items:
`/<root-namespace>/<collection-id>/<item-id>`. In practice,
this tends to manifest itself as URLs that look like
`/my-account/things/1`. The ezcap approach maps the authorization model
in a 1-to-1 way to the URL. Following along with the example, the root
capability would then be `/my-account`, which you will typically create and
have access to. You can then take that root capability and delegate access
to things like `/my-account/things` to let entities you trust modify the
`things` collection. You can also choose to be more specific and only
delegate to `/my-account/things/1` to really lock down access. ezcap attempts
to keep things very simple by mapping URL hierarchy to authorization scope.

Now, let's examine the second assumption that makes things easier:

> The REST-ful systems center around reading and writing resources.

There is an incredible amount of flexibility that zcaps provide. You can
define a variety of actions: read, write, bounce, atomicSwap, start, etc.
However, all that flexibility adds complexity and one of the goals of ezcap
is to reduce complexity to the point where the solution is good enough for
80% of the use cases. A large amount of REST-ful interactions tend to
revolve around reading and writing collections and the items in those
collections. For this reason, there are only two actions that are exposed
by default in ezcap: read and write. Keeping the number of actions to a
bare minimum has allowed implementers to achieve very complex use cases with
very simple code.

These are the two assumptions that ezcap makes and with those two assumptions,
80% of all use cases we've encountered are covered.

<a name="authorizeZcapInvocation"></a>

## authorizeZcapInvocation(options) ⇒ <code>function</code>
Authorizes an incoming request.

**Kind**: global function
**Returns**: <code>function</code> - Returns an Express.js middleware route handler.

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | Options hashmap. |
| options.documentLoader | <code>object</code> | Document loader used to load   DID Documents, capability documents, and JSON-LD Contexts. |
| [options.expectedAction] | <code>string</code> | The expected action for the   invoked capability. |
| options.expectedHost | <code>string</code> | The expected host for the invoked   capability. |
| [options.expectedTarget] | <code>string</code> \| <code>Array.&lt;string&gt;</code> | The expected   target(s) for the invoked capability. |
| options.getRootController | <code>function</code> | Used to get the root capability   controller for the given root capability ID. |
| [options.logger] | <code>object</code> | The logger instance to use. |
| [options.suite] | <code>object</code> | The expected cryptography suite to use when   verifying digital signatures. |

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
