# ezcap express library (ezcap-express)

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
* [Define getCapabilityController](#define-getcapabilitycontroller)

### Define getCapabilityController

```js
async function getCapabilityController({req}) {
  const capabilityId = req.params;
  let controller;

  // Assume something like this URL pattern for
  // server URLs: /accounts/:capabilityId/things/1
  if(!capabilityId) {
    throw new Error(`Root capability identifier could not be determined for URL (${req.url}).`);
  }

  // get associated capability controller from database
  try {
    const id = capabilityId;
    const record = await database.getControllerForId({id});
    controller = record.controller;
  } catch(e) {
    if(e.type === 'NotFoundError') {
      throw new Error(`Invalid capability identifier ` +
        `(${capabilityId}) for URL (${req.url})'.`);
    }
  }

  // return the controller for the request URL
  return controller;
}
```

### Define documentLoader

```js
import didIo from 'did-io';
import didKeyDriver from 'did-method-key';
import {documentLoader as _documentLoader} from 'bedrock-jsonld-document-loader';
const capabilityIdRegex = new RegExp('\/accounts\/([^/]+).*');

// support did:key
didIo.use('key', didKeyDriver.driver());

async function documentLoader(url) {
  let document;
  if(url.startsWith('did:')) {
    document = await didIo.get({did: url, forceConstruct: true});
    if(url.startsWith('did:v1')) {
      document = document.doc;
    }
    return {
      contextUrl: null,
      documentUrl: url,
      document
    };
  }

  if(url.startsWith('urn:zcap:root:')) {
    // dynamically generate zcap for root capability if applicable
    const targetUrl = decodeURIComponent(url.slice(14));
    const parsedUrl = URL.parse(targetUrl);
    const invocationTarget =
      'https://zcap.example' + parsedUrl.pathname;
    const capabilityId = parsedUrl.pathname.match(capabilityIdRegex)[1];
    const req = {
      url: parsedUrl.pathname,
      params: {capabilityId}
    };
    const controller = await getCapabilityController({req});
    const zcap = {
      '@context': SECURITY_CONTEXT_V2_URL,
      id: 'urn:zcap:root:' + encodeURIComponent(invocationTarget),
      invocationTarget,
      controller
    };
    return {
      contextUrl: null,
      documentUrl: url,
      document: zcap
    };
  }

  // finally, try the base document loader
  return _documentLoader(url);
}
```

### Define authorizeMyZcapInvocation

```js
const {asyncHandler} = require('bedrock-express');
const {authorizeZcapInvocation} = require('ezcap-express');

async function authorizeMyZcapInvocation({expectedTarget, expectedAction} = {}) {
  return asyncHandler(authorizeZcapInvocation({
    expectedHost: 'ezcap.example',
    getCapabilityController, documentLoader, expectedTarget, expectedAction
  }));
};
```

### Use authorizeMyZcapInvocation

```js
import express from 'express';
const {asyncHandler} = require('bedrock-express');
import {authorize} from '@digitalbazaar/ezcap-express';

const app = express();

app.post('/foo',
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
[zcapld](https://github.com/digitalbazaar/zcapld) library might
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
| [options.expectedAction] | <code>string</code> | The expected target for the   invoked capability. |
| [options.getController] | <code>Promise.&lt;string&gt;</code> | Gets the controller URL   for the invoked target. If this value isn't specified, getRootCapability   must be specified. |
| [options.getRootCapability] | <code>Promise</code> | The expected target for the   invoked capability. If this value isn't specified, getController must be   specified. |
| [options.suite] | <code>class</code> | The expected cryptography suite to use when   verifying digital signatures. |


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
