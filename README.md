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

This library provides Node.js express middleware that can be used to protect
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

- Node.js 14+ is supported.
- [Web Crypto API][] is required by dependencies. Node.js 14 must use a polyfill.

To install from NPM:

```
npm install @digitalbazaar/ezcap-express
```

To install development code:

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
import {authorizeZcapInvocation} from '@digitalbazaar/ezcap-express';

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

## Functions

<dl>
<dt><a href="#authorizeZcapInvocation">authorizeZcapInvocation(options)</a> ⇒ <code>function</code></dt>
<dd><p>Authorizes an incoming request.</p>
</dd>
<dt><a href="#authorizeZcapRevocation">authorizeZcapRevocation(options)</a> ⇒ <code>function</code></dt>
<dd><p>Authorizes a request to submit a zcap revocation.</p>
<p>This middleware is opinionated; it MUST be attached to an endpoint that
terminates in <code>/zcaps/revocations/:revocationId</code>. This to enable the
middleware to automatically generate expected values for running zcap checks
and to support a common, conventional revocation API pattern.</p>
<p>The pattern is in support of controlled objects on a service, aka
&quot;service objects&quot;. Each object&#39;s controller is used to populate the root
zcap for the object&#39;s controller field. This root zcap has an invocation
target that matches the URL for the service object, aka its
&quot;serviceObjectId&quot;.</p>
<p>Therefore, any route that matches an invocation target for a root zcap for
a service SHOULD attach this middleware to:</p>
<p><code>&lt;serviceObjectId&gt;/zcaps/revocations/:revocationId</code>.</p>
<p>This middleware will compute <code>serviceObjectId</code> by combining the expected
host with the subpath from the request URL that occurs before
<code>/zcaps/revocations/</code>. It assumes that the request URL will have this
pattern if the middleware code has been reached. IOW, <code>serviceObjectId</code> will
be set using:</p>
<p><code>https://&lt;expectedHost&gt;/&lt;URL subpath before &quot;/zcaps/revocations/&quot;&gt;</code>.</p>
<p>Note: This middleware does NOT support having <code>/zcaps/revocations/</code> appear
multiple places in the request URL.</p>
<p>Attaching this middleware will enable any zcaps delegated from the service
object&#39;s root zcap to be revoked without having to issue an additional zcap
to use the revocation endpoint. This middleware makes that possible by
supporting the invocation of a dynamically generated root zcap with an
invocation target of:</p>
<p><code>&lt;serviceObjectId&gt;/zcaps/revocations/:revocationId</code>.</p>
<p>This middleware will set the <code>controller</code> of this root zcap to all
controllers in the to-be-revoked zcap&#39;s delegation chain, permitting any
participant to revoke it. An error will be thrown prior to populating this
<code>controller</code> field if the root zcap in the to-be-revoked zcap&#39;s chain does
not have <code>&lt;serviceObjectId&gt;</code> as its invocation target (or a prefix of it).
This ensures that the only zcaps that have been delegated from a root zcap
using the service object&#39;s ID as part of its invocation target can be
revoked at its <code>/zcaps/revocations</code> route, i.e., other zcaps intended for
other service objects -- or entirely other services -- cannot be revoked via
this middleware.</p>
<p>This middleware will automatically generate two sets of expects values: one
for checking the invocation to revoke a capability and one for verifying the
delegation chain of the capability that is to be revoked. Only the expected
host value can and must be given as a parameter.</p>
<p>The expected values for checking the capability invocation will be:</p>
<p>host: <code>&lt;expectedHost&gt;</code>,
rootInvocationTarget: [
  // root zcap with this target, RZ1, can be delegated w/target attenuation
  // to allow delegates to revoke any zcap, Z1, with RZ1 as the root in its
  // chain, even if the delegate is not a controller in Z1&#39;s chain
  <code>&lt;serviceObjectId&gt;</code>,
  // root zcap that this target, RZ2, can be used to revoke a zcap, Z2,
  // with an &quot;id&quot; of <code>revocationId</code>; RZ2&#39;s controller will be populated
  // using all controllers from Z2&#39;s chain, enabling any controller in that
  // zcap&#39;s chain to invoke RZ2 to revoke Z2
  <code>&lt;serviceObjectId&gt;/zcaps/revocations/&lt;revocationId&gt;</code>,
],
action: &#39;write&#39;
.</p>
</dd>
</dl>

## Typedefs

<dl>
<dt><a href="#GetExpectedValues">GetExpectedValues</a></dt>
<dd></dd>
<dt><a href="#GetExpectedValues">GetExpectedValues</a> ⇒ <code><a href="#ExpectedValues">ExpectedValues</a></code></dt>
<dd><p>A function for returning expected values when checking a zcap invocation.</p>
</dd>
<dt><a href="#ExpectedValues">ExpectedValues</a> : <code>object</code></dt>
<dd><p>The expected values for checking a zcap invocation performed via an HTTP
request.</p>
</dd>
</dl>

<a name="authorizeZcapInvocation"></a>

## authorizeZcapInvocation(options) ⇒ <code>function</code>
Authorizes an incoming request.

**Kind**: global function  
**Returns**: <code>function</code> - Returns an Express.js style middleware route handler.  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| options | <code>object</code> |  | Options hashmap. |
| [options.allowTargetAttenuation] | <code>boolean</code> | <code>true</code> | Allow the   invocationTarget of a delegation chain to be increasingly restrictive   based on a hierarchical RESTful URL structure. |
| options.documentLoader | <code>object</code> |  | Document loader used to load   DID Documents, capability documents, and JSON-LD Contexts. |
| options.getExpectedValues | [<code>GetExpectedValues</code>](#GetExpectedValues) |  | Used to get the   expected values when checking the zcap invocation. |
| options.getRootController | <code>function</code> |  | Used to get the controller   of the root capability in the invoked capability's chain. |
| options.getVerifier | <code>function</code> |  | An async function to   call to get a verifier and verification method for the key ID. |
| [options.inspectCapabilityChain] | <code>function</code> |  | A function that can   inspect a capability chain, e.g., to check for revocations. |
| [options.maxChainLength] | <code>number</code> | <code>10</code> | The maximum length of the   capability delegation chain. |
| [options.maxClockSkew] | <code>number</code> | <code>300</code> | A maximum number of seconds   that clocks may be skewed when checking capability expiration date-times   against `date`, when comparing invocation proof creation time against   delegation proof creation time, and when comparing the capability   invocation expiration time against `now`. |
| [options.maxDelegationTtl] | <code>number</code> | <code>1000*60*60*24*90</code> | The maximum   milliseconds to live for a delegated zcap as measured by the time   difference between `expires` and `created` on the delegation proof. |
| [options.onError] | <code>function</code> |  | An error handler handler for   customizable error handling. |
| options.suiteFactory | <code>object</code> |  | A factory for creating the   supported suite(s) to use when verifying zcap delegation chains; this is   different from `getVerifier` which is used to produce a verifier for   verifying HTTP signatures used to invoke zcaps. |

<a name="authorizeZcapRevocation"></a>

## authorizeZcapRevocation(options) ⇒ <code>function</code>
Authorizes a request to submit a zcap revocation.

This middleware is opinionated; it MUST be attached to an endpoint that
terminates in `/zcaps/revocations/:revocationId`. This to enable the
middleware to automatically generate expected values for running zcap checks
and to support a common, conventional revocation API pattern.

The pattern is in support of controlled objects on a service, aka
"service objects". Each object's controller is used to populate the root
zcap for the object's controller field. This root zcap has an invocation
target that matches the URL for the service object, aka its
"serviceObjectId".

Therefore, any route that matches an invocation target for a root zcap for
a service SHOULD attach this middleware to:

`<serviceObjectId>/zcaps/revocations/:revocationId`.

This middleware will compute `serviceObjectId` by combining the expected
host with the subpath from the request URL that occurs before
`/zcaps/revocations/`. It assumes that the request URL will have this
pattern if the middleware code has been reached. IOW, `serviceObjectId` will
be set using:

`https://<expectedHost>/<URL subpath before "/zcaps/revocations/">`.

Note: This middleware does NOT support having `/zcaps/revocations/` appear
multiple places in the request URL.

Attaching this middleware will enable any zcaps delegated from the service
object's root zcap to be revoked without having to issue an additional zcap
to use the revocation endpoint. This middleware makes that possible by
supporting the invocation of a dynamically generated root zcap with an
invocation target of:

`<serviceObjectId>/zcaps/revocations/:revocationId`.

This middleware will set the `controller` of this root zcap to all
controllers in the to-be-revoked zcap's delegation chain, permitting any
participant to revoke it. An error will be thrown prior to populating this
`controller` field if the root zcap in the to-be-revoked zcap's chain does
not have `<serviceObjectId>` as its invocation target (or a prefix of it).
This ensures that the only zcaps that have been delegated from a root zcap
using the service object's ID as part of its invocation target can be
revoked at its `/zcaps/revocations` route, i.e., other zcaps intended for
other service objects -- or entirely other services -- cannot be revoked via
this middleware.

This middleware will automatically generate two sets of expects values: one
for checking the invocation to revoke a capability and one for verifying the
delegation chain of the capability that is to be revoked. Only the expected
host value can and must be given as a parameter.

The expected values for checking the capability invocation will be:

host: `<expectedHost>`,
rootInvocationTarget: [
  // root zcap with this target, RZ1, can be delegated w/target attenuation
  // to allow delegates to revoke any zcap, Z1, with RZ1 as the root in its
  // chain, even if the delegate is not a controller in Z1's chain
  `<serviceObjectId>`,
  // root zcap that this target, RZ2, can be used to revoke a zcap, Z2,
  // with an "id" of `revocationId`; RZ2's controller will be populated
  // using all controllers from Z2's chain, enabling any controller in that
  // zcap's chain to invoke RZ2 to revoke Z2
  `<serviceObjectId>/zcaps/revocations/<revocationId>`,
],
action: 'write'
.

**Kind**: global function  
**Returns**: <code>function</code> - Returns an Express.js style middleware route handler.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | Options hashmap. |
| options.documentLoader | <code>object</code> | Document loader used to load   DID Documents, capability documents, and JSON-LD Contexts. |
| options.expectedHost | <code>string</code> | The expected host header value   when checking the zcap invocation. |
| options.getRootController | <code>function</code> | Used to get the controller   of the root capability for the service object. |
| options.getVerifier | <code>function</code> | An async function to   call to get a verifier and verification method for the key ID. |
| [options.inspectCapabilityChain] | <code>function</code> | A function that can   inspect a capability chain, e.g., to check for revocations; it will be   used when verifying the invocation and the delegation chain for the   to-be-revoked capability. |
| [options.onError] | <code>function</code> | An error handler handler for   customizable error handling. |
| options.suiteFactory | <code>object</code> | A factory for creating the   supported suite(s) to use when verifying zcap delegation chains; this is   different from `getVerifier` which is used to produce a verifier for   verifying HTTP signatures used to invoke zcaps. |

<a name="GetExpectedValues"></a>

## GetExpectedValues
**Kind**: global typedef  
<a name="GetExpectedValues"></a>

## GetExpectedValues ⇒ [<code>ExpectedValues</code>](#ExpectedValues)
A function for returning expected values when checking a zcap invocation.

**Kind**: global typedef  
**Returns**: [<code>ExpectedValues</code>](#ExpectedValues) - - The expected values.  

| Param | Type | Description |
| --- | --- | --- |
| options | <code>object</code> | The options passed to the function. |
| options.req | <code>object</code> | The express request. |

<a name="ExpectedValues"></a>

## ExpectedValues : <code>object</code>
The expected values for checking a zcap invocation performed via an HTTP
request.

**Kind**: global typedef  
**Properties**

| Name | Type | Description |
| --- | --- | --- |
| [action] | <code>string</code> | The expected capability action; if no action   is specified during an invocation check, then a default action will be   determined based on the HTTP method from the request -- which is only safe   provided that the handler code path is also determined based on the HTTP   method in the request (i.e., typical method-based express/connect   routing); if the handler code path is determined by some other means,   e.g., the request body, then `action` MUST be set. |
| host | <code>string</code> | The expected host in the request header. |
| rootInvocationTarget | <code>string</code> \| <code>Array</code> | The expected invocation   target for every acceptable root capability; each string must express an   absolute URI. |
| [target] | <code>string</code> | The expected invocation target; if no target   is specified during an invocation check, then the target will default to   the absolute URL computed from the relative request URL and expected host   value. |


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

[Web Crypto API]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
