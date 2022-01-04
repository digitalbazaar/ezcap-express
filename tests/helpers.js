/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as didKey from '@digitalbazaar/did-method-key';
import {createRootCapability} from '@digitalbazaar/zcapld';
import {decodeSecretKeySeed} from 'bnid';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {ZcapClient} from '@digitalbazaar/ezcap';

const didKeyDriver = didKey.driver();

export async function getInvocationSigner({seed}) {
  const decoded = decodeSecretKeySeed({secretKeySeed: seed});
  const {methodFor} = await didKeyDriver.generate({seed: decoded});

  const invocationCapabilityKeyPair = methodFor(
    {purpose: 'capabilityInvocation'});
  return invocationCapabilityKeyPair.signer();
}

export async function getDelegationSigner({seed}) {
  const decoded = decodeSecretKeySeed({secretKeySeed: seed});
  const {methodFor} = await didKeyDriver.generate({seed: decoded});

  const delegationCapabilityKeyPair = methodFor(
    {purpose: 'capabilityDelegation'});
  return delegationCapabilityKeyPair.signer();
}

export async function delegate({seed, rootInvocationTarget, controller}) {
  const delegationSigner = await getInvocationSigner({seed});
  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    delegationSigner
  });
  // key ID is always `<controller>#...`
  const {id: keyId} = delegationSigner;
  const rootController = keyId.substr(0, keyId.indexOf('#'));
  const rootZcap = createRootCapability({
    controller: rootController,
    invocationTarget: rootInvocationTarget
  });
  return zcapClient.delegate({
    capability: rootZcap,
    controller,
    invocationTarget: rootZcap.invocationTarget
  });
}
