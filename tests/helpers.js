/*!
 * Copyright (c) 2021-2025 Digital Bazaar, Inc. All rights reserved.
 */
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';
import {createRootCapability} from '@digitalbazaar/zcap';
import {decodeSecretKeySeed} from 'bnid';
import {driver} from '@digitalbazaar/did-method-key';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {ZcapClient} from '@digitalbazaar/ezcap';

export const didKeyDriver = driver();
didKeyDriver.use({
  multibaseMultikeyHeader: 'z6Mk',
  fromMultibase: Ed25519Multikey.from
});

export async function getInvocationSigner({seed}) {
  const {methodFor} = await _fromSeed({seed});
  const keyPair = methodFor({purpose: 'capabilityInvocation'});
  const signer = await keyPair.signer();
  signer.controller = keyPair.controller;
  return signer;
}

export async function getDelegationSigner({seed}) {
  const {methodFor} = await _fromSeed({seed});
  const keyPair = methodFor({purpose: 'capabilityDelegation'});
  const signer = await keyPair.signer();
  signer.controller = keyPair.controller;
  return signer;
}

export async function delegate({seed, rootInvocationTarget, controller}) {
  const delegationSigner = await getDelegationSigner({seed});
  const zcapClient = new ZcapClient({
    SuiteClass: Ed25519Signature2020,
    delegationSigner
  });
  // key ID is always `<controller>#...`
  const {id: keyId} = delegationSigner;
  const rootController = keyId.slice(0, keyId.indexOf('#'));
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

async function _fromSeed({seed}) {
  const bytes = decodeSecretKeySeed({secretKeySeed: seed});
  const keyPair = await Ed25519Multikey.generate({seed: bytes});
  const {didDocument, methodFor, keyPairs} = await didKeyDriver.fromKeyPair({
    verificationKeyPair: keyPair
  });
  // use `keyPair` in map to include secret key material
  for(const [key, value] of keyPairs) {
    if(!keyPair.id) {
      keyPair.id = value.id;
      keyPair.controller = value.controller;
    }
    keyPairs.set(key, keyPair);
  }
  return {didDocument, methodFor, keyPairs};
}
