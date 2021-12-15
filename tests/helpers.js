/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import {decodeSecretKeySeed} from 'bnid';
import * as didKey from '@digitalbazaar/did-method-key';

const didKeyDriver = didKey.driver();

export const getInvocationSigner = async ({seed}) => {
  const decoded = decodeSecretKeySeed({secretKeySeed: seed});
  const {methodFor} = await didKeyDriver.generate({seed: decoded});

  const invocationCapabilityKeyPair = methodFor(
    {purpose: 'capabilityInvocation'});
  const invocationSigner = invocationCapabilityKeyPair.signer();

  return invocationSigner;
};
