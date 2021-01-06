/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import * as authorization from 'auth-header';
import {httpClient} from '@digitalbazaar/http-client';
import noopLogger from './noopLogger.js';

/**
 * Authorizes an incoming request.
 *
 * @param {object} options - Options hashmap.
 * @param {object} [options.logger] - Optional logger.
 * @param {object} options.httpsAgent - httpsAgent.
 *
 * @returns {Function} Returns an Express.js middleware route handler.
 */
export function authorize({
  logger = noopLogger, httpsAgent
}) {
  _assertOk(httpsAgent, 'httpsAgent');

  return async req => {
    throw new Error('Not implemented');
  };
}

function _assertString(arg, msg) {
  if(typeof (arg) !== 'string') {
    throw new TypeError(`"${msg}" must be a string.`);
  }
}

function _assertOk(arg, msg) {
  if(!arg) {
    throw new TypeError(`"${msg}" is required.`);
  }
}
