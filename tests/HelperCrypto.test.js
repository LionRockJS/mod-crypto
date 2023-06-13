import path from 'node:path';
import HelperCrypto from '../classes/helper/Crypto';

const testKeyHS256 = {
  kty: 'oct', alg: 'HS256', key_ops: ['sign', 'verify'], k: 'ALhJbC1Spav8eSbMJxXe2yR0ZZ-eXneYGaYM51ti1T5pGT9QxYlS6YqQD5Asm4VrVjyTmZLQ00ID1vmn-91ckg', ext: true,
};

import * as url from 'node:url';
const __dirname = url.fileURLToPath(new URL('.', import.meta.url)).replace(/\/$/, '');

describe('test crypto', () => {
  test('make key', async () => {
    const fileName = path.normalize(`${__dirname}/keys/testKey.js`);
    const jwk = await HelperCrypto.makeSignKey(fileName, { name: 'HMAC', hash: 'SHA-256' });
    const {default : key} = await import('./keys/testKey');
    expect(jwk.alg).toBe(key.alg);
    expect(jwk.ext).toBe(key.ext);
    expect(jwk.k).toBe(key.k);
    expect(jwk.kty).toBe(key.kty);

    const fileName2 = path.normalize(`${__dirname}/keys/testKey2.js`);
    const jwk2 = await HelperCrypto.makeSignKey(fileName2);
    const {default: key2} = await import('./keys/testKey2');
    expect(jwk2.alg).toBe(key2.alg);
    expect(jwk2.ext).toBe(key2.ext);
    expect(jwk2.k).toBe(key2.k);
    expect(jwk2.kty).toBe(key2.kty);
  });

  test('sign', async () => {
    const sign = await HelperCrypto.sign(testKeyHS256, 'hello');
    expect(sign).toBe('7NZQDQgE1dV0uu2w0BboV5J7YxTrjhDZQ0+DdXzcIho=');
  });

  test('sign, expire', async () => {
    const expire = 600;
    const timestamp = 1563669060000;
    const sign = await HelperCrypto.sign(testKeyHS256, 'hello', { name: 'HMAC', hash: 'SHA-256' }, expire, timestamp);
    const signs = sign.split('::');
    const signExpire = parseInt(signs[1]);

    expect(sign).toBe('vAMmolmXSfobsltcMc5PmIR4D4QKGAsU84UUYtPL+ro=::1563669660');
    expect(signs[0]).toBe('vAMmolmXSfobsltcMc5PmIR4D4QKGAsU84UUYtPL+ro=');
    expect(signExpire - Math.floor(timestamp / 1000) ).toBe(expire);

    const timestamp2 = 1563669070000;
    const sign2 = await HelperCrypto.sign(testKeyHS256, 'hello', { name: 'HMAC', hash: 'SHA-256' }, expire, timestamp2);
    const sign2s = sign2.split('::');
    const signExpire2 = parseInt(sign2s[1]);
    expect(sign2).toBe('mcUWH87f0GpTnaFdgwDmxTx2CZ+MkHasO6V9xtaD4hA=::1563669670');
    expect(sign2s[0]).toBe('mcUWH87f0GpTnaFdgwDmxTx2CZ+MkHasO6V9xtaD4hA=');
    expect(signExpire2 - Math.floor(timestamp2 / 1000) ).toBe(expire);

    const sign3 = await HelperCrypto.sign(testKeyHS256, 'hello', { name: 'HMAC', hash: 'SHA-256' }, expire);
    const sign3s = sign3.split('::');
    const signExpire3 = parseInt(sign3s[1]);
    expect(signExpire3 - Math.floor(Date.now() / 1000) ).toBe(expire);
  });

  test('verify', async () => {
    const verify = await HelperCrypto.verify(testKeyHS256, '7NZQDQgE1dV0uu2w0BboV5J7YxTrjhDZQ0+DdXzcIho=', 'hello');
    expect(verify).toBe(true);
  });

  test('verify_timestamp', async () => {
    const verify = await HelperCrypto.verify(testKeyHS256, 'mcUWH87f0GpTnaFdgwDmxTx2CZ+MkHasO6V9xtaD4hA=::1563669670', 'hello', { name: 'HMAC', hash: 'SHA-256' }, 1563669060000);
    expect(verify).toBe(true);

    const verify2 = await HelperCrypto.verify(testKeyHS256, 'mcUWH87f0GpTnaFdgwDmxTx2CZ+MkHasO6V9xtaD4hA=::1563669670', 'hello', { name: 'HMAC', hash: 'SHA-256' });
    expect(verify2).toBe(false);
  });

  test('verify false', async () => {
    const verify = await HelperCrypto.verify(testKeyHS256, '7NZQDQgE1dV0uu2w0BboV5J7YxTrjhDZQ0+DdXzcIho=', 'hellos');
    expect(verify).toBe(false);
  });
});
