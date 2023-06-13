import { Buffer } from 'node:buffer';
import { TextEncoder } from 'node:util';
import { subtle } from 'node:crypto';
import fs from 'node:fs/promises';

const CRYPTO_ALGORITHMS = {
  RSASSA_PKCS1_v1_5: 'RSASSA-PKCS1-v1_5',
  RSA_PSS: 'RSA-PSS',
  ECDSA: 'ECDSA',
  HMAC: 'HMAC',
  RSA_OAEP: 'RSA-OAEP',
  AES_CTR: 'AES-CTR',
  AES_CBC: 'AES-CBC',
  AES_GCM: 'AES-GCM',
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA384: 'SHA-384',
  SHA512: 'SHA-512',
  ECDH: 'ECDH',
  HKDF: 'HKDF',
  PBKDF2: 'PBKDF2',
  AES_KW: 'AES-KW',
};

const defaultSignAlgorithm = { name: CRYPTO_ALGORITHMS.HMAC, hash: CRYPTO_ALGORITHMS.SHA256 };

export default class HelperCrypto {
  static CRYPTO_ALGORITHMS = CRYPTO_ALGORITHMS;

  static async makeSignKey(filePath, algorithm = defaultSignAlgorithm) {
    const key = await subtle.generateKey(algorithm, true, ['sign', 'verify']);
    const jwk = await subtle.exportKey('jwk', key);

    await fs.writeFile(filePath, /.json$/.test(filePath)? JSON.stringify(jwk) : `export default ${JSON.stringify(jwk)}`);
    return jwk;
  }

  static async sign(jwk, data, algorithm = defaultSignAlgorithm, expire=0, timestamp= 0) {
    const key = await subtle.importKey('jwk', jwk, algorithm, true, ['sign', 'verify']);
    const expire_ms = expire * 1000;

    const strExpire = (expire ? `::${ Math.floor(((timestamp || Date.now()) + expire_ms) / 1000) }` : '');

    const buffer = new TextEncoder().encode(data + strExpire);
    const sign = await subtle.sign(algorithm, key, buffer);

    return Buffer.from(sign).toString('base64') + strExpire;
  }

  static async verify(jwk, sign, data, algorithm = defaultSignAlgorithm, timestamp=0) {
    const signs = sign.split('::');
    if(signs[1]){
      const expire_ms = parseInt(signs[1]) * 1000;
      if((timestamp || Date.now()) > expire_ms)return false;
    }
    const strExpire = signs[1] ? `::${signs[1]}` : '';

    const key = await subtle.importKey('jwk', jwk, algorithm, true, ['sign', 'verify']);
    const bufferSign = Buffer.from(signs[0], "base64");
    const bufferData = new TextEncoder().encode(data + strExpire);
    return subtle.verify(algorithm, key, bufferSign, bufferData);
  }
}