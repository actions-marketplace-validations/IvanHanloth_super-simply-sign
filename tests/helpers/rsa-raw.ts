/**
 * What the Certum cloud HSM does with a digest: an RSASSA-PKCS1-v1_5 signature
 * over `DigestInfo(sha256, digest)`. node:crypto only signs *messages*, so the
 * test double does the padding and the modular exponentiation itself.
 */
import type { KeyObject } from 'node:crypto';

const SHA256_DIGEST_INFO_PREFIX = Buffer.from('3031300d060960864801650304020105000420', 'hex');

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    b = (b * b) % modulus;
    e >>= 1n;
  }
  return result;
}

const fromBase64Url = (s: string): bigint => BigInt(`0x${Buffer.from(s, 'base64url').toString('hex')}`);

/** PKCS#1 v1.5 signature over an already-computed SHA-256 digest. */
export function signDigestPkcs1v15Sha256(digest: Uint8Array, privateKey: KeyObject): Buffer {
  const jwk = privateKey.export({ format: 'jwk' }) as { n: string; d: string };
  const n = fromBase64Url(jwk.n);
  const d = fromBase64Url(jwk.d);
  const k = Buffer.from(jwk.n, 'base64url').length;
  const t = Buffer.concat([SHA256_DIGEST_INFO_PREFIX, digest]);
  const em = Buffer.concat([Buffer.from([0x00, 0x01]), Buffer.alloc(k - t.length - 3, 0xff), Buffer.from([0x00]), t]);
  const s = modPow(BigInt(`0x${em.toString('hex')}`), d, n);
  return Buffer.from(s.toString(16).padStart(k * 2, '0'), 'hex');
}
