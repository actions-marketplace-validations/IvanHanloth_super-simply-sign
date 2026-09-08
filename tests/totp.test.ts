import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TotpError, base32Decode, isValidOtpCode, parseTotpSecret, secondsLeftInWindow, totpCode } from '../src/totp.ts';

/** RFC 4648 base32 (test-side encoder, so the RFC 6238 seeds can be spelled out as ASCII). */
function base32Encode(bytes: Buffer): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

// RFC 6238 appendix B seeds: "12345678901234567890" for SHA-1, extended to 32 / 64 bytes for SHA-256 / SHA-512.
const SEED_SHA1 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const SEED_SHA256 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';
const SEED_SHA512 = base32Encode(Buffer.from('1234567890'.repeat(7).slice(0, 64)));

test('RFC 6238 test vectors', () => {
  const sha1 = parseTotpSecret(`otpauth://totp/x?secret=${SEED_SHA1}&algorithm=SHA1&digits=8`);
  assert.equal(totpCode(sha1, 59), '94287082');
  assert.equal(totpCode(sha1, 1111111109), '07081804');
  assert.equal(totpCode(sha1, 20000000000), '65353130');
  const sha256 = parseTotpSecret(`otpauth://totp/x?secret=${SEED_SHA256}&algorithm=SHA256&digits=8`);
  assert.equal(totpCode(sha256, 59), '46119246');
  assert.equal(totpCode(sha256, 1111111109), '68084774');
  const sha512 = parseTotpSecret(`otpauth://totp/x?secret=${SEED_SHA512}&algorithm=SHA512&digits=8`);
  assert.equal(totpCode(sha512, 59), '90693936');
  assert.equal(totpCode(sha512, 1234567890), '93441116');
});

test('the test-side base32 encoder agrees with the decoder', () => {
  assert.equal(base32Encode(Buffer.from('12345678901234567890')), SEED_SHA1);
  assert.equal(base32Encode(Buffer.from('12345678901234567890123456789012')), SEED_SHA256);
  assert.equal(base32Decode(SEED_SHA512).toString(), '1234567890'.repeat(7).slice(0, 64));
});

test('a bare base32 secret gets the Certum defaults (SHA-256, 6 digits, 30 s)', () => {
  const p = parseTotpSecret(SEED_SHA256);
  assert.equal(p.algorithm, 'sha256');
  assert.equal(p.digits, 6);
  assert.equal(p.period, 30);
  assert.equal(totpCode(p, 59), '46119246'.slice(-6));
  assert.match(totpCode(p), /^\d{6}$/);
});

test('otpauth URIs are self-describing and validated', () => {
  const p = parseTotpSecret('otpauth://totp/Certum:me%40example.com?secret=GEZDGNBVGY3TQOJQ&issuer=Certum&algorithm=SHA1&digits=8&period=60');
  assert.equal(p.algorithm, 'sha1');
  assert.equal(p.digits, 8);
  assert.equal(p.period, 60);
  assert.throws(() => parseTotpSecret('otpauth://hotp/x?secret=GEZDGNBV'), /only totp/);
  assert.throws(() => parseTotpSecret('otpauth://totp/x?issuer=nobody'), /no secret/);
  assert.throws(() => parseTotpSecret('otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5'), /unsupported TOTP algorithm/);
  assert.throws(() => parseTotpSecret('otpauth://totp/x?secret=GEZDGNBV&digits=4'), /digits/);
  assert.throws(() => parseTotpSecret('otpauth://totp/x?secret=GEZDGNBV&period=0'), /period/);
  assert.throws(() => parseTotpSecret('otpauth://'), TotpError);
});

test('base32 decoding is forgiving about case, spacing and padding but not about the alphabet', () => {
  assert.equal(base32Decode('GEZDGNBVGY3TQOJQ').toString(), '1234567890');
  assert.equal(base32Decode('gezd gnbv-gy3t qojq====').toString(), '1234567890');
  assert.equal(base32Decode('MY======').toString(), 'f');
  assert.equal(base32Decode('MZXW6YTBOI').toString(), 'foobar');
  assert.throws(() => base32Decode('GEZDGNBV1'), /not valid base32/);
  assert.throws(() => parseTotpSecret('   '), /empty/);
});

test('code validation and window arithmetic', () => {
  assert.equal(isValidOtpCode('123456'), true);
  assert.equal(isValidOtpCode('12345'), false);
  assert.equal(isValidOtpCode('12345a'), false);
  assert.equal(isValidOtpCode('12345678', 8), true);
  const p = parseTotpSecret(SEED_SHA1);
  assert.equal(secondsLeftInWindow(p, 0), 30);
  assert.equal(secondsLeftInWindow(p, 29), 1);
  assert.equal(secondsLeftInWindow(p, 30), 30);
});
