import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import * as der from '../src/der.ts';
import { TimestampError, buildTimeStampReq, parseTimeStampResp, verifyTimestampToken } from '../src/timestamp.ts';
import { OID_EKU_CODE_SIGNING, OID_EKU_TIME_STAMPING, makeCertificate } from './helpers/mini-x509.ts';
import { buildTimeStampResp } from './helpers/mock-certum.ts';

const tsa = makeCertificate({ commonName: 'Unit TSA', extendedKeyUsage: [OID_EKU_TIME_STAMPING] });
const imprint = createHash('sha256').update('some signature bytes').digest();
const nonce = randomBytes(8);

test('TimeStampReq has version 1, a SHA-256 imprint, the nonce and certReq TRUE', () => {
  const req = der.children(der.readExact(buildTimeStampReq(imprint, nonce)));
  assert.equal(der.integerValue(req[0]!), 1n);
  const [alg, hashed] = der.children(req[1]!);
  assert.equal(der.decodeOid(der.children(alg!)[0]!), '2.16.840.1.101.3.4.2.1');
  assert.equal(der.octets(hashed, 'hashed').equals(imprint), true);
  assert.equal(der.integerMagnitude(req[2]!).equals(der.integerMagnitude(der.readExact(der.integer(nonce)))), true);
  assert.deepEqual([...req[3]!.raw], [0x01, 0x01, 0xff]);
  assert.equal(der.children(der.readExact(buildTimeStampReq(imprint, null))).length, 3);
});

test('a granted response yields a verified token', () => {
  const token = parseTimeStampResp(buildTimeStampResp(buildTimeStampReq(imprint, nonce), tsa), { imprint, nonce });
  assert.equal(token.policy, '1.3.6.1.4.1.99999.1');
  assert.match(token.serialNumber, /^[0-9a-f]+$/);
  assert.ok(Math.abs(token.genTime.getTime() - Date.now()) < 60_000);
  assert.equal(token.tsa.x509.subject, 'CN=Unit TSA');
  assert.equal(der.decodeOid(der.children(der.readExact(token.token))[0]!), '1.2.840.113549.1.7.2');
  // Without a nonce expectation the same token still verifies.
  assert.ok(verifyTimestampToken(token.token, { imprint, nonce: null }));
});

test('every deviation from what we asked for is rejected', () => {
  const req = buildTimeStampReq(imprint, nonce);
  const rejects = (bytes: Buffer, pattern: RegExp): void => {
    assert.throws(() => parseTimeStampResp(bytes, { imprint, nonce }), (err: unknown) => err instanceof TimestampError && pattern.test(err.message));
  };
  rejects(buildTimeStampResp(req, tsa, 'reject'), /rejected the request \(status rejection: policy not supported\)/);
  rejects(buildTimeStampResp(req, tsa, 'wrong-imprint'), /different message/);
  rejects(buildTimeStampResp(req, tsa, 'drop-nonce'), /did not echo our nonce/);
  rejects(Buffer.from('this is not a timestamp'), /not a TimeStampResp/);
  rejects(buildTimeStampResp(buildTimeStampReq(imprint, randomBytes(8)), tsa), /different nonce/);

  const notTsa = makeCertificate({ commonName: 'Just a signer', extendedKeyUsage: [OID_EKU_CODE_SIGNING] });
  rejects(buildTimeStampResp(req, notTsa), /not a time-stamping certificate/);

  // A token whose signature was made with another key than the embedded certificate.
  const impostor = { ...tsa, privateKey: makeCertificate({ commonName: 'x' }).privateKey };
  rejects(buildTimeStampResp(req, impostor), /timestamp signature is invalid/);

  // Structural damage inside the token.
  const good = buildTimeStampResp(req, tsa);
  const damaged = Buffer.from(good);
  damaged[damaged.length - 5] ^= 0xff;
  assert.throws(() => parseTimeStampResp(damaged, { imprint, nonce }), TimestampError);
});
