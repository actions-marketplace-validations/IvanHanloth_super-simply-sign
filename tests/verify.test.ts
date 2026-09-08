import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { authenticodeHash, parsePeLayout, peChecksum, readCertificateTable, stripSignature } from '../src/pe.ts';
import { verifySignedPe } from '../src/verify.ts';
import { oneLineName } from '../src/x509.ts';

/** hello.exe signed by Microsoft signtool with a real Certum RFC 3161 timestamp — see fixtures/README.md. */
const signtoolSigned = readFileSync(new URL('./fixtures/hello-signtool.exe', import.meta.url));
const HELLO_HASH = 'bc17b1c98515d63f366bcd9f472054ae49cd5e839043265ce060b38b33ca2a43';

test('an image signed by signtool (with a genuine Certum timestamp) verifies end to end', () => {
  const result = verifySignedPe(signtoolSigned);
  assert.equal(result.hashAlgorithm, 'sha256');
  assert.equal(result.peHash.toString('hex'), HELLO_HASH, 'signtool embedded the same Authenticode digest we compute');
  assert.equal(result.signer.x509.subject, 'CN=SSS signtool cross-check');
  assert.equal(result.certificates.length, 1);
  assert.equal(result.description, 'signtool cross-check');
  assert.equal(result.url, 'https://example.com/xcheck');
  assert.equal(result.signingTime, null, 'signtool does not add a signingTime attribute');
  assert.ok(result.timestamp, 'the RFC 3161 counter-signature must be found and verified');
  assert.equal(result.timestamp.genTime.toISOString(), '2026-09-08T12:32:11.000Z');
  assert.equal(result.timestamp.policy, '1.2.616.1.113527.2.5.1.11');
  assert.equal(oneLineName(result.timestamp.tsa.x509.subject), 'C=PL, O=Asseco Data Systems S.A., CN=Certum Timestamp 2026');
  assert.equal(oneLineName(result.timestamp.tsa.x509.issuer), 'C=PL, O=Asseco Data Systems S.A., CN=Certum Timestamping 2021 CA');
});

test('our PE arithmetic agrees with signtool on the signed image', () => {
  const layout = parsePeLayout(signtoolSigned);
  assert.equal(layout.certTableOffset + layout.certTableSize, signtoolSigned.length);
  assert.equal(signtoolSigned.readUInt32LE(layout.checksumOffset), peChecksum(signtoolSigned, layout.checksumOffset), 'PE checksum');
  assert.equal(authenticodeHash(signtoolSigned).toString('hex'), HELLO_HASH, 'hashing the signed image skips the certificate table');
  const [entry] = readCertificateTable(signtoolSigned);
  assert.equal(entry?.revision, 0x0200);
  assert.equal(entry?.type, 0x0002);
  const stripped = stripSignature(signtoolSigned);
  assert.equal(authenticodeHash(stripped).toString('hex'), HELLO_HASH);
  assert.equal(parsePeLayout(stripped).certTableSize, 0);
});

test('a modified signtool-signed image is rejected', () => {
  const tampered = Buffer.from(signtoolSigned);
  tampered[0x800] ^= 0x01;
  assert.throws(() => verifySignedPe(tampered), /digest mismatch/);
});
