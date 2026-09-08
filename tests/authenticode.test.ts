import assert from 'node:assert/strict';
import { createHash, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { OID_SPC_SP_OPUS_INFO, finalize, prepare, spcIndirectDataContent, spcPeImageData, spcSpOpusInfo } from '../src/authenticode.ts';
import { findAttribute, parseAttributes, parseSignedData } from '../src/cms.ts';
import * as der from '../src/der.ts';
import { authenticodeHash, parsePeLayout, readCertificateTable } from '../src/pe.ts';
import { buildTimeStampReq, verifyTimestampToken } from '../src/timestamp.ts';
import { VerificationError, verifySignedPe } from '../src/verify.ts';
import { parseCertificate } from '../src/x509.ts';
import { OID_EKU_CODE_SIGNING, OID_EKU_TIME_STAMPING, makeCertificate } from './helpers/mini-x509.ts';
import { buildTimeStampResp } from './helpers/mock-certum.ts';
import { signDigestPkcs1v15Sha256 } from './helpers/rsa-raw.ts';

const hello = readFileSync(new URL('./fixtures/hello.exe', import.meta.url));

/** SpcAttributeTypeAndOptionalValue captured verbatim from a real Authenticode signature. */
const SPC_ATTR_CAPTURED =
  '3034060a2b060104018237020' +
  '10f30260302078' +
  '0a020a21e801c003c003c003c004f00620073006f006c006500740065003e003e003e';

test('the SpcPeImageData attribute is rebuilt byte for byte', () => {
  assert.equal(spcPeImageData().toString('hex'), SPC_ATTR_CAPTURED);
});

test('messageDigest hashes the SpcIndirectDataContent *content* (reference vector)', () => {
  const peHash = Buffer.from('BC17B1C98515D63F366BCD9F472054AE49CD5E839043265CE060B38B33CA2A43', 'hex');
  const spc = spcIndirectDataContent(peHash);
  assert.equal(createHash('sha256').update(spc.content).digest('hex').toUpperCase(), '320623882B0DBD238471A6E7DC3C1F3177D2DD38C0DC166FB12109BA89698E4B');
  assert.equal(der.readExact(spc.der).content.equals(spc.content), true);
});

test('prepare() builds sorted signed attributes and the digest the HSM signs', () => {
  const plain = prepare(hello, { signingTime: new Date(Date.UTC(2026, 6, 10, 7, 18, 1)) });
  assert.equal(plain.peHash.toString('hex'), authenticodeHash(hello).toString('hex'));
  const attrs = parseAttributes(der.readExact(plain.signedAttrsSet));
  assert.equal(attrs.length, 4);
  const encodings = der.children(der.readExact(plain.signedAttrsSet)).map((t) => t.raw);
  for (let i = 1; i < encodings.length; i++) assert.ok(der.derCompare(encodings[i - 1]!, encodings[i]!) < 0, 'attributes must be DER-sorted');
  assert.equal(plain.toBeSigned.toString('hex'), createHash('sha256').update(plain.signedAttrsSet).digest('hex'));

  const rich = prepare(hello, { description: 'Demo ✓', url: 'https://example.com/x', signingTime: new Date() });
  const richAttrs = parseAttributes(der.readExact(rich.signedAttrsSet));
  assert.equal(richAttrs.length, 5);
  assert.ok(findAttribute(richAttrs, OID_SPC_SP_OPUS_INFO));
  assert.throws(() => spcSpOpusInfo(undefined, 'https://exämple.com'), /printable ASCII/);
});

function localSigner() {
  const ca = makeCertificate({ commonName: 'Test Root CA', ca: true });
  const leaf = makeCertificate({ commonName: 'Test Publisher', issuer: ca, extendedKeyUsage: [OID_EKU_CODE_SIGNING] });
  const tsa = makeCertificate({ commonName: 'Test TSA', extendedKeyUsage: [OID_EKU_TIME_STAMPING] });
  return { ca, leaf, tsa, leafInfo: parseCertificate(leaf.der), caInfo: parseCertificate(ca.der) };
}

test('a locally assembled signature verifies, with the chain and opus info intact', () => {
  const { leaf, leafInfo, caInfo } = localSigner();
  const signingTime = new Date(Date.UTC(2026, 8, 8, 12, 0, 0));
  const prepared = prepare(hello, { description: 'Hello World 你好', url: 'https://example.com/hello', signingTime });
  // Exactly what the cloud HSM does: PKCS#1 v1.5 over DigestInfo(sha256, toBeSigned).
  const signature = signDigestPkcs1v15Sha256(prepared.toBeSigned, leaf.privateKey);
  assert.equal(signature.equals(sign('sha256', prepared.signedAttrsSet, leaf.privateKey)), true);

  const signed = finalize(hello, prepared, signature, leafInfo, [caInfo], null);
  const result = verifySignedPe(signed);
  assert.equal(result.hashAlgorithm, 'sha256');
  assert.equal(result.peHash.toString('hex'), prepared.peHash.toString('hex'));
  assert.equal(result.signer.x509.fingerprint256, leafInfo.x509.fingerprint256);
  assert.deepEqual(
    result.certificates.map((c) => c.x509.subject),
    [leafInfo.x509.subject, caInfo.x509.subject],
  );
  assert.equal(result.description, 'Hello World 你好');
  assert.equal(result.url, 'https://example.com/hello');
  assert.equal(result.signingTime?.getTime(), signingTime.getTime());
  assert.equal(result.timestamp, null);

  const sd = parseSignedData(der.readTlv(readCertificateTable(signed)[0]!.data).raw);
  assert.equal(sd.version, 1);
  assert.deepEqual(sd.digestAlgorithms, ['2.16.840.1.101.3.4.2.1']);
  assert.equal(sd.signerInfos[0]?.sid.kind, 'issuerAndSerialNumber');
});

test('tampering with the image or the signature is detected', () => {
  const { leaf, leafInfo } = localSigner();
  const prepared = prepare(hello, { signingTime: new Date() });
  const signature = signDigestPkcs1v15Sha256(prepared.toBeSigned, leaf.privateKey);
  const signed = finalize(hello, prepared, signature, leafInfo, [], null);
  assert.ok(verifySignedPe(signed));

  const patchedCode = Buffer.from(signed);
  patchedCode[0x500] ^= 0x01;
  assert.throws(() => verifySignedPe(patchedCode), (err: unknown) => err instanceof VerificationError && /digest mismatch/.test(err.message));

  const patchedSignature = Buffer.from(signed);
  const layout = parsePeLayout(signed);
  const sigOffset = signed.indexOf(signature, layout.certTableOffset);
  assert.ok(sigOffset > 0);
  patchedSignature[sigOffset + 10] ^= 0xff;
  assert.throws(() => verifySignedPe(patchedSignature), /does not verify with the signer certificate/);

  assert.throws(() => verifySignedPe(hello), /no Authenticode signature/);
});

test('an RFC 3161 token rides along as an unauthenticated attribute and is verified', () => {
  const { leaf, leafInfo, tsa } = localSigner();
  const prepared = prepare(hello, { signingTime: new Date() });
  const signature = signDigestPkcs1v15Sha256(prepared.toBeSigned, leaf.privateKey);
  const imprint = createHash('sha256').update(signature).digest();
  const nonce = Buffer.from('0123456789abcdef', 'hex');
  const resp = buildTimeStampResp(buildTimeStampReq(imprint, nonce), tsa);
  const token = der.children(der.readExact(resp))[1]!.raw;
  const verifiedToken = verifyTimestampToken(token, { imprint, nonce });

  const signed = finalize(hello, prepared, signature, leafInfo, [], verifiedToken.token);
  const result = verifySignedPe(signed);
  assert.ok(result.timestamp);
  assert.equal(result.timestamp.tsa.x509.subject, parseCertificate(tsa.der).x509.subject);
  assert.ok(Math.abs(result.timestamp.genTime.getTime() - Date.now()) < 60_000);

  // A token over a different signature must be rejected at verification time.
  const other = signDigestPkcs1v15Sha256(createHash('sha256').update('other').digest(), leaf.privateKey);
  const foreignResp = buildTimeStampResp(buildTimeStampReq(createHash('sha256').update(other).digest(), null), tsa);
  const foreignToken = der.children(der.readExact(foreignResp))[1]!.raw;
  const badlyStamped = finalize(hello, prepared, signature, leafInfo, [], foreignToken);
  assert.throws(() => verifySignedPe(badlyStamped), /invalid timestamp: the timestamp covers a different message/);
});
