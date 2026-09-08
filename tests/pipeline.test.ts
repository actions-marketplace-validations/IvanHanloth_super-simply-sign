import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { consoleLogger } from '../src/log.ts';
import { parsePeLayout } from '../src/pe.ts';
import { ScsError } from '../src/scs.ts';
import { CloudSession, SignError, signPe } from '../src/signer.ts';
import { TimestampError } from '../src/timestamp.ts';
import { verifySignedPe } from '../src/verify.ts';
import { parseCertificate } from '../src/x509.ts';
import { OID_EKU_CODE_SIGNING, OID_EKU_TIME_STAMPING, makeCertificate, type TestCert } from './helpers/mini-x509.ts';
import { startMockCertum, type MockCertumOptions } from './helpers/mock-certum.ts';

const hello = readFileSync(new URL('./fixtures/hello.exe', import.meta.url));
const ca = makeCertificate({ commonName: 'Pipeline Test CA', ca: true });
const signingCert: TestCert = makeCertificate({ commonName: 'Pipeline Publisher', issuer: ca, extendedKeyUsage: [OID_EKU_CODE_SIGNING] });
const tsaCert = makeCertificate({ commonName: 'Pipeline TSA', extendedKeyUsage: [OID_EKU_TIME_STAMPING] });
const EMAIL = 'dev@example.com';

let nextCode = 100000;
const freshCode = (): string => String(nextCode++);
const baseOptions = (): MockCertumOptions => ({ email: EMAIL, acceptCode: (c) => /^\d{6}$/.test(c), signingCert, tsaCert });

async function withMock<T>(options: Partial<MockCertumOptions>, fn: (mock: Awaited<ReturnType<typeof startMockCertum>>) => Promise<T>): Promise<T> {
  const mock = await startMockCertum({ ...baseOptions(), ...options });
  try {
    return await fn(mock);
  } finally {
    await mock.close();
  }
}

test('end to end: login once, sign two images, timestamp, embed the chain, self-verify', async () => {
  await withMock({}, async (mock) => {
    const log = consoleLogger();
    const session = await CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints, log });
    assert.equal(session.cardSerial, '1234567890');
    assert.equal(session.certificate.x509.subject, 'CN=Pipeline Publisher');

    const odd = Buffer.concat([hello, Buffer.from('trailing overlay!')]);
    const results = [];
    for (const image of [hello, odd]) {
      const result = await signPe(session, image, {
        description: 'Pipeline demo',
        url: 'https://example.com/pipeline',
        timestampUrl: mock.tsaUrl,
        extraCertificates: [parseCertificate(ca.der)],
        log,
      });
      results.push(result);
      assert.ok(result.verification, 'self-verification runs by default');
      assert.ok(result.timestamp);
      assert.equal(result.chain.length, 1);
      assert.equal(result.chain[0]?.x509.subject, 'CN=Pipeline Test CA');
      const independent = verifySignedPe(result.signed);
      assert.equal(independent.signer.x509.fingerprint256, session.certificate.x509.fingerprint256);
      assert.equal(independent.description, 'Pipeline demo');
      assert.equal(independent.url, 'https://example.com/pipeline');
      assert.ok(independent.timestamp);
      assert.equal(independent.certificates.length, 2, 'leaf + the test CA (the Certum intermediate is not the issuer here)');
      assert.equal(parsePeLayout(result.signed).certTableSize > 0, true);
    }
    assert.equal(mock.accessTokens.length, 1, 'one login for the whole batch');
    assert.equal(mock.signedDigests.length, 2);
    assert.ok(mock.signedDigests.every((d) => /^[0-9a-f]{64}$/.test(d)), 'the cloud only ever sees SHA-256 digests');
    assert.notEqual(mock.signedDigests[0], results[0]!.peHash.toString('hex'), 'the HSM signs the signed-attributes digest, never the raw file hash');
    assert.notEqual(results[0]!.peHash.toString('hex'), results[1]!.peHash.toString('hex'));
    assert.ok(log.secrets.length >= 3, 'token, code and cookie were registered as secrets');
    assert.ok(log.secrets.includes('1234567890'), 'the card serial is masked too');
  });
});

test('without a suitable intermediate only the leaf is embedded and a warning is logged', async () => {
  await withMock({}, async (mock) => {
    const log = consoleLogger();
    const warnings: string[] = [];
    const warnLog = { ...log, warning: (m: string) => warnings.push(m) };
    const session = await CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints, log: warnLog });
    const result = await signPe(session, hello, { timestampUrl: null, log: warnLog });
    assert.equal(result.timestamp, null);
    assert.equal(result.chain.length, 0);
    assert.equal(result.verification?.certificates.length, 1);
    assert.ok(warnings.some((w) => w.includes('CN=Pipeline Test CA')), `expected a missing-issuer warning, got ${JSON.stringify(warnings)}`);
  });
});

test('an existing signature is only replaced on request', async () => {
  await withMock({}, async (mock) => {
    const session = await CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints });
    const first = await signPe(session, hello, { timestampUrl: null });
    await assert.rejects(signPe(session, first.signed, { timestampUrl: null }), (err: unknown) => err instanceof SignError && /already carries a signature/.test(err.message));
    const second = await signPe(session, first.signed, { timestampUrl: null, replaceExistingSignature: true });
    assert.equal(second.peHash.toString('hex'), first.peHash.toString('hex'));
    assert.equal(verifySignedPe(second.signed).certificates.length, 1);
    assert.equal(mock.signedDigests.length, 2);
  });
});

test('a cloud signature that does not match the certificate is never embedded', async () => {
  await withMock({ corruptSignature: true }, async (mock) => {
    const session = await CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints });
    await assert.rejects(signPe(session, hello, { timestampUrl: null }), /does not verify with the signing certificate — refusing/);
  });
});

test('a timestamp that does not cover our signature aborts the file', async () => {
  await withMock({ tsaBehaviour: 'wrong-imprint' }, async (mock) => {
    const session = await CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints });
    await assert.rejects(signPe(session, hello, { timestampUrl: mock.tsaUrl }), (err: unknown) => err instanceof TimestampError && /different message/.test(err.message));
  });
  await withMock({ tsaBehaviour: 'reject' }, async (mock) => {
    const session = await CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints });
    await assert.rejects(signPe(session, hello, { timestampUrl: mock.tsaUrl }), /rejected the request/);
  });
});

test('atom:links pointing at another origin are refused (the bearer token stays home)', async () => {
  await withMock({ foreignAtomLink: 'https://evil.example' }, async (mock) => {
    await assert.rejects(CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints }), (err: unknown) => err instanceof ScsError && /outside/.test(err.message));
    assert.equal(mock.requests.filter((r) => r.path.startsWith('/scs1/')).length, 0);
  });
});

test('cards: PIN-protected cards are refused, several cards can be selected by serial', async () => {
  await withMock({ pinRequired: true }, async (mock) => {
    await assert.rejects(CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints }), /requires a PIN/);
  });
  await withMock({ extraCards: 2 }, async (mock) => {
    const warnings: string[] = [];
    const log = { ...consoleLogger(), warning: (m: string) => warnings.push(m) };
    const session = await CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints, log });
    assert.equal(session.cardSerial, '1234567890');
    assert.ok(warnings.some((w) => w.includes('3 cards')));
    await assert.rejects(CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints, cardSerial: 'nope' }), /no card with serial "nope"/);
  });
});

test('a wrong one-time code fails before anything is signed', async () => {
  await withMock({ acceptCode: () => false }, async (mock) => {
    await assert.rejects(CloudSession.open({ email: EMAIL, otpCode: '111111', endpoints: mock.endpoints }), /rejected by the identity provider/);
    assert.equal(mock.accessTokens.length, 0);
  });
});
