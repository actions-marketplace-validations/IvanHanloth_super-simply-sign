import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { parseCompoundFile } from '../src/cfb.ts';
import { consoleLogger } from '../src/log.ts';
import { DIGITAL_SIGNATURE_EX_STREAM, DIGITAL_SIGNATURE_STREAM, msiDigest, msiPrehash, readMsiSignature } from '../src/msi.ts';
import { CloudSession, SignError, signFile, signMsi } from '../src/signer.ts';
import { verifySignedFile, verifySignedMsi } from '../src/verify.ts';
import { parseCertificate } from '../src/x509.ts';
import { OID_EKU_CODE_SIGNING, OID_EKU_TIME_STAMPING, makeCertificate, type TestCert } from './helpers/mini-x509.ts';
import { startMockCertum, type MockCertumOptions } from './helpers/mock-certum.ts';

const helloMsi = readFileSync(new URL('./fixtures/hello.msi', import.meta.url));
const helloExe = readFileSync(new URL('./fixtures/hello.exe', import.meta.url));
const signtoolSigned = readFileSync(new URL('./fixtures/hello-signtool.msi', import.meta.url));
const ca = makeCertificate({ commonName: 'MSI Pipeline CA', ca: true });
const signingCert: TestCert = makeCertificate({ commonName: 'MSI Pipeline Publisher', issuer: ca, extendedKeyUsage: [OID_EKU_CODE_SIGNING] });
const tsaCert = makeCertificate({ commonName: 'MSI Pipeline TSA', extendedKeyUsage: [OID_EKU_TIME_STAMPING] });
const EMAIL = 'msi@example.com';

let nextCode = 200000;
const freshCode = (): string => String(nextCode++);
const baseOptions = (): MockCertumOptions => ({ email: EMAIL, acceptCode: (c) => /^\d{6}$/.test(c), signingCert, tsaCert });

async function withSession<T>(fn: (session: CloudSession, mock: Awaited<ReturnType<typeof startMockCertum>>) => Promise<T>): Promise<T> {
  const mock = await startMockCertum(baseOptions());
  try {
    const session = await CloudSession.open({ email: EMAIL, otpCode: freshCode(), endpoints: mock.endpoints, log: consoleLogger() });
    return await fn(session, mock);
  } finally {
    await mock.close();
  }
}

test('an MSI package goes through the whole pipeline: cloud signature, timestamp, chain, extended metadata stream, self-verification', async () => {
  await withSession(async (session, mock) => {
    const result = await signFile(session, helloMsi, {
      description: 'MSI pipeline demo',
      url: 'https://example.com/msi',
      timestampUrl: mock.tsaUrl,
      extraCertificates: [parseCertificate(ca.der)],
      log: consoleLogger(),
    });
    assert.equal(result.kind, 'msi');
    assert.ok(result.verification);
    assert.ok(result.timestamp);
    assert.equal(result.chain[0]?.x509.subject, 'CN=MSI Pipeline CA');
    assert.notEqual(mock.signedDigests[0], result.digest.toString('hex'), 'the HSM signs the signed-attributes digest, not the package digest');

    const independent = verifySignedFile(result.signed);
    assert.equal(independent.kind, 'msi');
    assert.equal(independent.signer.x509.fingerprint256, session.certificate.x509.fingerprint256);
    assert.equal(independent.description, 'MSI pipeline demo');
    assert.equal(independent.url, 'https://example.com/msi');
    assert.ok(independent.timestamp);
    assert.equal(independent.certificates.length, 2);

    const pkg = parseCompoundFile(result.signed);
    const signature = readMsiSignature(pkg);
    assert.ok(signature?.extended, 'MsiDigitalSignatureEx is always written');
    assert.deepEqual(signature.extended, msiPrehash(pkg, 'sha256'));
    assert.deepEqual(result.digest, msiDigest(pkg, 'sha256'));
    const names = pkg.root.children.map((c) => c.name);
    assert.ok(names.includes(DIGITAL_SIGNATURE_STREAM) && names.includes(DIGITAL_SIGNATURE_EX_STREAM));
    // Everything the Installer wrote is still there, byte for byte.
    const before = parseCompoundFile(helloMsi).root.children;
    for (const original of before) {
      const after = pkg.root.children.find((c) => c.name === original.name);
      assert.ok(after, `stream ${JSON.stringify(original.name)} survived`);
      assert.deepEqual(after.data, original.data);
      assert.deepEqual(after.clsid, original.clsid);
      assert.deepEqual(after.modifiedTime, original.modifiedTime);
    }
    // Our digest for the package equals what signtool signed for the same fixture.
    assert.deepEqual(result.digest, verifySignedMsi(signtoolSigned).digest);
  });
});

test('a signed package is refused unless replace-existing-signature is set, and then replaced cleanly', async () => {
  await withSession(async (session) => {
    await assert.rejects(signMsi(session, signtoolSigned, { timestampUrl: null }), (err: unknown) => err instanceof SignError && /already carries a signature/.test(err.message));
    const replaced = await signMsi(session, signtoolSigned, { timestampUrl: null, replaceExistingSignature: true });
    assert.equal(verifySignedMsi(replaced.signed).signer.x509.subject, 'CN=MSI Pipeline Publisher');
    assert.equal(replaced.verification?.timestamp, null);
    assert.deepEqual(replaced.digest, verifySignedMsi(signtoolSigned).digest, 'the old signature streams do not affect the digest');
    const first = await signMsi(session, helloMsi, { timestampUrl: null });
    assert.deepEqual(first.digest, replaced.digest);
  });
});

test('signFile dispatches on the magic number and rejects anything else', async () => {
  await withSession(async (session) => {
    assert.equal((await signFile(session, helloExe, { timestampUrl: null })).kind, 'pe');
    assert.equal((await signFile(session, helloMsi, { timestampUrl: null })).kind, 'msi');
    await assert.rejects(signFile(session, Buffer.from('%PDF-1.7 not signable'), { timestampUrl: null }), /neither a PE image .* nor an MSI package/);
    await assert.rejects(signMsi(session, helloExe, { timestampUrl: null }), /not an OLE compound file/);
  });
});
