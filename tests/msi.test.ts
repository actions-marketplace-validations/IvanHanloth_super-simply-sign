import assert from 'node:assert/strict';
import { createHash, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { buildSignedData, prepareIndirectData } from '../src/authenticode.ts';
import { CfbError, ENTRY_ROOT, ENTRY_STORAGE, ENTRY_STREAM, makeStream, parseCompoundFile, treeNameCompare, withChildren, writeCompoundFile, type CfbEntry, type CompoundFile } from '../src/cfb.ts';
import { detectImageKind } from '../src/image.ts';
import { DIGITAL_SIGNATURE_EX_STREAM, DIGITAL_SIGNATURE_STREAM, embedMsiSignature, hashNameCompare, msiDigest, msiPrehash, readMsiSignature, spcSipInfo, stripMsiSignature, withExtendedSignature } from '../src/msi.ts';
import { VerificationError, verifySignedFile, verifySignedMsi, verifySignedPe } from '../src/verify.ts';
import { oneLineName, parseCertificate } from '../src/x509.ts';
import { OID_EKU_CODE_SIGNING, makeCertificate } from './helpers/mini-x509.ts';

/** Built by the Windows Installer engine: Property/AB/ABC tables, a 6000-byte Binary stream, a nested storage — see fixtures/README.md. */
const hello = readFileSync(new URL('./fixtures/hello.msi', import.meta.url));
/** The same package signed by Microsoft signtool with a real Certum timestamp. */
const signtoolSigned = readFileSync(new URL('./fixtures/hello-signtool.msi', import.meta.url));

const streamNames = (e: CfbEntry): string[] => e.children.filter((c) => c.type === ENTRY_STREAM).map((c) => c.name);

function sameTree(a: CfbEntry, b: CfbEntry): void {
  assert.equal(a.name, b.name);
  assert.equal(a.type, b.type);
  assert.deepEqual([a.nameRaw, a.clsid, a.creationTime, a.modifiedTime, a.data], [b.nameRaw, b.clsid, b.creationTime, b.modifiedTime, b.data]);
  assert.equal(a.stateBits, b.stateBits);
  const sa = [...a.children].sort(hashNameCompare);
  const sb = [...b.children].sort(hashNameCompare);
  assert.equal(sa.length, sb.length);
  sa.forEach((c, i) => sameTree(c, sb[i]!));
}

test('the Installer-built fixture parses: nested storage, a regular-sector stream and mini-stream streams', () => {
  assert.equal(detectImageKind(hello), 'msi');
  const pkg = parseCompoundFile(hello);
  assert.equal(pkg.majorVersion, 4);
  assert.equal(pkg.root.type, ENTRY_ROOT);
  const sub = pkg.root.children.find((c) => c.type === ENTRY_STORAGE);
  assert.ok(sub, 'the _Storages row became a nested storage');
  assert.equal(sub.name, 'SubStorage');
  assert.ok(sub.children.length >= 5, 'the nested storage carries the embedded package’s streams');
  const big = pkg.root.children.find((c) => c.data.length === 6000);
  assert.ok(big, 'the 6000-byte Binary blob is a stream in regular sectors');
  assert.ok(streamNames(pkg.root).includes('SummaryInformation'));
  assert.ok(pkg.root.children.some((c) => c.data.length > 0 && c.data.length < 64), 'tiny streams live in the mini stream');
  assert.equal(readMsiSignature(pkg), null);
});

test('parse → write → parse round-trips the tree, and the writer output is a valid package for the reader', () => {
  const pkg = parseCompoundFile(hello);
  const rewritten = writeCompoundFile(pkg);
  assert.equal(detectImageKind(rewritten), 'msi');
  const again = parseCompoundFile(rewritten);
  sameTree(pkg.root, again.root);
  assert.deepEqual(msiDigest(again, 'sha256'), msiDigest(pkg, 'sha256'));
  assert.deepEqual(msiPrehash(again, 'sha256'), msiPrehash(pkg, 'sha256'));
  // idempotent: writing the re-parsed tree gives the same bytes
  assert.deepEqual(writeCompoundFile(again), rewritten);
});

test('a version 3 (512-byte sector) package with many streams round-trips, including empty and cutoff-sized streams', () => {
  const stream = (name: string, size: number, fill = name.length): CfbEntry => makeStream(name, Buffer.alloc(size, fill));
  const streams: CfbEntry[] = [
    stream('empty', 0),
    stream('tiny', 1),
    stream('mini', 4095),
    stream('cutoff', 4096),
    stream('big', 70_000),
    stream('SummaryInformation', 300),
  ];
  for (let i = 0; i < 300; i++) streams.push(stream(`s${i}`, (i * 37) % 5000));
  const nested: CfbEntry = { ...makeStream('deep', Buffer.alloc(0)), type: ENTRY_STORAGE, children: [stream('inner', 10), { ...makeStream('deeper', Buffer.alloc(0)), type: ENTRY_STORAGE, children: [stream('leaf', 5000)] }] };
  const root: CfbEntry = { ...makeStream('Root Entry', Buffer.alloc(0)), type: ENTRY_ROOT, clsid: Buffer.from('000c108400000000c000000000000046', 'hex'), children: [...streams, nested] };
  const file: CompoundFile = { root, majorVersion: 3 };
  const bytes = writeCompoundFile(file);
  assert.equal(bytes.length % 512, 0);
  assert.equal(bytes.readUInt16LE(0x1a), 3);
  assert.ok(bytes.readUInt32LE(0x2c) > 1, 'several FAT sectors');
  const again = parseCompoundFile(bytes);
  sameTree(root, again.root);
  assert.equal(again.root.children.find((c) => c.name === 'cutoff')?.data.length, 4096);
  assert.equal(again.root.children.find((c) => c.name === 'empty')?.data.length, 0);
});

test('a package large enough to need DIFAT sectors round-trips', () => {
  // 512-byte sectors, 128 FAT entries per sector; 109 FAT sectors cover ~7 MB, so 8 MB of streams needs a DIFAT sector.
  const root: CfbEntry = { ...makeStream('Root Entry', Buffer.alloc(0)), type: ENTRY_ROOT, children: [makeStream('huge', Buffer.alloc(8 * 1024 * 1024, 7))] };
  const bytes = writeCompoundFile({ root, majorVersion: 3 });
  assert.ok(bytes.readUInt32LE(0x48) >= 1, 'a DIFAT sector was written');
  const again = parseCompoundFile(bytes);
  assert.equal(again.root.children[0]?.data.length, 8 * 1024 * 1024);
  assert.ok(again.root.children[0]!.data.every((b) => b === 7));
});

test('the writer rejects what the format cannot express', () => {
  const root: CfbEntry = { ...makeStream('Root Entry', Buffer.alloc(0)), type: ENTRY_ROOT, children: [] };
  assert.throws(() => writeCompoundFile({ root: withChildren(root, [makeStream('a'.repeat(32), Buffer.alloc(1))]), majorVersion: 4 }), CfbError);
  assert.throws(() => writeCompoundFile({ root: withChildren(root, [makeStream('Same', Buffer.alloc(1)), makeStream('same', Buffer.alloc(1))]), majorVersion: 4 }), /duplicate/);
  assert.throws(() => parseCompoundFile(Buffer.alloc(1024)), /bad signature/);
  const truncated = hello.subarray(0, 8192);
  assert.throws(() => parseCompoundFile(truncated), CfbError);
});

test('directory tree order is by length then case-insensitive code unit; digest order is by raw bytes with the shorter prefix first', () => {
  const e = (name: string): CfbEntry => makeStream(name, Buffer.alloc(0));
  assert.ok(treeNameCompare(e('b'), e('aa')) < 0, 'shorter first');
  assert.ok(treeNameCompare(e('abc'), e('ABD')) < 0, 'case-insensitive');
  assert.equal(treeNameCompare(e('abc'), e('ABC')), 0);
  assert.ok(hashNameCompare(e('ab'), e('abc')) < 0, 'the shorter name sorts first on a prefix tie (its terminator compares lowest)');
  assert.ok(hashNameCompare(e('abd'), e('abc')) > 0);
  assert.ok(hashNameCompare(e('䡀'), e('㦨')) < 0, 'raw little-endian bytes: 0x40 0x48 sorts before 0xa8 0x39');
  assert.ok(hashNameCompare(e('B'), e('a')) < 0, 'case-sensitive');
});

test('an MSI signed by signtool (with a genuine Certum timestamp) verifies end to end', () => {
  const result = verifySignedMsi(signtoolSigned);
  assert.equal(result.kind, 'msi');
  assert.equal(result.hashAlgorithm, 'sha256');
  assert.equal(result.signer.x509.subject, 'CN=SSS signtool cross-check');
  assert.equal(result.description, 'signtool cross-check');
  assert.equal(result.url, 'https://example.com/xcheck');
  assert.ok(result.timestamp, 'the RFC 3161 counter-signature must be found and verified');
  assert.equal(oneLineName(result.timestamp.tsa.x509.issuer), 'C=PL, O=Asseco Data Systems S.A., CN=Certum Timestamping 2021 CA');
  assert.equal(verifySignedFile(signtoolSigned).digest.toString('hex'), result.digest.toString('hex'));

  const pkg = parseCompoundFile(signtoolSigned);
  const signature = readMsiSignature(pkg);
  assert.ok(signature?.extended, 'signtool writes MsiDigitalSignatureEx');
  assert.deepEqual(msiPrehash(pkg, 'sha256'), signature.extended, 'our metadata pre-hash equals the one signtool stored');
  assert.deepEqual(msiDigest(pkg, 'sha256'), result.digest);
  // \x05DigitalSignature is ignored by the digest: the unsigned fixture plus the metadata stream hashes the same
  assert.deepEqual(msiDigest(withExtendedSignature(parseCompoundFile(hello), signature.extended), 'sha256'), result.digest);
  assert.deepEqual(msiPrehash(parseCompoundFile(hello), 'sha256'), signature.extended);
});

test('a stream whose name sorts below the signature streams is hashed before MsiDigitalSignatureEx (signtool-signed regression fixture)', () => {
  // Built by our writer, signed by signtool: streams "㨀" (bytes 00 3A — the MSI-encoded
  // cabinet name "08…"), "䅁" and \x05SummaryInformation. osslsigncode's "pre-hash first" model fails here.
  const bytes = readFileSync(new URL('./fixtures/lowname-signtool.msi', import.meta.url));
  const result = verifySignedMsi(bytes);
  assert.equal(result.signer.x509.subject, 'CN=SSS probe');
  const pkg = parseCompoundFile(bytes);
  const order = [...pkg.root.children].sort(hashNameCompare).map((c) => c.name);
  assert.deepEqual(order, ['㨀', DIGITAL_SIGNATURE_STREAM, DIGITAL_SIGNATURE_EX_STREAM, 'SummaryInformation', '䅁']);
  const signature = readMsiSignature(pkg);
  assert.ok(signature?.extended);
  // Hashing the pre-hash first (osslsigncode's model) gives a different digest than what signtool signed.
  const prefixModel = createHash('sha256')
    .update(signature.extended)
    .update(pkg.root.children.find((c) => c.name === '㨀')!.data)
    .update(pkg.root.children.find((c) => c.name === 'SummaryInformation')!.data)
    .update(pkg.root.children.find((c) => c.name === '䅁')!.data)
    .update(pkg.root.clsid)
    .digest();
  assert.notDeepEqual(prefixModel, result.digest);
});

test('tampering with a signed package is detected, in content and in metadata', () => {
  const pkg = parseCompoundFile(signtoolSigned);
  const flip = (mutate: (root: CfbEntry) => CfbEntry): Buffer => writeCompoundFile({ ...pkg, root: mutate(pkg.root) });
  const big = pkg.root.children.find((c) => c.data.length === 6000)!;
  const contentTampered = flip((root) => withChildren(root, root.children.map((c) => (c === big ? { ...c, data: Buffer.from([...c.data.subarray(0, 100), c.data[100]! ^ 1, ...c.data.subarray(101)]) } : c))));
  assert.throws(() => verifySignedMsi(contentTampered), /digest mismatch/);
  const renamed = flip((root) => withChildren(root, root.children.map((c) => (c === big ? { ...c, name: 'renamed', nameRaw: Buffer.from('renamed', 'utf16le') } : c))));
  assert.throws(() => verifySignedMsi(renamed), /MsiDigitalSignatureEx stream does not match/);
  const dropped = flip((root) => withChildren(root, root.children.filter((c) => c.name !== DIGITAL_SIGNATURE_EX_STREAM)));
  assert.throws(() => verifySignedMsi(dropped), /digest mismatch/, 'without the pre-hash the content digest no longer matches what was signed');
  assert.throws(() => verifySignedMsi(hello), /no Authenticode signature/);
  assert.throws(() => verifySignedPe(signtoolSigned), VerificationError);
  const stripped = writeCompoundFile(stripMsiSignature(pkg));
  assert.equal(readMsiSignature(parseCompoundFile(stripped)), null);
  assert.deepEqual(msiDigest(parseCompoundFile(stripped), 'sha256'), msiDigest(parseCompoundFile(hello), 'sha256'));
});

test('a locally assembled MSI signature verifies, with and without the extended metadata stream', () => {
  const ca = makeCertificate({ commonName: 'MSI Test CA', ca: true });
  const leaf = makeCertificate({ commonName: 'MSI Publisher', issuer: ca, extendedKeyUsage: [OID_EKU_CODE_SIGNING] });
  const leafInfo = parseCertificate(leaf.der);
  const pkg = parseCompoundFile(hello);
  for (const extended of [true, false]) {
    const prehash = extended ? msiPrehash(pkg, 'sha256') : null;
    const digest = msiDigest(prehash ? withExtendedSignature(pkg, prehash) : pkg, 'sha256');
    const prepared = prepareIndirectData(spcSipInfo(), digest, { description: 'MSI demo', url: 'https://example.com/msi', signingTime: new Date() });
    const signature = sign('sha256', prepared.signedAttrsSet, leaf.privateKey);
    const pkcs7 = buildSignedData(prepared, signature, leafInfo, [parseCertificate(ca.der)], null);
    const signed = writeCompoundFile(embedMsiSignature(pkg, pkcs7, prehash));
    const result = verifySignedMsi(signed);
    assert.equal(result.signer.x509.subject, 'CN=MSI Publisher');
    assert.equal(result.description, 'MSI demo');
    assert.equal(result.certificates.length, 2);
    assert.deepEqual(result.digest, digest);
    const streams = streamNames(parseCompoundFile(signed).root);
    assert.ok(streams.includes(DIGITAL_SIGNATURE_STREAM));
    assert.equal(streams.includes(DIGITAL_SIGNATURE_EX_STREAM), extended);
    assert.equal(createHash('sha256').update(signed).digest('hex').length, 64);
  }
});
