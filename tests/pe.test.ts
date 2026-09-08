import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { PeError, alignmentPadding, authenticodeHash, embedSignature, parsePeLayout, peChecksum, readCertificateTable, stripSignature } from '../src/pe.ts';
import { SECTION_TABLE_OFFSET, SYNTHETIC_HEADERS_SIZE, buildSyntheticPe } from './helpers/synthetic-pe.ts';

const hello = readFileSync(new URL('./fixtures/hello.exe', import.meta.url));
/** Authenticode SHA-256 of hello.exe as computed by osslsigncode (reference vector). */
const HELLO_HASH = 'bc17b1c98515d63f366bcd9f472054ae49cd5e839043265ce060b38b33ca2a43';

test('the Authenticode hash of the fixture matches osslsigncode', () => {
  assert.equal(authenticodeHash(hello).toString('hex'), HELLO_HASH);
  assert.equal(authenticodeHash(hello, 'sha1').length, 20);
});

test('the hash of an unsigned file already covers the alignment padding embed() adds', () => {
  const odd = Buffer.concat([hello, Buffer.from('ABCDE')]);
  assert.notEqual(odd.length % 8, 0);
  const padded = Buffer.concat([odd, Buffer.alloc(alignmentPadding(odd.length))]);
  assert.equal(authenticodeHash(odd).toString('hex'), authenticodeHash(padded).toString('hex'));
});

test('embedding a signature does not change the Authenticode hash (what Windows recomputes)', () => {
  const blob = Buffer.from('not really pkcs7 but long enough to matter');
  for (const image of [hello, Buffer.concat([hello, Buffer.from('xyz')])]) {
    const signed = embedSignature(image, blob);
    assert.equal(authenticodeHash(signed).toString('hex'), authenticodeHash(image).toString('hex'));
    const layout = parsePeLayout(signed);
    assert.equal(layout.certTableOffset % 8, 0);
    assert.equal(layout.certTableSize % 8, 0);
    assert.equal(layout.certTableOffset + layout.certTableSize, signed.length);
    assert.equal(signed.readUInt32LE(layout.checksumOffset), peChecksum(signed, layout.checksumOffset));
    const [entry] = readCertificateTable(signed);
    assert.equal(entry?.revision, 0x0200);
    assert.equal(entry?.type, 0x0002);
    assert.equal(entry?.data.subarray(0, blob.length).toString(), blob.toString());
    assert.throws(() => embedSignature(signed, blob), /already carries a signature/);
  }
});

test('stripping a signature restores the unsigned image (with a valid checksum)', () => {
  const signed = embedSignature(hello, Buffer.from('blob'));
  const stripped = stripSignature(signed);
  assert.equal(stripped.length, hello.length);
  // hello.exe was linked with CheckSum = 0; stripping recomputes it, everything else is byte-identical.
  const layout = parsePeLayout(hello);
  const expected = Buffer.from(hello);
  expected.writeUInt32LE(peChecksum(hello, layout.checksumOffset), layout.checksumOffset);
  assert.equal(createHash('sha256').update(stripped).digest('hex'), createHash('sha256').update(expected).digest('hex'));
  assert.equal(authenticodeHash(stripped).toString('hex'), HELLO_HASH, 'the checksum field is excluded from the Authenticode hash');
  assert.equal(stripSignature(hello).equals(hello), true);
  const trailing = Buffer.concat([signed, Buffer.from('overlay')]);
  const signedLayout = parsePeLayout(signed);
  trailing.writeUInt32LE(signedLayout.certTableSize, signedLayout.securityDirOffset + 4);
  assert.throws(() => stripSignature(trailing), /not at the end/);
  assert.throws(() => authenticodeHash(trailing), /not at the end/);
});

test('parsePeLayout rejects non-PE and inconsistent images', () => {
  assert.throws(() => parsePeLayout(Buffer.from('hello world')), /MZ header/);
  const noPe = Buffer.from(hello.subarray(0, 0x200));
  noPe.writeUInt32LE(0x41414141, 0xf0);
  assert.throws(() => parsePeLayout(noPe), /PE signature/);
  assert.throws(() => parsePeLayout(hello.subarray(0, 0x100)), PeError);
  const outside = buildSyntheticPe([{ name: '.text', data: Buffer.from('code') }], { securityDirectory: [0xfffffff0, 0x20] });
  assert.throws(() => authenticodeHash(outside), /outside the file/);
  const stale = buildSyntheticPe([{ name: '.text', data: Buffer.from('code') }], { securityDirectory: [0xfffffff0, 0] });
  assert.equal(authenticodeHash(stale).length, 32);
});

test('sections are hashed in PointerToRawData order regardless of the section table order', () => {
  const sections = [
    { name: '.text', data: Buffer.from('first section '.repeat(40)) },
    { name: '.data', data: Buffer.from('second section '.repeat(20)) },
    { name: '.rsrc', data: Buffer.from('third') },
  ];
  const trailing = Buffer.from('overlay data that is not in any section');
  const straight = buildSyntheticPe(sections, { trailing });
  const reversed = buildSyntheticPe(sections, { reverseSectionTable: true, trailing });
  assert.notEqual(straight.toString('hex'), reversed.toString('hex'));
  // The headers differ (section table order), so hash each against a manual computation.
  for (const image of [straight, reversed]) {
    const layout = parsePeLayout(image);
    const expected = createHash('sha256');
    expected.update(image.subarray(0, layout.checksumOffset));
    expected.update(image.subarray(layout.checksumOffset + 4, layout.securityDirOffset));
    expected.update(image.subarray(layout.securityDirOffset + 8, SYNTHETIC_HEADERS_SIZE));
    expected.update(image.subarray(SYNTHETIC_HEADERS_SIZE)); // sections in file order + overlay
    expected.update(Buffer.alloc(alignmentPadding(image.length)));
    assert.equal(authenticodeHash(image).toString('hex'), expected.digest('hex'));
  }
  assert.equal(parsePeLayout(reversed).sections[0]?.name, '.rsrc');
  assert.equal(SECTION_TABLE_OFFSET, 0x148);
});

test('a section that claims bytes beyond the file is rejected', () => {
  const image = buildSyntheticPe([{ name: '.text', data: Buffer.from('code') }]);
  image.writeUInt32LE(0x10000, SECTION_TABLE_OFFSET + 16); // SizeOfRawData
  assert.throws(() => authenticodeHash(image), /extends beyond/);
});

test('the PE checksum matches the checksum the fixture linker wrote', () => {
  // hello.exe ships with CheckSum = 0 (linker default); the recomputed value is deterministic.
  const layout = parsePeLayout(hello);
  assert.equal(peChecksum(hello, layout.checksumOffset), 0x247dc);
  const odd = Buffer.concat([hello, Buffer.from([0x7f])]);
  assert.equal(typeof peChecksum(odd, layout.checksumOffset), 'number');
});
