import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as der from '../src/der.ts';

test('encodes OIDs byte for byte like the reference vectors', () => {
  assert.equal(der.oid('2.16.840.1.101.3.4.2.1').toString('hex'), '0609608648016503040201');
  assert.equal(der.oid('1.3.6.1.4.1.311.2.1.4').toString('hex'), '060a2b060104018237020104');
  assert.equal(der.decodeOid(der.readExact(der.oid('1.2.840.113549.1.9.16.1.4'))), '1.2.840.113549.1.9.16.1.4');
  assert.equal(der.decodeOid(der.readExact(der.oid('2.999.1'))), '2.999.1');
  assert.throws(() => der.oid('3.1'), der.DerError);
  assert.throws(() => der.oid('1.40'), der.DerError);
  assert.throws(() => der.oid('1.x'), der.DerError);
});

test('length encoding covers short and long forms', () => {
  assert.deepEqual([...der.encodeLength(0x7f)], [0x7f]);
  assert.deepEqual([...der.encodeLength(0x80)], [0x81, 0x80]);
  const long = der.tlv(0x04, Buffer.alloc(300));
  assert.deepEqual([...long.subarray(0, 4)], [0x04, 0x82, 0x01, 0x2c]);
  assert.equal(der.readExact(long).length, 300);
  assert.equal(der.readExact(der.tlv(0x04, Buffer.alloc(70_000))).length, 70_000);
});

test('INTEGER encoding is minimal and unsigned-safe', () => {
  assert.equal(der.integer(1).toString('hex'), '020101');
  assert.equal(der.integer(0).toString('hex'), '020100');
  assert.equal(der.integer(127).toString('hex'), '02017f');
  assert.equal(der.integer(128).toString('hex'), '02020080');
  assert.equal(der.integer(Buffer.from([0x00, 0x00, 0xff])).toString('hex'), '020200ff');
  assert.equal(der.integer(65537n).toString('hex'), '0203010001');
  assert.equal(der.integerValue(der.readExact(der.integer(65537n))), 65537n);
  assert.equal(der.integerMagnitude(der.readExact(der.integer(Buffer.from([0x80])))).toString('hex'), '80');
  assert.throws(() => der.integer(-1), der.DerError);
});

test('SET OF members are sorted the X.690 way', () => {
  const a = Buffer.from([0x04, 0x01, 0x02]);
  const b = Buffer.from([0x04, 0x01, 0x01]);
  const c = Buffer.from([0x04, 0x02, 0x01, 0x00]);
  assert.equal(der.setOf([a, c, b]).toString('hex'), '310a' + '040101' + '040102' + '04020100');
  assert.ok(der.derCompare(Buffer.from([1]), Buffer.from([1, 0])) < 0);
  assert.ok(der.derCompare(Buffer.from([1, 1]), Buffer.from([1])) > 0);
});

test('time encodings match the reference vector and round-trip', () => {
  const t = new Date(Date.UTC(2026, 6, 10, 7, 18, 1));
  assert.equal(der.readExact(der.utcTime(t)).content.toString('latin1'), '260710071801Z');
  assert.equal(der.readExact(der.time(t)).tag, 0x17);
  const far = new Date(Date.UTC(2051, 0, 2, 3, 4, 5));
  assert.equal(der.readExact(der.time(far)).tag, 0x18);
  assert.equal(der.readExact(der.generalizedTime(far)).content.toString('latin1'), '20510102030405Z');
  assert.equal(der.decodeTime(der.readExact(der.utcTime(t))).getTime(), t.getTime());
  assert.equal(der.decodeTime(der.readExact(der.generalizedTime(far))).getTime(), far.getTime());
  assert.equal(der.decodeTime(der.readExact(der.tlv(0x18, Buffer.from('20260710071801.5Z')))).getTime(), t.getTime() + 500);
  assert.equal(der.decodeTime(der.readExact(der.tlv(0x17, Buffer.from('991231235959Z')))).getUTCFullYear(), 1999);
  assert.throws(() => der.utcTime(new Date(Date.UTC(2050, 0, 1))), der.DerError);
  assert.throws(() => der.decodeTime(der.readExact(der.tlv(0x17, Buffer.from('garbage')))), der.DerError);
});

test('string types', () => {
  assert.equal(der.utf16be('<<<Obsolete>>>').length, 28);
  assert.equal(der.bmpString('A').toString('hex'), '1e020041');
  assert.equal(der.ia5String('ab').toString('hex'), '16026162');
  assert.throws(() => der.ia5String('é'), der.DerError);
  assert.equal(der.bitString(Buffer.from([0x80]), 7).toString('hex'), '03020780');
});

test('readTlv rejects what DER forbids and reports truncation', () => {
  assert.throws(() => der.readTlv(Buffer.from([0x30, 0x80, 0x00, 0x00])), /indefinite/);
  assert.throws(() => der.readTlv(Buffer.from([0x30, 0x05, 0x00])), /truncated/);
  assert.throws(() => der.readTlv(Buffer.from([0x30])), /unexpected end/);
  assert.throws(() => der.readTlv(Buffer.from([0x1f, 0x81, 0x00])), /multi-byte/);
  assert.throws(() => der.readExact(Buffer.from([0x05, 0x00, 0xff])), /trailing/);
  const t = der.readTlv(Buffer.from([0xff, 0x30, 0x03, 0x02, 0x01, 0x07]), 1);
  assert.equal(t.tag, 0x30);
  assert.equal(t.constructed, true);
  assert.equal(t.end, 6);
  assert.deepEqual([...t.content], [0x02, 0x01, 0x07]);
});

test('children, expectTag and octets walk constructed values', () => {
  const s = der.seq(der.integer(7), der.octetString(Buffer.from('hi')), der.nul());
  const kids = der.children(s);
  assert.equal(kids.length, 3);
  assert.equal(der.integerValue(der.expectTag(kids[0], 0x02, 'int')), 7n);
  assert.equal(der.octets(kids[1], 'str').toString(), 'hi');
  assert.throws(() => der.expectTag(kids[2], 0x04, 'oops'), /expected tag 0x4, got 0x5/);
  assert.throws(() => der.expectTag(undefined, 0x04, 'missing thing'), /missing missing thing/);
  assert.throws(() => der.children(Buffer.from([0x30, 0x02, 0x04, 0x05])), der.DerError);
});
