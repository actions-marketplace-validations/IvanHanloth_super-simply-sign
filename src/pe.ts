/**
 * PE (Portable Executable) plumbing: locate the fields Authenticode cares
 * about, compute the Authenticode digest exactly the way the Windows
 * Authenticode specification describes it, and splice a PKCS#7 blob into the
 * attribute certificate table. Pure byte work — no Windows APIs, so this runs
 * on any runner OS.
 */
import { createHash } from 'node:crypto';
import { asBuffer } from './der.ts';

export class PeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PeError';
  }
}

export const WIN_CERT_REVISION_2_0 = 0x0200;
export const WIN_CERT_TYPE_PKCS_SIGNED_DATA = 0x0002;

/** IMAGE_DIRECTORY_ENTRY_SECURITY */
const SECURITY_DIRECTORY_INDEX = 4;

export interface PeSection {
  readonly name: string;
  readonly pointerToRawData: number;
  readonly sizeOfRawData: number;
}

export interface PeLayout {
  readonly isPe32Plus: boolean;
  readonly peHeaderOffset: number;
  readonly sizeOfHeaders: number;
  /** Offset of the 4-byte CheckSum field in the optional header. */
  readonly checksumOffset: number;
  /** Offset of the 8-byte IMAGE_DIRECTORY_ENTRY_SECURITY (VirtualAddress, Size). */
  readonly securityDirOffset: number;
  /** File offset of the attribute certificate table (0 when unsigned). */
  readonly certTableOffset: number;
  /** Size of the attribute certificate table (0 when unsigned). */
  readonly certTableSize: number;
  readonly sections: readonly PeSection[];
}

function u16(b: Buffer, off: number): number {
  if (off + 2 > b.length) throw new PeError('PE file is truncated');
  return b.readUInt16LE(off);
}

function u32(b: Buffer, off: number): number {
  if (off + 4 > b.length) throw new PeError('PE file is truncated');
  return b.readUInt32LE(off);
}

/** Parse the headers and validate everything the signing path relies on. */
export function parsePeLayout(pe: Uint8Array): PeLayout {
  const b = asBuffer(pe);
  if (b.length < 0x40 || b[0] !== 0x4d || b[1] !== 0x5a) throw new PeError('not a PE file (missing MZ header)');
  const peHeaderOffset = u32(b, 0x3c);
  if (u32(b, peHeaderOffset) !== 0x00004550) throw new PeError('not a PE file (missing PE signature)');

  const numberOfSections = u16(b, peHeaderOffset + 6);
  const sizeOfOptionalHeader = u16(b, peHeaderOffset + 20);
  const optOff = peHeaderOffset + 24;
  const magic = u16(b, optOff);
  const isPe32Plus = magic === 0x20b;
  if (!isPe32Plus && magic !== 0x10b) throw new PeError(`unknown optional header magic 0x${magic.toString(16)}`);

  const sizeOfHeaders = u32(b, optOff + 60);
  const checksumOffset = optOff + 64;
  const dataDirOff = optOff + (isPe32Plus ? 112 : 96);
  const numberOfRvaAndSizes = u32(b, dataDirOff - 4);
  if (numberOfRvaAndSizes <= SECURITY_DIRECTORY_INDEX) throw new PeError('PE has no security data directory entry');
  const securityDirOffset = dataDirOff + SECURITY_DIRECTORY_INDEX * 8;
  if (securityDirOffset + 8 > optOff + sizeOfOptionalHeader) throw new PeError('optional header is too small for its data directories');

  const sectionTableOffset = optOff + sizeOfOptionalHeader;
  const sections: PeSection[] = [];
  for (let i = 0; i < numberOfSections; i++) {
    const off = sectionTableOffset + i * 40;
    if (off + 40 > b.length) throw new PeError('section table is truncated');
    sections.push({
      name: b.toString('latin1', off, off + 8).replace(/\0+$/, ''),
      sizeOfRawData: u32(b, off + 16),
      pointerToRawData: u32(b, off + 20),
    });
  }
  if (sizeOfHeaders < sectionTableOffset + numberOfSections * 40) throw new PeError('SizeOfHeaders does not cover the section table');
  if (sizeOfHeaders > b.length) throw new PeError('SizeOfHeaders exceeds the file size');

  const certTableOffset = u32(b, securityDirOffset);
  const certTableSize = u32(b, securityDirOffset + 4);
  if (certTableSize !== 0 && (certTableOffset < sizeOfHeaders || certTableOffset + certTableSize > b.length)) {
    throw new PeError('the certificate table lies outside the file');
  }

  return { isPe32Plus, peHeaderOffset, sizeOfHeaders, checksumOffset, securityDirOffset, certTableOffset, certTableSize, sections };
}

/** Bytes needed to bring `length` up to a multiple of 8. */
export function alignmentPadding(length: number): number {
  return (8 - (length % 8)) % 8;
}

/**
 * The Authenticode digest of a PE image, per "Windows Authenticode Portable
 * Executable Signature Format": the headers minus CheckSum and the security
 * directory entry, then every section in PointerToRawData order, then any
 * trailing data minus the certificate table.
 *
 * For an unsigned file the 8-byte alignment padding that `embedSignature`
 * inserts before the certificate table is hashed as well, because Windows
 * will see it as part of the trailing data of the signed file.
 */
export function authenticodeHash(pe: Uint8Array, algorithm = 'sha256'): Buffer {
  const b = asBuffer(pe);
  const l = parsePeLayout(b);
  if (l.certTableSize !== 0 && l.certTableOffset + l.certTableSize !== b.length) {
    throw new PeError('unsupported PE: the certificate table is not at the end of the file');
  }
  const h = createHash(algorithm);
  h.update(b.subarray(0, l.checksumOffset));
  h.update(b.subarray(l.checksumOffset + 4, l.securityDirOffset));
  h.update(b.subarray(l.securityDirOffset + 8, l.sizeOfHeaders));

  let sumOfBytesHashed = l.sizeOfHeaders;
  const sections = l.sections.filter((s) => s.sizeOfRawData !== 0).sort((x, y) => x.pointerToRawData - y.pointerToRawData);
  for (const s of sections) {
    const end = s.pointerToRawData + s.sizeOfRawData;
    if (end > b.length) throw new PeError(`section "${s.name}" extends beyond the end of the file`);
    h.update(b.subarray(s.pointerToRawData, end));
    sumOfBytesHashed += s.sizeOfRawData;
  }

  const hashedEnd = l.certTableSize === 0 ? b.length : l.certTableOffset;
  if (hashedEnd > sumOfBytesHashed) h.update(b.subarray(sumOfBytesHashed, hashedEnd));
  if (l.certTableSize === 0) h.update(Buffer.alloc(alignmentPadding(b.length)));
  return h.digest();
}

/** The PE image checksum: ones-complement 16-bit sum, plus the file length. */
export function peChecksum(pe: Uint8Array, checksumOffset: number): number {
  const b = asBuffer(pe);
  let sum = 0;
  let i = 0;
  const evenEnd = b.length - (b.length % 2);
  while (i < evenEnd) {
    if (i === checksumOffset) {
      i += 4;
      continue;
    }
    sum += b.readUInt16LE(i);
    sum = (sum & 0xffff) + (sum >>> 16);
    i += 2;
  }
  if (i < b.length) {
    sum += b[i]!;
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  sum = (sum & 0xffff) + (sum >>> 16);
  return (sum + b.length) >>> 0;
}

function withChecksum(pe: Buffer, checksumOffset: number): Buffer {
  pe.writeUInt32LE(peChecksum(pe, checksumOffset), checksumOffset);
  return pe;
}

/** Append `pkcs7` as a WIN_CERTIFICATE, point the security directory at it and fix the checksum. */
export function embedSignature(pe: Uint8Array, pkcs7: Uint8Array): Buffer {
  const src = asBuffer(pe);
  const l = parsePeLayout(src);
  if (l.certTableSize !== 0) throw new PeError('the file already carries a signature');

  const tableOffset = src.length + alignmentPadding(src.length);
  const certLength = 8 + pkcs7.length;
  const tableSize = certLength + alignmentPadding(certLength);
  const out = Buffer.alloc(tableOffset + tableSize);
  src.copy(out, 0);
  out.writeUInt32LE(certLength, tableOffset);
  out.writeUInt16LE(WIN_CERT_REVISION_2_0, tableOffset + 4);
  out.writeUInt16LE(WIN_CERT_TYPE_PKCS_SIGNED_DATA, tableOffset + 6);
  asBuffer(pkcs7).copy(out, tableOffset + 8);
  out.writeUInt32LE(tableOffset, l.securityDirOffset);
  out.writeUInt32LE(tableSize, l.securityDirOffset + 4);
  return withChecksum(out, l.checksumOffset);
}

/** Remove an existing certificate table (it must sit at the end of the file). */
export function stripSignature(pe: Uint8Array): Buffer {
  const src = asBuffer(pe);
  const l = parsePeLayout(src);
  if (l.certTableSize === 0) return Buffer.from(src);
  if (l.certTableOffset + l.certTableSize !== src.length) {
    throw new PeError('cannot strip the signature: the certificate table is not at the end of the file');
  }
  const out = Buffer.from(src.subarray(0, l.certTableOffset));
  out.writeUInt32LE(0, l.securityDirOffset);
  out.writeUInt32LE(0, l.securityDirOffset + 4);
  return withChecksum(out, l.checksumOffset);
}

export interface WinCertificate {
  readonly revision: number;
  readonly type: number;
  readonly data: Buffer;
}

/** All WIN_CERTIFICATE entries of the attribute certificate table. */
export function readCertificateTable(pe: Uint8Array): WinCertificate[] {
  const b = asBuffer(pe);
  const l = parsePeLayout(b);
  const out: WinCertificate[] = [];
  let off = l.certTableOffset;
  const end = l.certTableOffset + l.certTableSize;
  while (l.certTableSize !== 0 && off + 8 <= end) {
    const length = b.readUInt32LE(off);
    if (length < 8 || off + length > end) throw new PeError('malformed WIN_CERTIFICATE entry');
    out.push({ revision: b.readUInt16LE(off + 4), type: b.readUInt16LE(off + 6), data: b.subarray(off + 8, off + length) });
    off += length + alignmentPadding(length);
  }
  return out;
}
