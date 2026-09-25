/**
 * MSI (Windows Installer package) Authenticode. A package is an OLE compound
 * file (see `cfb.ts`); its signature is the PKCS#7 blob stored verbatim in a
 * root stream named `\x05DigitalSignature`, optionally accompanied by
 * `\x05MsiDigitalSignatureEx`, a digest over the directory *metadata* that is
 * prepended to the content digest so names, CLSIDs and times are covered too.
 *
 * The content digest walks the tree in a very particular order — sorted by a
 * memcmp over the raw UTF-16LE names, longer name first on a prefix tie —
 * hashing every stream's bytes and, after a storage's children, its CLSID.
 * These rules were checked byte for byte against packages signed by
 * Microsoft's signtool (see tests/fixtures and docs/PROTOCOL.md).
 */
import { createHash } from 'node:crypto';
import { ENTRY_ROOT, ENTRY_STORAGE, ENTRY_STREAM, makeStream, withChildren, type CfbEntry, type CompoundFile } from './cfb.ts';
import * as der from './der.ts';

export class MsiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MsiError';
  }
}

/** SPC_SIPINFO_OBJID — the SpcAttributeTypeAndOptionalValue type used for MSI. */
export const OID_SPC_SIPINFO = '1.3.6.1.4.1.311.2.1.30';
export const DIGITAL_SIGNATURE_STREAM = 'DigitalSignature';
export const DIGITAL_SIGNATURE_EX_STREAM = 'MsiDigitalSignatureEx';

/** The SIP class for MSI packages, {000C10F1-0000-0000-C000-000000000046} in little-endian GUID order. */
const SIP_UUID_MSI = Buffer.from('f1100c0000000000c000000000000046', 'hex');

/**
 * `SpcAttributeTypeAndOptionalValue { SPC_SIPINFO, SpcSipInfo { 2, uuid, 0, 0, 0, 0, 0 } }`
 * — identical for every MSI. The leading INTEGER is 2 in everything signtool
 * produces (osslsigncode writes 1; Windows accepts both, we match signtool).
 */
export function spcSipInfo(): Buffer {
  const zero = der.integer(0);
  return der.seq(der.oid(OID_SPC_SIPINFO), der.seq(der.integer(2), der.octetString(SIP_UUID_MSI), zero, zero, zero, zero, zero));
}

/**
 * Digest ordering: memcmp over the UTF-16LE name bytes *including the
 * terminator* — so on a prefix tie the shorter name sorts first (its 0x0000
 * terminator compares below any character). Byte order, not code-unit order:
 * the two disagree when low and high bytes rank differently, and only the
 * byte order reproduces what signtool signed.
 */
export function hashNameCompare(a: CfbEntry, b: CfbEntry): number {
  const n = Math.min(a.nameRaw.length, b.nameRaw.length);
  const d = Buffer.compare(a.nameRaw.subarray(0, n), b.nameRaw.subarray(0, n));
  return d !== 0 ? d : a.nameRaw.length - b.nameRaw.length;
}

const isSignatureStream = (e: CfbEntry): boolean => e.name === DIGITAL_SIGNATURE_STREAM || e.name === DIGITAL_SIGNATURE_EX_STREAM;
const sortedChildren = (e: CfbEntry): CfbEntry[] => [...e.children].sort(hashNameCompare);

/**
 * The Authenticode digest of a package: every stream's bytes in walk order,
 * then each storage's CLSID after its children. Only `\x05DigitalSignature`
 * is skipped. `\x05MsiDigitalSignatureEx`, when present, is hashed like any
 * other stream at its sorted position — which is normally first (its name
 * starts with byte 0x05), so its value *looks* like a prefix of the digest,
 * but a stream whose name sorts below it (first byte 0x00–0x04, e.g. the
 * MSI-encoded cabinet name "08…" = U+3A00…) is hashed before it. Confirmed
 * against signtool with exactly such names; osslsigncode's "prepend the
 * pre-hash" model breaks on them.
 */
export function msiDigest(file: CompoundFile, algorithm: string): Buffer {
  const h = createHash(algorithm);
  const walk = (entry: CfbEntry, isRoot: boolean): void => {
    for (const child of sortedChildren(entry)) {
      if (isRoot && child.name === DIGITAL_SIGNATURE_STREAM) continue;
      if (child.type === ENTRY_STREAM) h.update(child.data);
      else if (child.type === ENTRY_STORAGE) walk(child, false);
    }
    h.update(entry.clsid);
  };
  walk(file.root, true);
  return h.digest();
}

/**
 * The MsiDigitalSignatureEx value: a digest over directory metadata, in the
 * same walk order — for each entry its name (not for the root), its CLSID
 * (storages) or low 32 bits of its size (streams), its state bits and (not
 * for the root) its creation and modification times.
 */
export function msiPrehash(file: CompoundFile, algorithm: string): Buffer {
  const h = createHash(algorithm);
  const metadata = (e: CfbEntry): void => {
    if (e.type !== ENTRY_ROOT) h.update(e.nameRaw);
    if (e.type === ENTRY_STREAM) {
      const size = Buffer.alloc(4);
      size.writeUInt32LE(e.data.length >>> 0);
      h.update(size);
    } else {
      h.update(e.clsid);
    }
    const state = Buffer.alloc(4);
    state.writeUInt32LE(e.stateBits >>> 0);
    h.update(state);
    if (e.type !== ENTRY_ROOT) {
      h.update(e.creationTime);
      h.update(e.modifiedTime);
    }
  };
  const walk = (entry: CfbEntry, isRoot: boolean): void => {
    metadata(entry);
    for (const child of sortedChildren(entry)) {
      if (isRoot && isSignatureStream(child)) continue;
      if (child.type === ENTRY_STREAM) metadata(child);
      else if (child.type === ENTRY_STORAGE) walk(child, false);
    }
  };
  walk(file.root, true);
  return h.digest();
}

export interface MsiSignature {
  /** The PKCS#7 SignedData exactly as stored. */
  readonly pkcs7: Buffer;
  /** The MsiDigitalSignatureEx value, if that stream exists. */
  readonly extended: Buffer | null;
}

/** The signature streams of a package, or null when it is unsigned. */
export function readMsiSignature(file: CompoundFile): MsiSignature | null {
  const find = (name: string): CfbEntry | undefined => file.root.children.find((c) => c.name === name && c.type === ENTRY_STREAM);
  const signature = find(DIGITAL_SIGNATURE_STREAM);
  if (!signature) return null;
  const extended = find(DIGITAL_SIGNATURE_EX_STREAM);
  return { pkcs7: signature.data, extended: extended ? extended.data : null };
}

export function isMsiSigned(file: CompoundFile): boolean {
  return readMsiSignature(file) !== null;
}

/** The package without its signature streams. */
export function stripMsiSignature(file: CompoundFile): CompoundFile {
  return { ...file, root: withChildren(file.root, file.root.children.filter((c) => !isSignatureStream(c))) };
}

/** The package with only the MsiDigitalSignatureEx stream (its value is what `msiPrehash` computes) — the tree `msiDigest` must see when signing. */
export function withExtendedSignature(file: CompoundFile, extended: Uint8Array): CompoundFile {
  const stripped = stripMsiSignature(file);
  return { ...stripped, root: withChildren(stripped.root, [...stripped.root.children, makeStream(DIGITAL_SIGNATURE_EX_STREAM, extended)]) };
}

/** The package with `pkcs7` (and the optional MsiDigitalSignatureEx value) as its signature streams. */
export function embedMsiSignature(file: CompoundFile, pkcs7: Uint8Array, extended: Uint8Array | null): CompoundFile {
  const stripped = stripMsiSignature(file);
  const streams = [makeStream(DIGITAL_SIGNATURE_STREAM, pkcs7)];
  if (extended) streams.push(makeStream(DIGITAL_SIGNATURE_EX_STREAM, extended));
  return { ...stripped, root: withChildren(stripped.root, [...stripped.root.children, ...streams]) };
}
