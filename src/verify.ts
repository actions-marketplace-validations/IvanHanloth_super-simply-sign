/**
 * Self-verification of a signed file — a compact Authenticode verifier that
 * re-does everything a Windows verifier does short of chain trust:
 *
 *  - the PKCS#7 SignedData (from a PE's WIN_CERTIFICATE or an MSI's
 *    `\x05DigitalSignature` stream) wraps an SpcIndirectDataContent for the
 *    right file type;
 *  - the embedded digest equals the file's Authenticode digest, recomputed
 *    (for an MSI with `\x05MsiDigitalSignatureEx`, that metadata pre-hash is
 *    recomputed and must match too);
 *  - the signer certificate is embedded, and the signed attributes carry the
 *    right contentType and messageDigest;
 *  - the RSA signature verifies with that certificate;
 *  - if an RFC 3161 token is present, it covers this very signature and
 *    verifies with the TSA certificate it carries.
 *
 * `signFile` runs this on its own output before a file is written, so a file
 * that Windows would flag as tampered can never leave the action.
 */
import { createHash } from 'node:crypto';
import { OID_RFC3161_COUNTER_SIGN, OID_SPC_INDIRECT_DATA, OID_SPC_PE_IMAGE_DATA, OID_SPC_SP_OPUS_INFO } from './authenticode.ts';
import { parseCompoundFile } from './cfb.ts';
import { CmsError, OID_SIGNING_TIME, findAttribute, findSignerCertificate, hashNameForOid, parseAlgorithmIdentifier, parseSignedData, verifySignerInfo } from './cms.ts';
import * as der from './der.ts';
import { detectImageKind, type ImageKind } from './image.ts';
import { OID_SPC_SIPINFO, msiDigest, msiPrehash, readMsiSignature } from './msi.ts';
import { WIN_CERT_TYPE_PKCS_SIGNED_DATA, authenticodeHash, readCertificateTable } from './pe.ts';
import { TimestampError, verifyTimestampToken, type TimestampToken } from './timestamp.ts';
import type { CertificateInfo } from './x509.ts';

export class VerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VerificationError';
  }
}

export interface VerificationResult {
  readonly kind: ImageKind;
  readonly hashAlgorithm: string;
  /** The Authenticode digest of the file, as recomputed (and as embedded — they must agree). */
  readonly digest: Buffer;
  readonly signer: CertificateInfo;
  readonly certificates: readonly CertificateInfo[];
  readonly signingTime: Date | null;
  readonly description: string | null;
  readonly url: string | null;
  readonly timestamp: TimestampToken | null;
}

const message = (err: unknown): string => (err instanceof Error ? err.message : String(err));

function spcString(t: der.Tlv): string | null {
  if (t.tag === 0x80) return Buffer.from(t.content).swap16().toString('utf16le'); // unicode BMPString
  if (t.tag === 0x81) return t.content.toString('latin1'); // ascii IA5String
  return null;
}

/** `SpcSpOpusInfo { programName [0] SpcString, moreInfo [1] SpcLink }` — best effort. */
export function parseOpusInfo(t: der.Tlv): { description: string | null; url: string | null } {
  let description: string | null = null;
  let url: string | null = null;
  for (const field of der.children(t)) {
    const inner = der.children(field)[0];
    if (!inner) continue;
    if (field.tag === 0xa0) description = spcString(inner);
    else if (field.tag === 0xa1 && inner.tag === 0x80) url = inner.content.toString('latin1');
  }
  return { description, url };
}

/**
 * Verify a PKCS#7 Authenticode signature against the file it claims to
 * cover: `expectedType` is the SpcAttributeTypeAndOptionalValue type for
 * this file kind and `computeDigest` recomputes the file's digest with the
 * algorithm the signature names.
 */
export function verifySignedData(kind: ImageKind, pkcs7: Uint8Array, expectedType: string, computeDigest: (hashAlgorithm: string) => Buffer): VerificationResult {
  let sd;
  let spc: der.Tlv[];
  try {
    // A PE's WIN_CERTIFICATE body may be padded: take exactly one DER value.
    sd = parseSignedData(der.readTlv(pkcs7, 0).raw);
    if (sd.eContentType !== OID_SPC_INDIRECT_DATA || !sd.eContent) throw new CmsError('the signature does not wrap an SpcIndirectDataContent');
    spc = der.children(der.expectTag(sd.eContent, 0x30, 'SpcIndirectDataContent'));
  } catch (err) {
    throw new VerificationError(`malformed signature: ${message(err)}`);
  }

  const attributeType = der.decodeOid(der.expectTag(der.children(der.expectTag(spc[0], 0x30, 'SpcAttributeTypeAndOptionalValue'))[0], 0x06, 'type'));
  if (attributeType !== expectedType) throw new VerificationError(`the signature is for a different file type (SpcAttributeType ${attributeType})`);
  const digestInfo = der.children(der.expectTag(spc[1], 0x30, 'DigestInfo'));
  const hashAlgorithm = hashNameForOid(parseAlgorithmIdentifier(digestInfo[0]).oid);
  const embeddedHash = der.octets(digestInfo[1], 'DigestInfo.digest');
  const digest = computeDigest(hashAlgorithm);
  if (!der.bytesEqual(embeddedHash, digest)) {
    throw new VerificationError(`Authenticode ${hashAlgorithm} digest mismatch — the signature does not match the file contents`);
  }

  const signerInfo = sd.signerInfos[0];
  if (!signerInfo || sd.signerInfos.length !== 1) throw new VerificationError(`expected exactly one signer, found ${sd.signerInfos.length}`);
  const signer = findSignerCertificate(sd, signerInfo);
  if (!signer) throw new VerificationError('the signer certificate is not embedded in the signature');
  try {
    verifySignerInfo(sd, signerInfo, signer);
  } catch (err) {
    if (err instanceof CmsError) throw new VerificationError(`invalid signature: ${err.message}`);
    throw err;
  }

  const signingTimeAttr = findAttribute(signerInfo.signedAttributes, OID_SIGNING_TIME);
  const opus = findAttribute(signerInfo.signedAttributes, OID_SPC_SP_OPUS_INFO);
  const { description, url } = opus ? parseOpusInfo(opus) : { description: null, url: null };

  let timestamp: TimestampToken | null = null;
  const tokenAttr = findAttribute(signerInfo.unsignedAttributes, OID_RFC3161_COUNTER_SIGN);
  if (tokenAttr) {
    try {
      timestamp = verifyTimestampToken(tokenAttr.raw, { imprint: createHash('sha256').update(signerInfo.signature).digest(), nonce: null });
    } catch (err) {
      if (err instanceof TimestampError) throw new VerificationError(`invalid timestamp: ${err.message}`);
      throw err;
    }
  }

  return {
    kind,
    hashAlgorithm,
    digest,
    signer,
    certificates: sd.certificates,
    signingTime: signingTimeAttr ? der.decodeTime(signingTimeAttr) : null,
    description,
    url,
    timestamp,
  };
}

/** Verify the Authenticode signature of a PE image; throws a VerificationError on any defect. */
export function verifySignedPe(pe: Uint8Array): VerificationResult {
  let entries;
  try {
    entries = readCertificateTable(pe);
  } catch (err) {
    throw new VerificationError(`cannot read the certificate table: ${message(err)}`);
  }
  const entry = entries.find((e) => e.type === WIN_CERT_TYPE_PKCS_SIGNED_DATA);
  if (!entry) throw new VerificationError('the file carries no Authenticode signature');
  return verifySignedData('pe', entry.data, OID_SPC_PE_IMAGE_DATA, (algorithm) => authenticodeHash(pe, algorithm));
}

/** Verify the Authenticode signature of an MSI package; throws a VerificationError on any defect. */
export function verifySignedMsi(bytes: Uint8Array): VerificationResult {
  let file;
  try {
    file = parseCompoundFile(bytes);
  } catch (err) {
    throw new VerificationError(`cannot read the package: ${message(err)}`);
  }
  const signature = readMsiSignature(file);
  if (!signature) throw new VerificationError('the file carries no Authenticode signature');
  return verifySignedData('msi', signature.pkcs7, OID_SPC_SIPINFO, (algorithm) => {
    if (signature.extended && !der.bytesEqual(msiPrehash(file, algorithm), signature.extended)) {
      throw new VerificationError('the MsiDigitalSignatureEx stream does not match the package metadata (names, CLSIDs, sizes or times changed)');
    }
    // The MsiDigitalSignatureEx stream, if any, is part of the tree and is hashed in place.
    return msiDigest(file, algorithm);
  });
}

/** Verify whichever kind of signed file `bytes` is. */
export function verifySignedFile(bytes: Uint8Array): VerificationResult {
  return detectImageKind(bytes) === 'pe' ? verifySignedPe(bytes) : verifySignedMsi(bytes);
}
