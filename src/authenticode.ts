/**
 * Step 3 and 5 — the local Authenticode work:
 *
 *  - `prepare`  : hash the PE, build the SpcIndirectDataContent and the signed
 *    attributes, and return the SHA-256 the cloud HSM must sign (over the
 *    DER SET of signed attributes — that is what an RSA PKCS#1 v1.5 signature
 *    with SHA-256 covers).
 *  - `finalize` : wrap [signed attributes + signature + certificate chain +
 *    RFC 3161 token] into a PKCS#7 SignedData and splice it into the PE.
 */
import { createHash } from 'node:crypto';
import { OID_CONTENT_TYPE, OID_MESSAGE_DIGEST, OID_PKCS7_SIGNED_DATA, OID_RSA_ENCRYPTION, OID_SHA256, OID_SIGNING_TIME } from './cms.ts';
import * as der from './der.ts';
import { authenticodeHash, embedSignature } from './pe.ts';
import type { CertificateInfo } from './x509.ts';

export const OID_SPC_INDIRECT_DATA = '1.3.6.1.4.1.311.2.1.4';
export const OID_SPC_STATEMENT_TYPE = '1.3.6.1.4.1.311.2.1.11';
export const OID_SPC_SP_OPUS_INFO = '1.3.6.1.4.1.311.2.1.12';
export const OID_SPC_PE_IMAGE_DATA = '1.3.6.1.4.1.311.2.1.15';
export const OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE = '1.3.6.1.4.1.311.2.1.21';
/** szOID_RFC3161_counterSign — the unauthenticated attribute carrying the TimeStampToken. */
export const OID_RFC3161_COUNTER_SIGN = '1.3.6.1.4.1.311.3.3.1';

const sha256 = (data: Uint8Array): Buffer => createHash('sha256').update(data).digest();
const attribute = (oid: string, value: Uint8Array): Buffer => der.seq(der.oid(oid), der.set(value));

/**
 * `SpcAttributeTypeAndOptionalValue { SPC_PE_IMAGE_DATA, SpcPeImageData }` —
 * identical for every PE signature: flags = includeResources, and the
 * historical `<<<Obsolete>>>` file moniker as a unicode SpcString.
 */
export function spcPeImageData(): Buffer {
  const obsolete = der.ctxPrim(0, der.utf16be('<<<Obsolete>>>')); // SpcString.unicode [0] IMPLICIT BMPString
  const file = der.ctx(0, der.ctx(2, obsolete)); // SpcPeImageData.file [0] EXPLICIT SpcLink.file [2] EXPLICIT SpcString
  const flags = der.bitString(Buffer.from([0x80]), 7); // SpcPeImageFlags { includeResources }
  return der.seq(der.oid(OID_SPC_PE_IMAGE_DATA), der.seq(flags, file));
}

export function digestInfo(hashOid: string, hash: Uint8Array): Buffer {
  return der.seq(der.seq(der.oid(hashOid), der.nul()), der.octetString(hash));
}

/** `SpcIndirectDataContent { data SpcAttributeTypeAndOptionalValue, messageDigest DigestInfo }`. */
export function spcIndirectDataContent(peHash: Uint8Array): { der: Buffer; content: Buffer } {
  const content = der.concat(spcPeImageData(), digestInfo(OID_SHA256, peHash));
  return { der: der.tlv(0x30, content), content };
}

/**
 * `SpcSpOpusInfo { programName [0] EXPLICIT SpcString, moreInfo [1] EXPLICIT SpcLink }`.
 * The program name is always a unicode SpcString (what signtool emits); the
 * URL is an SpcLink.url and must therefore be ASCII.
 */
export function spcSpOpusInfo(description: string | undefined, url: string | undefined): Buffer {
  const parts: Buffer[] = [];
  if (description) parts.push(der.ctx(0, der.ctxPrim(0, der.utf16be(description))));
  if (url) {
    if (!/^[\x21-\x7e]+$/.test(url)) throw new der.DerError('the signature URL must be printable ASCII');
    parts.push(der.ctx(1, der.ctxPrim(0, Buffer.from(url, 'latin1'))));
  }
  return der.seq(...parts);
}

export interface PrepareOptions {
  readonly description?: string | undefined;
  readonly url?: string | undefined;
  readonly signingTime: Date;
}

export interface PreparedSignature {
  /** Authenticode SHA-256 of the image. */
  readonly peHash: Buffer;
  /** The SpcIndirectDataContent SEQUENCE. */
  readonly spcIndirectData: Buffer;
  /** The signed attributes as a DER SET OF — hashed for signing and embedded as [0] IMPLICIT. */
  readonly signedAttrsSet: Buffer;
  /** SHA-256 over `signedAttrsSet`: the digest the cloud HSM signs. */
  readonly toBeSigned: Buffer;
}

/** Build everything that can be built before the cloud signature exists. */
export function prepare(pe: Uint8Array, options: PrepareOptions): PreparedSignature {
  const peHash = authenticodeHash(pe, 'sha256');
  const spc = spcIndirectDataContent(peHash);
  // Authenticode quirk: messageDigest is the hash of the SEQUENCE *content*.
  const messageDigest = sha256(spc.content);
  const attributes = [
    attribute(OID_CONTENT_TYPE, der.oid(OID_SPC_INDIRECT_DATA)),
    attribute(OID_SIGNING_TIME, der.time(options.signingTime)),
    attribute(OID_SPC_STATEMENT_TYPE, der.seq(der.oid(OID_SPC_INDIVIDUAL_SP_KEY_PURPOSE))),
    attribute(OID_MESSAGE_DIGEST, der.octetString(messageDigest)),
  ];
  if (options.description || options.url) attributes.push(attribute(OID_SPC_SP_OPUS_INFO, spcSpOpusInfo(options.description, options.url)));
  const signedAttrsSet = der.setOf(attributes);
  return { peHash, spcIndirectData: spc.der, signedAttrsSet, toBeSigned: sha256(signedAttrsSet) };
}

/** The PKCS#7 `ContentInfo { signedData }` blob for a prepared signature. */
export function buildSignedData(
  prepared: PreparedSignature,
  signature: Uint8Array,
  signer: CertificateInfo,
  chain: readonly CertificateInfo[],
  timestampToken: Uint8Array | null,
): Buffer {
  const sha256AlgId = der.seq(der.oid(OID_SHA256), der.nul());
  const rsaAlgId = der.seq(der.oid(OID_RSA_ENCRYPTION), der.nul());

  // authenticatedAttributes [0] IMPLICIT — the same SET content that was hashed.
  const signedAttrsImplicit = der.ctx(0, der.readExact(prepared.signedAttrsSet).content);
  const signerInfoParts = [der.integer(1), signer.issuerAndSerialNumber, sha256AlgId, signedAttrsImplicit, rsaAlgId, der.octetString(signature)];
  // unauthenticatedAttributes [1] IMPLICIT SET OF Attribute — carries the RFC 3161 token.
  if (timestampToken) signerInfoParts.push(der.ctx(1, attribute(OID_RFC3161_COUNTER_SIGN, timestampToken)));
  const signerInfo = der.seq(...signerInfoParts);

  const contentInfo = der.seq(der.oid(OID_SPC_INDIRECT_DATA), der.ctx(0, prepared.spcIndirectData));
  const certificates = der.ctx(0, der.concat(signer.der, ...chain.map((c) => c.der)));
  const signedData = der.seq(der.integer(1), der.set(sha256AlgId), contentInfo, certificates, der.set(signerInfo));
  return der.seq(der.oid(OID_PKCS7_SIGNED_DATA), der.ctx(0, signedData));
}

/** Assemble the PKCS#7 for `prepared` and splice it into `pe`; returns the signed image. */
export function finalize(
  pe: Uint8Array,
  prepared: PreparedSignature,
  signature: Uint8Array,
  signer: CertificateInfo,
  chain: readonly CertificateInfo[],
  timestampToken: Uint8Array | null,
): Buffer {
  return embedSignature(pe, buildSignedData(prepared, signature, signer, chain, timestampToken));
}
