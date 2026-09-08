/**
 * PKCS#7 / CMS SignedData parsing and SignerInfo verification, shared by the
 * RFC 3161 token checks and the post-signing self-verification of a PE.
 * Parsing only — building the Authenticode SignedData lives in
 * `authenticode.ts`.
 */
import { constants, createHash, verify as cryptoVerify, type KeyObject } from 'node:crypto';
import { bytesEqual, children, decodeOid, expectTag, integerValue, octets, readExact, tlv, type Tlv } from './der.ts';
import { parseCertificate, type CertificateInfo } from './x509.ts';

export class CmsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CmsError';
  }
}

export const OID_PKCS7_SIGNED_DATA = '1.2.840.113549.1.7.2';
export const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';
export const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
export const OID_SIGNING_TIME = '1.2.840.113549.1.9.5';

export const OID_SHA1 = '1.3.14.3.2.26';
export const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
export const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
export const OID_SHA512 = '2.16.840.1.101.3.4.2.3';

export const OID_RSA_ENCRYPTION = '1.2.840.113549.1.1.1';
export const OID_SHA1_WITH_RSA = '1.2.840.113549.1.1.5';
export const OID_RSASSA_PSS = '1.2.840.113549.1.1.10';
export const OID_SHA256_WITH_RSA = '1.2.840.113549.1.1.11';
export const OID_SHA384_WITH_RSA = '1.2.840.113549.1.1.12';
export const OID_SHA512_WITH_RSA = '1.2.840.113549.1.1.13';
export const OID_ECDSA_SHA1 = '1.2.840.10045.4.1';
export const OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2';
export const OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3';
export const OID_ECDSA_SHA512 = '1.2.840.10045.4.3.4';

const HASH_NAMES: Readonly<Record<string, string>> = {
  [OID_SHA1]: 'sha1',
  [OID_SHA256]: 'sha256',
  [OID_SHA384]: 'sha384',
  [OID_SHA512]: 'sha512',
};

export function hashNameForOid(oid: string): string {
  const name = HASH_NAMES[oid];
  if (!name) throw new CmsError(`unsupported digest algorithm ${oid}`);
  return name;
}

export interface AlgorithmIdentifier {
  readonly oid: string;
  readonly params: Tlv | null;
}

export function parseAlgorithmIdentifier(t: Tlv | undefined): AlgorithmIdentifier {
  const [algorithm, params] = children(expectTag(t, 0x30, 'AlgorithmIdentifier'));
  return { oid: decodeOid(expectTag(algorithm, 0x06, 'algorithm')), params: params ?? null };
}

export interface Attribute {
  readonly oid: string;
  readonly values: readonly Tlv[];
}

/** The attributes inside a (possibly implicitly tagged) SET OF Attribute. */
export function parseAttributes(container: Tlv): Attribute[] {
  return children(container).map((attr) => {
    const [type, values] = children(expectTag(attr, 0x30, 'Attribute'));
    return { oid: decodeOid(expectTag(type, 0x06, 'attrType')), values: children(expectTag(values, 0x31, 'attrValues')) };
  });
}

/** The first value of the attribute with `oid`, if present. */
export function findAttribute(attributes: readonly Attribute[], oid: string): Tlv | null {
  return attributes.find((a) => a.oid === oid)?.values[0] ?? null;
}

export type SignerIdentifier =
  | { readonly kind: 'issuerAndSerialNumber'; readonly value: Buffer }
  | { readonly kind: 'subjectKeyIdentifier'; readonly value: Buffer };

export interface SignerInfo {
  readonly version: number;
  readonly sid: SignerIdentifier;
  readonly digestAlgorithm: string;
  /** The signed attributes re-tagged as a SET OF — the bytes the signature covers. */
  readonly signedAttrsDer: Buffer | null;
  readonly signedAttributes: readonly Attribute[];
  readonly signatureAlgorithm: AlgorithmIdentifier;
  readonly signature: Buffer;
  readonly unsignedAttributes: readonly Attribute[];
}

export interface SignedData {
  readonly version: number;
  readonly digestAlgorithms: readonly string[];
  readonly eContentType: string;
  /** The encapsulated content TLV (an OCTET STRING for CMS, a SEQUENCE for Authenticode). */
  readonly eContent: Tlv | null;
  readonly certificates: readonly CertificateInfo[];
  readonly signerInfos: readonly SignerInfo[];
}

function parseSignerInfo(t: Tlv): SignerInfo {
  const f = children(expectTag(t, 0x30, 'SignerInfo'));
  const version = Number(integerValue(expectTag(f[0], 0x02, 'SignerInfo.version')));
  const sidTlv = f[1];
  if (!sidTlv) throw new CmsError('SignerInfo has no SignerIdentifier');
  let sid: SignerIdentifier;
  if (sidTlv.tag === 0x30) sid = { kind: 'issuerAndSerialNumber', value: Buffer.from(sidTlv.raw) };
  else if (sidTlv.tag === 0x80) sid = { kind: 'subjectKeyIdentifier', value: Buffer.from(sidTlv.content) };
  else throw new CmsError('unsupported SignerIdentifier');
  const digestAlgorithm = parseAlgorithmIdentifier(f[2]).oid;
  let i = 3;
  let signedAttrsDer: Buffer | null = null;
  let signedAttributes: Attribute[] = [];
  const maybeSigned = f[i];
  if (maybeSigned && maybeSigned.tag === 0xa0) {
    signedAttrsDer = tlv(0x31, maybeSigned.content);
    signedAttributes = parseAttributes(maybeSigned);
    i++;
  }
  const signatureAlgorithm = parseAlgorithmIdentifier(f[i++]);
  const signature = Buffer.from(octets(f[i++], 'SignerInfo.signature'));
  const maybeUnsigned = f[i];
  const unsignedAttributes = maybeUnsigned && maybeUnsigned.tag === 0xa1 ? parseAttributes(maybeUnsigned) : [];
  return { version, sid, digestAlgorithm, signedAttrsDer, signedAttributes, signatureAlgorithm, signature, unsignedAttributes };
}

/** Parse a `ContentInfo { signedData }` (a PKCS#7 blob or an RFC 3161 TimeStampToken). */
export function parseSignedData(contentInfo: Uint8Array): SignedData {
  const ci = expectTag(readExact(contentInfo), 0x30, 'ContentInfo');
  const [contentType, wrapper] = children(ci);
  if (decodeOid(expectTag(contentType, 0x06, 'ContentInfo.contentType')) !== OID_PKCS7_SIGNED_DATA) throw new CmsError('not a PKCS#7 SignedData');
  const sd = expectTag(children(expectTag(wrapper, 0xa0, 'ContentInfo.content'))[0], 0x30, 'SignedData');
  const f = children(sd);
  const version = Number(integerValue(expectTag(f[0], 0x02, 'SignedData.version')));
  const digestAlgorithms = children(expectTag(f[1], 0x31, 'digestAlgorithms')).map((a) => parseAlgorithmIdentifier(a).oid);
  const eci = children(expectTag(f[2], 0x30, 'encapContentInfo'));
  const eContentType = decodeOid(expectTag(eci[0], 0x06, 'eContentType'));
  const eContentWrapper = eci[1];
  const eContent = eContentWrapper ? (children(expectTag(eContentWrapper, 0xa0, 'eContent'))[0] ?? null) : null;
  let i = 3;
  const certificates: CertificateInfo[] = [];
  const maybeCerts = f[i];
  if (maybeCerts && maybeCerts.tag === 0xa0) {
    for (const c of children(maybeCerts)) if (c.tag === 0x30) certificates.push(parseCertificate(c.raw));
    i++;
  }
  const maybeCrls = f[i];
  if (maybeCrls && maybeCrls.tag === 0xa1) i++;
  const signerInfos = children(expectTag(f[i], 0x31, 'signerInfos')).map(parseSignerInfo);
  return { version, digestAlgorithms, eContentType, eContent, certificates, signerInfos };
}

export function findSignerCertificate(sd: SignedData, si: SignerInfo): CertificateInfo | null {
  const sid = si.sid;
  if (sid.kind === 'issuerAndSerialNumber') return sd.certificates.find((c) => bytesEqual(c.issuerAndSerialNumber, sid.value)) ?? null;
  return sd.certificates.find((c) => c.subjectKeyIdentifier !== null && bytesEqual(c.subjectKeyIdentifier, sid.value)) ?? null;
}

/** Verify `signature` over `data` with the key, for the signature schemes CMS producers use. */
export function verifySignature(hashName: string, data: Uint8Array, algorithm: AlgorithmIdentifier, signature: Uint8Array, key: KeyObject): boolean {
  try {
    switch (algorithm.oid) {
      case OID_RSA_ENCRYPTION:
      case OID_SHA1_WITH_RSA:
      case OID_SHA256_WITH_RSA:
      case OID_SHA384_WITH_RSA:
      case OID_SHA512_WITH_RSA:
        return key.asymmetricKeyType === 'rsa' && cryptoVerify(hashName, data, key, signature);
      case OID_RSASSA_PSS:
        return (
          (key.asymmetricKeyType === 'rsa' || key.asymmetricKeyType === 'rsa-pss') &&
          cryptoVerify(hashName, data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_AUTO }, signature)
        );
      case OID_ECDSA_SHA1:
      case OID_ECDSA_SHA256:
      case OID_ECDSA_SHA384:
      case OID_ECDSA_SHA512:
        return key.asymmetricKeyType === 'ec' && cryptoVerify(hashName, data, { key, dsaEncoding: 'der' }, signature);
      default:
        throw new CmsError(`unsupported signature algorithm ${algorithm.oid}`);
    }
  } catch (err) {
    if (err instanceof CmsError) throw err;
    return false;
  }
}

/**
 * Check a SignerInfo against the encapsulated content and the signer's
 * certificate: contentType and messageDigest attributes, then the signature
 * over the signed attributes. Throws a CmsError describing the first failure.
 */
export function verifySignerInfo(sd: SignedData, si: SignerInfo, cert: CertificateInfo): { hashName: string } {
  if (!si.signedAttrsDer) throw new CmsError('SignerInfo has no signed attributes');
  if (!sd.eContent) throw new CmsError('SignedData has no encapsulated content');
  const hashName = hashNameForOid(si.digestAlgorithm);
  const contentType = findAttribute(si.signedAttributes, OID_CONTENT_TYPE);
  if (!contentType || decodeOid(contentType) !== sd.eContentType) throw new CmsError('the contentType attribute does not match the encapsulated content');
  const messageDigest = findAttribute(si.signedAttributes, OID_MESSAGE_DIGEST);
  const expected = createHash(hashName).update(sd.eContent.content).digest();
  if (!messageDigest || !bytesEqual(octets(messageDigest, 'messageDigest'), expected)) throw new CmsError('the messageDigest attribute does not match the content');
  if (!verifySignature(hashName, si.signedAttrsDer, si.signatureAlgorithm, si.signature, cert.x509.publicKey)) {
    throw new CmsError('the signature does not verify with the signer certificate');
  }
  return { hashName };
}
