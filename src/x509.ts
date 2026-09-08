/**
 * X.509 helpers on top of node:crypto's X509Certificate: the DER pieces a
 * PKCS#7 SignerInfo needs (issuer + serial exactly as encoded), PEM handling,
 * and the two extensions we look at (subjectKeyIdentifier, extendedKeyUsage).
 */
import { X509Certificate } from 'node:crypto';
import { DerError, asBuffer, children, decodeOid, expectTag, readExact, seq } from './der.ts';

export const OID_EXT_SUBJECT_KEY_IDENTIFIER = '2.5.29.14';
export const OID_EXT_EXTENDED_KEY_USAGE = '2.5.29.37';
export const OID_EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';
export const OID_EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';

export interface CertificateInfo {
  readonly der: Buffer;
  readonly x509: X509Certificate;
  /** The serialNumber INTEGER, exactly as encoded in the certificate. */
  readonly serialNumber: Buffer;
  /** The issuer Name, exactly as encoded in the certificate. */
  readonly issuer: Buffer;
  readonly subject: Buffer;
  /** PKCS#7 `IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber INTEGER }`. */
  readonly issuerAndSerialNumber: Buffer;
  readonly subjectPublicKeyInfo: Buffer;
  readonly subjectKeyIdentifier: Buffer | null;
  readonly extendedKeyUsage: readonly string[] | null;
}

/** Parse a DER certificate; throws on anything OpenSSL or our DER walker rejects. */
export function parseCertificate(der: Uint8Array): CertificateInfo {
  const raw = Buffer.from(asBuffer(der));
  const cert = expectTag(readExact(raw), 0x30, 'Certificate');
  const tbs = expectTag(children(cert)[0], 0x30, 'TBSCertificate');
  const fields = children(tbs);
  const i = fields[0]?.tag === 0xa0 ? 1 : 0; // version [0] EXPLICIT is optional
  const serialNumber = expectTag(fields[i], 0x02, 'serialNumber');
  const issuer = expectTag(fields[i + 2], 0x30, 'issuer');
  const subject = expectTag(fields[i + 4], 0x30, 'subject');
  const spki = expectTag(fields[i + 5], 0x30, 'subjectPublicKeyInfo');

  let subjectKeyIdentifier: Buffer | null = null;
  let extendedKeyUsage: string[] | null = null;
  const extensions = fields.slice(i + 6).find((t) => t.tag === 0xa3);
  if (extensions) {
    for (const ext of children(expectTag(children(extensions)[0], 0x30, 'extensions'))) {
      const extFields = children(ext);
      const id = decodeOid(expectTag(extFields[0], 0x06, 'extnID'));
      const value = extFields.find((f) => f.tag === 0x04);
      if (!value) throw new DerError('certificate extension without extnValue');
      if (id === OID_EXT_SUBJECT_KEY_IDENTIFIER) {
        subjectKeyIdentifier = Buffer.from(expectTag(readExact(value.content), 0x04, 'SubjectKeyIdentifier').content);
      } else if (id === OID_EXT_EXTENDED_KEY_USAGE) {
        extendedKeyUsage = children(expectTag(readExact(value.content), 0x30, 'ExtKeyUsageSyntax')).map((o) => decodeOid(o));
      }
    }
  }

  return {
    der: raw,
    x509: new X509Certificate(raw),
    serialNumber: Buffer.from(serialNumber.raw),
    issuer: Buffer.from(issuer.raw),
    subject: Buffer.from(subject.raw),
    issuerAndSerialNumber: seq(issuer.raw, serialNumber.raw),
    subjectPublicKeyInfo: Buffer.from(spki.raw),
    subjectKeyIdentifier,
    extendedKeyUsage,
  };
}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

/** Every `-----BEGIN <label>-----` block in `text`, decoded to DER. */
export function pemBlocks(text: string, label = 'CERTIFICATE'): Buffer[] {
  const out: Buffer[] = [];
  for (const m of text.matchAll(PEM_BLOCK)) {
    if (m[1] !== label) continue;
    const b64 = (m[2] ?? '').replace(/[^A-Za-z0-9+/=]/g, '');
    const der = Buffer.from(b64, 'base64');
    if (der.length === 0) throw new DerError(`empty ${label} PEM block`);
    out.push(der);
  }
  return out;
}

export function looksLikePem(bytes: Uint8Array): boolean {
  return asBuffer(bytes).subarray(0, 64).toString('latin1').trimStart().startsWith('-----BEGIN');
}

/** Decode the first CERTIFICATE block of a PEM, or pass DER through untouched. */
export function pemToDer(bytes: Uint8Array): Buffer {
  if (!looksLikePem(bytes)) return Buffer.from(asBuffer(bytes));
  const blocks = pemBlocks(asBuffer(bytes).toString('latin1'));
  const first = blocks[0];
  if (!first) throw new DerError('no CERTIFICATE block found in the PEM data');
  return first;
}

/** `CN=…, O=…, C=…` on one line (node renders names one attribute per line). */
export function oneLineName(name: string): string {
  return name.split('\n').filter(Boolean).join(', ');
}

export function isSelfSigned(cert: CertificateInfo): boolean {
  return cert.x509.checkIssued(cert.x509) && cert.x509.verify(cert.x509.publicKey);
}

/** True when `issuer` issued `cert` (name chaining + signature check). */
export function issuedBy(cert: CertificateInfo, issuer: CertificateInfo): boolean {
  return cert.x509.checkIssued(issuer.x509) && cert.x509.verify(issuer.x509.publicKey);
}

/**
 * Order `candidates` into the chain above `leaf`: each element issued the one
 * before it, stopping at a self-signed certificate or when no candidate issued
 * the current one. A self-signed root among the candidates is embedded too —
 * harmless, and what `signtool /ac` does — but only the built-in Certum
 * intermediate and certificates the user supplied are ever candidates.
 * Returns the certificates to embed after the leaf and the subject of the
 * first issuer that could not be found (if any).
 */
export function buildChain(leaf: CertificateInfo, candidates: readonly CertificateInfo[]): { chain: CertificateInfo[]; missingIssuer: string | null } {
  const chain: CertificateInfo[] = [];
  let current = leaf;
  const used = new Set<string>();
  for (;;) {
    if (isSelfSigned(current)) return { chain, missingIssuer: null };
    const issuer = candidates.find((c) => !used.has(c.x509.fingerprint256) && issuedBy(current, c));
    if (!issuer) return { chain, missingIssuer: oneLineName(current.x509.issuer) };
    used.add(issuer.x509.fingerprint256);
    chain.push(issuer);
    current = issuer;
  }
}
