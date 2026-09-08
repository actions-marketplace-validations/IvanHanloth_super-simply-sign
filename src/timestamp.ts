/**
 * RFC 3161 timestamping: hash the signature, ask the TSA to countersign it,
 * and return the TimeStampToken to embed as an unauthenticated attribute.
 *
 * The reply is trusted only after it is checked: it must be a CMS SignedData
 * carrying a TSTInfo whose messageImprint is *our* imprint and whose nonce is
 * the one we sent, and its signature must verify with the TSA certificate
 * included in the token — which must be a time-stamping certificate. A token
 * that fails any of this is not embedded: better no timestamp than a
 * signature that stops validating the moment the certificate expires.
 */
import { createHash, randomBytes } from 'node:crypto';
import * as der from './der.ts';
import {
  OID_SHA256,
  findSignerCertificate,
  hashNameForOid,
  parseAlgorithmIdentifier,
  parseSignedData,
  verifySignerInfo,
  CmsError,
} from './cms.ts';
import { bodySnippet, type HttpClient } from './http.ts';
import type { Logger } from './log.ts';
import { OID_EKU_TIME_STAMPING, oneLineName, type CertificateInfo } from './x509.ts';

export class TimestampError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TimestampError';
  }
}

export const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';

export interface TimestampToken {
  /** The DER TimeStampToken (a ContentInfo), ready to embed. */
  readonly token: Buffer;
  readonly genTime: Date;
  readonly serialNumber: string;
  readonly policy: string;
  readonly tsa: CertificateInfo;
}

export interface ExpectedTimestamp {
  readonly imprint: Uint8Array;
  readonly nonce: Uint8Array | null;
}

/** `TimeStampReq { version 1, messageImprint { sha256, imprint }, nonce?, certReq TRUE }`. */
export function buildTimeStampReq(imprint: Uint8Array, nonce: Uint8Array | null): Buffer {
  const parts = [der.integer(1), der.seq(der.seq(der.oid(OID_SHA256), der.nul()), der.octetString(imprint))];
  if (nonce) parts.push(der.integer(nonce));
  parts.push(der.boolTrue());
  return der.seq(...parts);
}

const PKI_STATUS: Readonly<Record<number, string>> = {
  0: 'granted',
  1: 'grantedWithMods',
  2: 'rejection',
  3: 'waiting',
  4: 'revocationWarning',
  5: 'revocationNotification',
};

/** Parse a `TimeStampResp`, check its status and validate the token it carries. */
export function parseTimeStampResp(bytes: Uint8Array, expected: ExpectedTimestamp): TimestampToken {
  let top: der.Tlv[];
  try {
    top = der.children(der.expectTag(der.readExact(bytes), 0x30, 'TimeStampResp'));
  } catch (err) {
    throw new TimestampError(`the TSA reply is not a TimeStampResp: ${(err as Error).message}`);
  }
  const statusInfo = der.children(der.expectTag(top[0], 0x30, 'PKIStatusInfo'));
  const status = Number(der.integerValue(der.expectTag(statusInfo[0], 0x02, 'PKIStatus')));
  if (status !== 0 && status !== 1) {
    const text = statusInfo[1]?.tag === 0x30 ? der.children(statusInfo[1]).map((s) => s.content.toString('utf8')).join('; ') : '';
    throw new TimestampError(`the TSA rejected the request (status ${PKI_STATUS[status] ?? status}${text ? `: ${text}` : ''})`);
  }
  const token = top[1];
  if (!token) throw new TimestampError('the TSA granted the request but returned no timeStampToken');
  return verifyTimestampToken(token.raw, expected);
}

/** Validate a TimeStampToken structurally and cryptographically against what we asked for. */
export function verifyTimestampToken(token: Uint8Array, expected: ExpectedTimestamp): TimestampToken {
  let sd;
  try {
    sd = parseSignedData(token);
  } catch (err) {
    throw new TimestampError(`malformed timeStampToken: ${(err as Error).message}`);
  }
  if (sd.eContentType !== OID_TST_INFO) throw new TimestampError('the timeStampToken does not carry a TSTInfo');
  if (!sd.eContent) throw new TimestampError('the timeStampToken has no content');

  const tst = der.children(der.expectTag(der.readExact(der.octets(sd.eContent, 'TSTInfo')), 0x30, 'TSTInfo'));
  const version = Number(der.integerValue(der.expectTag(tst[0], 0x02, 'TSTInfo.version')));
  if (version !== 1) throw new TimestampError(`unsupported TSTInfo version ${version}`);
  const policy = der.decodeOid(der.expectTag(tst[1], 0x06, 'TSTInfo.policy'));
  const imprint = der.children(der.expectTag(tst[2], 0x30, 'messageImprint'));
  const imprintAlgorithm = parseAlgorithmIdentifier(imprint[0]).oid;
  if (imprintAlgorithm !== OID_SHA256) throw new TimestampError(`the TSA hashed with ${imprintAlgorithm}, not SHA-256`);
  if (!der.bytesEqual(der.octets(imprint[1], 'hashedMessage'), expected.imprint)) {
    throw new TimestampError('the timestamp covers a different message than our signature');
  }
  const serialNumber = der.integerMagnitude(der.expectTag(tst[3], 0x02, 'TSTInfo.serialNumber')).toString('hex');
  const genTime = der.decodeTime(der.expectTag(tst[4], 0x18, 'TSTInfo.genTime'));
  const nonce = tst.slice(5).find((t) => t.tag === 0x02);
  if (expected.nonce) {
    if (!nonce) throw new TimestampError('the TSA did not echo our nonce');
    if (!der.bytesEqual(der.integerMagnitude(nonce), der.integerMagnitude(der.readExact(der.integer(expected.nonce))))) {
      throw new TimestampError('the TSA echoed a different nonce');
    }
  }

  const signerInfo = sd.signerInfos[0];
  if (!signerInfo || sd.signerInfos.length !== 1) throw new TimestampError('the timeStampToken must have exactly one signer');
  const tsa = findSignerCertificate(sd, signerInfo);
  if (!tsa) throw new TimestampError('the TSA did not include its signing certificate in the token');
  try {
    verifySignerInfo(sd, signerInfo, tsa);
    hashNameForOid(signerInfo.digestAlgorithm);
  } catch (err) {
    if (err instanceof CmsError) throw new TimestampError(`the timestamp signature is invalid: ${err.message}`);
    throw err;
  }
  if (!tsa.extendedKeyUsage?.includes(OID_EKU_TIME_STAMPING)) {
    throw new TimestampError(`the token was signed by "${oneLineName(tsa.x509.subject)}", which is not a time-stamping certificate`);
  }
  return { token: Buffer.from(token), genTime, serialNumber, policy, tsa };
}

/** Request a timestamp over `signature` from the RFC 3161 TSA at `url`. */
export async function fetchTimestamp(http: HttpClient, url: string, signature: Uint8Array, log: Logger): Promise<TimestampToken> {
  const imprint = createHash('sha256').update(signature).digest();
  const nonce = randomBytes(8);
  const response = await http.fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/timestamp-query', accept: 'application/timestamp-reply' },
    body: buildTimeStampReq(imprint, nonce),
  });
  if (response.status !== 200) throw new TimestampError(`the timestamp authority returned HTTP ${response.status}: ${bodySnippet(response.body)}`);
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/timestamp-reply')) log.warning(`the timestamp authority replied with content-type "${contentType}"`);
  return parseTimeStampResp(response.body, { imprint, nonce });
}
