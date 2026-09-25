/**
 * The pipeline: one authenticated cloud session (login → card → certificate)
 * that signs any number of files — PE images and MSI packages — each as
 *
 *   digest → signed attributes → cloud signature → check it against the
 *   certificate → RFC 3161 timestamp (checked) → assemble PKCS#7 → embed →
 *   self-verify.
 *
 * Nothing here touches the disk and no token is ever persisted: the session
 * lives exactly as long as the process that logged in.
 */
import { verify as cryptoVerify } from 'node:crypto';
import { CERTUM_OAUTH, login, type OAuthConfig } from './auth.ts';
import { buildSignedData, prepare, prepareIndirectData, type PreparedSignature } from './authenticode.ts';
import { CERTUM_CODE_SIGNING_2021_CA_DER } from './certs/certum-code-signing-2021-ca.ts';
import { parseCompoundFile, writeCompoundFile } from './cfb.ts';
import { asBuffer } from './der.ts';
import { HttpClient } from './http.ts';
import { detectImageKind, type ImageKind } from './image.ts';
import { silentLogger, type Logger } from './log.ts';
import { embedMsiSignature, isMsiSigned, msiDigest, msiPrehash, spcSipInfo, stripMsiSignature, withExtendedSignature } from './msi.ts';
import { embedSignature, parsePeLayout, stripSignature } from './pe.ts';
import { fetchCard, requestSignature, type CloudCard, type ScsClient } from './scs.ts';
import { fetchTimestamp, type TimestampToken } from './timestamp.ts';
import { verifySignedMsi, verifySignedPe, type VerificationResult } from './verify.ts';
import { OID_EKU_CODE_SIGNING, buildChain, oneLineName, parseCertificate, pemToDer, type CertificateInfo } from './x509.ts';

export const VERSION = '1.0.0';
export const USER_AGENT = `super-simply-sign/${VERSION}`;

export class SignError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SignError';
  }
}

export interface SigningEndpoints {
  readonly apiBase: string;
  readonly oauth: OAuthConfig;
}

/** Production endpoints. Tests inject their own; the action never lets the environment override these. */
export const CERTUM_ENDPOINTS: SigningEndpoints = {
  apiBase: 'https://cloudsign.webnotarius.pl',
  oauth: CERTUM_OAUTH,
};

const CERTUM_INTERMEDIATE = parseCertificate(CERTUM_CODE_SIGNING_2021_CA_DER);

export interface SessionOptions {
  readonly email: string;
  /** The current 6-digit one-time code. */
  readonly otpCode: string;
  readonly endpoints?: SigningEndpoints;
  readonly cardSerial?: string | undefined;
  readonly userAgent?: string;
  readonly timeoutMs?: number;
  readonly log?: Logger;
}

function checkCertificate(cert: CertificateInfo, log: Logger): void {
  const now = Date.now();
  const notAfter = cert.x509.validToDate.getTime();
  const notBefore = cert.x509.validFromDate.getTime();
  if (notAfter < now) throw new SignError(`the signing certificate expired on ${cert.x509.validToDate.toISOString()}`);
  if (notBefore > now) throw new SignError(`the signing certificate is not valid before ${cert.x509.validFromDate.toISOString()}`);
  if (notAfter - now < 30 * 86_400_000) log.warning(`the signing certificate expires on ${cert.x509.validToDate.toISOString()}`);
  if (cert.extendedKeyUsage && !cert.extendedKeyUsage.includes(OID_EKU_CODE_SIGNING)) {
    log.warning('the signing certificate does not list the Code Signing extended key usage');
  }
  if (cert.x509.publicKey.asymmetricKeyType !== 'rsa') {
    throw new SignError(`unsupported signing key type "${cert.x509.publicKey.asymmetricKeyType}" (the SimplySign flow signs with RSA)`);
  }
}

/** An authenticated Certum cloud session, ready to sign SHA-256 digests with one card. */
export class CloudSession {
  readonly certificate: CertificateInfo;
  readonly card: CloudCard;
  readonly #scs: ScsClient;

  private constructor(scs: ScsClient, card: CloudCard, certificate: CertificateInfo) {
    this.#scs = scs;
    this.card = card;
    this.certificate = certificate;
  }

  /** Log in (e-mail + current one-time code), pick the card and fetch its certificate. */
  static async open(options: SessionOptions): Promise<CloudSession> {
    const endpoints = options.endpoints ?? CERTUM_ENDPOINTS;
    const log = options.log ?? silentLogger;
    const http = new HttpClient({
      userAgent: options.userAgent ?? USER_AGENT,
      timeoutMs: options.timeoutMs ?? 60_000,
      allowedOrigins: [endpoints.apiBase, endpoints.oauth.authorizeUrl, endpoints.oauth.loginUrl, endpoints.oauth.tokenUrl, endpoints.oauth.redirectUri],
      log,
    });
    log.info(`logging in to ${new URL(endpoints.apiBase).host} as ${options.email}`);
    const token = await login(http, endpoints.oauth, options.email, options.otpCode, log);
    const scs: ScsClient = { http, apiBase: endpoints.apiBase, token: token.accessToken, log };
    const card = await fetchCard(scs, options.cardSerial);
    if (card.serial.length >= 8) log.secret(card.serial);
    let certificate: CertificateInfo;
    try {
      certificate = parseCertificate(pemToDer(card.certificateRaw));
    } catch (err) {
      throw new SignError(`the cloud returned an unparsable signing certificate: ${(err as Error).message}`);
    }
    checkCertificate(certificate, log);
    log.info(`signing certificate: ${oneLineName(certificate.x509.subject)} (SHA-256 ${certificate.x509.fingerprint256}), valid until ${certificate.x509.validToDate.toISOString()}`);
    return new CloudSession(scs, card, certificate);
  }

  get cardSerial(): string {
    return this.card.serial;
  }

  /** Ask the cloud HSM for the RSA PKCS#1 v1.5 signature of a SHA-256 digest. */
  async signDigest(digest: Uint8Array): Promise<Buffer> {
    return requestSignature(this.#scs, this.card, digest);
  }
}

export interface SignOptions {
  readonly description?: string | undefined;
  readonly url?: string | undefined;
  /** RFC 3161 TSA; null/empty disables timestamping. */
  readonly timestampUrl?: string | null | undefined;
  /** Extra intermediates to embed (the Certum Code Signing 2021 CA is built in). */
  readonly extraCertificates?: readonly CertificateInfo[];
  readonly signingTime?: Date;
  readonly replaceExistingSignature?: boolean;
  /** Re-verify the produced file before returning it (default true). */
  readonly verify?: boolean;
  readonly timeoutMs?: number;
  readonly userAgent?: string;
  readonly log?: Logger;
}

export interface SignResult {
  readonly kind: ImageKind;
  readonly signed: Buffer;
  /** The Authenticode digest of the file that was signed. */
  readonly digest: Buffer;
  readonly signature: Buffer;
  readonly timestamp: TimestampToken | null;
  /** The intermediates that were embedded after the signer certificate. */
  readonly chain: readonly CertificateInfo[];
  readonly verification: VerificationResult | null;
}

/** The format-independent middle of the pipeline: cloud signature, its check, timestamp, chain — then the PKCS#7. */
async function signPrepared(
  session: CloudSession,
  prepared: PreparedSignature,
  options: SignOptions,
  log: Logger,
): Promise<{ pkcs7: Buffer; signature: Buffer; timestamp: TimestampToken | null; chain: CertificateInfo[] }> {
  log.debug(`authenticode sha256 ${prepared.digest.toString('hex')}`);
  const signature = await session.signDigest(prepared.toBeSigned);
  if (!cryptoVerify('sha256', prepared.signedAttrsSet, session.certificate.x509.publicKey, signature)) {
    throw new SignError('the cloud returned a signature that does not verify with the signing certificate — refusing to embed it');
  }

  let timestamp: TimestampToken | null = null;
  if (options.timestampUrl) {
    const tsaHttp = new HttpClient({
      userAgent: options.userAgent ?? USER_AGENT,
      timeoutMs: options.timeoutMs ?? 60_000,
      allowedOrigins: [options.timestampUrl],
      allowHttp: true,
      log,
    });
    timestamp = await fetchTimestamp(tsaHttp, options.timestampUrl, signature, log);
    log.debug(`timestamped at ${timestamp.genTime.toISOString()} by ${oneLineName(timestamp.tsa.x509.subject)}`);
  }

  const { chain, missingIssuer } = buildChain(session.certificate, [...(options.extraCertificates ?? []), CERTUM_INTERMEDIATE]);
  if (missingIssuer) log.warning(`no certificate for issuer "${missingIssuer}" is available to embed; verifiers will have to obtain it themselves`);

  const pkcs7 = buildSignedData(prepared, signature, session.certificate, chain, timestamp?.token ?? null);
  return { pkcs7, signature, timestamp, chain };
}

function checkSelfVerification(session: CloudSession, verification: VerificationResult, prepared: PreparedSignature, timestamp: TimestampToken | null): void {
  if (verification.signer.x509.fingerprint256 !== session.certificate.x509.fingerprint256) {
    throw new SignError('self-verification found a different signer certificate than the session certificate');
  }
  if (!verification.digest.equals(prepared.digest)) throw new SignError('self-verification recomputed a different file digest than the one that was signed');
  if (timestamp && !verification.timestamp) throw new SignError('self-verification could not find the embedded timestamp');
}

const alreadySigned = (options: SignOptions, log: Logger): void => {
  if (!options.replaceExistingSignature) throw new SignError('the file already carries a signature (enable replace-existing-signature to replace it)');
  log.info('replacing the existing signature');
};

/** Sign one PE image through `session`; returns the signed image (the input is not modified). */
export async function signPe(session: CloudSession, pe: Uint8Array, options: SignOptions = {}): Promise<SignResult> {
  const log = options.log ?? silentLogger;
  let image = asBuffer(pe);
  if (parsePeLayout(image).certTableSize !== 0) {
    alreadySigned(options, log);
    image = stripSignature(image);
  }
  const prepared = prepare(image, { description: options.description, url: options.url, signingTime: options.signingTime ?? new Date() });
  const { pkcs7, signature, timestamp, chain } = await signPrepared(session, prepared, options, log);
  const signed = embedSignature(image, pkcs7);

  let verification: VerificationResult | null = null;
  if (options.verify !== false) {
    verification = verifySignedPe(signed);
    checkSelfVerification(session, verification, prepared, timestamp);
  }
  return { kind: 'pe', signed, digest: prepared.digest, signature, timestamp, chain, verification };
}

/**
 * Sign one MSI package through `session`; returns the signed package (the
 * input is not modified). The package is re-laid-out around the new
 * `\x05DigitalSignature` stream, and `\x05MsiDigitalSignatureEx` is always
 * written so the signature also covers the directory metadata.
 */
export async function signMsi(session: CloudSession, bytes: Uint8Array, options: SignOptions = {}): Promise<SignResult> {
  const log = options.log ?? silentLogger;
  const parsed = parseCompoundFile(bytes);
  if (isMsiSigned(parsed)) alreadySigned(options, log);
  // Drop any signature streams (a stale MsiDigitalSignatureEx too), compute
  // the metadata digest, put it in its stream, then hash the tree as a
  // verifier will see it.
  const file = stripMsiSignature(parsed);
  const prehash = msiPrehash(file, 'sha256');
  const withExtended = withExtendedSignature(file, prehash);
  const digest = msiDigest(withExtended, 'sha256');
  const prepared = prepareIndirectData(spcSipInfo(), digest, { description: options.description, url: options.url, signingTime: options.signingTime ?? new Date() });
  const { pkcs7, signature, timestamp, chain } = await signPrepared(session, prepared, options, log);
  const signed = writeCompoundFile(embedMsiSignature(withExtended, pkcs7, prehash));

  let verification: VerificationResult | null = null;
  if (options.verify !== false) {
    verification = verifySignedMsi(signed);
    checkSelfVerification(session, verification, prepared, timestamp);
  }
  return { kind: 'msi', signed, digest, signature, timestamp, chain, verification };
}

/** Sign a PE image or an MSI package, whichever `bytes` is. */
export async function signFile(session: CloudSession, bytes: Uint8Array, options: SignOptions = {}): Promise<SignResult> {
  return detectImageKind(bytes) === 'pe' ? signPe(session, bytes, options) : signMsi(session, bytes, options);
}
