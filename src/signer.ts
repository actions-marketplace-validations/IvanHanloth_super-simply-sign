/**
 * The pipeline: one authenticated cloud session (login → card → certificate)
 * that signs any number of PE images, each as
 *
 *   prepare → cloud signature → check it against the certificate →
 *   RFC 3161 timestamp (checked) → assemble PKCS#7 → embed → self-verify.
 *
 * Nothing here touches the disk and no token is ever persisted: the session
 * lives exactly as long as the process that logged in.
 */
import { verify as cryptoVerify } from 'node:crypto';
import { CERTUM_OAUTH, login, type OAuthConfig } from './auth.ts';
import { finalize, prepare } from './authenticode.ts';
import { CERTUM_CODE_SIGNING_2021_CA_DER } from './certs/certum-code-signing-2021-ca.ts';
import { asBuffer } from './der.ts';
import { HttpClient } from './http.ts';
import { silentLogger, type Logger } from './log.ts';
import { parsePeLayout, stripSignature } from './pe.ts';
import { fetchCard, requestSignature, type CloudCard, type ScsClient } from './scs.ts';
import { fetchTimestamp, type TimestampToken } from './timestamp.ts';
import { verifySignedPe, type VerificationResult } from './verify.ts';
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
  /** Re-verify the produced image before returning it (default true). */
  readonly verify?: boolean;
  readonly timeoutMs?: number;
  readonly userAgent?: string;
  readonly log?: Logger;
}

export interface SignResult {
  readonly signed: Buffer;
  readonly peHash: Buffer;
  readonly signature: Buffer;
  readonly timestamp: TimestampToken | null;
  /** The intermediates that were embedded after the signer certificate. */
  readonly chain: readonly CertificateInfo[];
  readonly verification: VerificationResult | null;
}

/** Sign one PE image through `session`; returns the signed image (the input is not modified). */
export async function signPe(session: CloudSession, pe: Uint8Array, options: SignOptions = {}): Promise<SignResult> {
  const log = options.log ?? silentLogger;
  let image = asBuffer(pe);
  if (parsePeLayout(image).certTableSize !== 0) {
    if (!options.replaceExistingSignature) throw new SignError('the file already carries a signature (enable replace-existing-signature to replace it)');
    log.info('replacing the existing signature');
    image = stripSignature(image);
  }

  const prepared = prepare(image, { description: options.description, url: options.url, signingTime: options.signingTime ?? new Date() });
  log.debug(`authenticode sha256 ${prepared.peHash.toString('hex')}`);

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
    });
    timestamp = await fetchTimestamp(tsaHttp, options.timestampUrl, signature, log);
    log.debug(`timestamped at ${timestamp.genTime.toISOString()} by ${oneLineName(timestamp.tsa.x509.subject)}`);
  }

  const { chain, missingIssuer } = buildChain(session.certificate, [...(options.extraCertificates ?? []), CERTUM_INTERMEDIATE]);
  if (missingIssuer) log.warning(`no certificate for issuer "${missingIssuer}" is available to embed; verifiers will have to obtain it themselves`);

  const signed = finalize(image, prepared, signature, session.certificate, chain, timestamp?.token ?? null);

  let verification: VerificationResult | null = null;
  if (options.verify !== false) {
    verification = verifySignedPe(signed);
    if (verification.signer.x509.fingerprint256 !== session.certificate.x509.fingerprint256) {
      throw new SignError('self-verification found a different signer certificate than the session certificate');
    }
    if (timestamp && !verification.timestamp) throw new SignError('self-verification could not find the embedded timestamp');
  }
  return { signed, peHash: prepared.peHash, signature, timestamp, chain, verification };
}
