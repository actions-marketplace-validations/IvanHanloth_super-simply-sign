/**
 * A tiny X.509 issuer for tests: fresh RSA keys, a handful of extensions,
 * signed with sha256WithRSAEncryption. Nothing here is ever committed — keys
 * are generated per test run, so no throwaway private key lives in the repo.
 */
import { createHash, generateKeyPairSync, sign, type KeyObject } from 'node:crypto';
import * as der from '../../src/der.ts';

export interface TestCert {
  readonly der: Buffer;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  readonly subjectDer: Buffer;
  readonly pem: string;
}

export interface TestCertOptions {
  readonly commonName: string;
  readonly issuer?: TestCert;
  readonly extendedKeyUsage?: readonly string[];
  readonly ca?: boolean;
  readonly serial?: number;
  readonly notBefore?: Date;
  readonly notAfter?: Date;
  readonly modulusLength?: number;
}

const OID_SHA256_WITH_RSA = '1.2.840.113549.1.1.11';

const name = (cn: string): Buffer => der.seq(der.set(der.seq(der.oid('2.5.4.3'), der.utf8String(cn))));

const extension = (oid: string, value: Uint8Array, critical: boolean): Buffer =>
  der.seq(der.oid(oid), ...(critical ? [der.boolTrue()] : []), der.octetString(value));

let serialCounter = 1000;

export function makeCertificate(options: TestCertOptions): TestCert {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: options.modulusLength ?? 2048 });
  const spki = publicKey.export({ type: 'spki', format: 'der' });
  const subjectDer = name(options.commonName);
  const issuerDer = options.issuer ? options.issuer.subjectDer : subjectDer;
  const signingKey = options.issuer ? options.issuer.privateKey : privateKey;
  const notBefore = options.notBefore ?? new Date(Date.now() - 86_400_000);
  const notAfter = options.notAfter ?? new Date(Date.now() + 365 * 86_400_000);

  const spkiBits = der.children(der.readExact(spki))[1]!.content.subarray(1);
  const extensions = [
    extension('2.5.29.19', der.seq(...(options.ca ? [der.boolTrue()] : [])), true), // basicConstraints
    extension('2.5.29.14', der.octetString(createHash('sha1').update(spkiBits).digest()), false), // subjectKeyIdentifier
  ];
  if (options.extendedKeyUsage) extensions.push(extension('2.5.29.37', der.seq(...options.extendedKeyUsage.map((o) => der.oid(o))), true));

  const sigAlg = der.seq(der.oid(OID_SHA256_WITH_RSA), der.nul());
  const tbs = der.seq(
    der.ctx(0, der.integer(2)),
    der.integer(options.serial ?? serialCounter++),
    sigAlg,
    issuerDer,
    der.seq(der.time(notBefore), der.time(notAfter)),
    subjectDer,
    spki,
    der.ctx(3, der.seq(...extensions)),
  );
  const certDer = der.seq(tbs, sigAlg, der.bitString(sign('sha256', tbs, signingKey)));
  const pem = `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64').replace(/(.{64})/g, '$1\n').trim()}\n-----END CERTIFICATE-----\n`;
  return { der: certDer, privateKey, publicKey, subjectDer, pem };
}

export const OID_EKU_CODE_SIGNING = '1.3.6.1.5.5.7.3.3';
export const OID_EKU_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';
