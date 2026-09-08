/**
 * Maintainer tool — sign a PE through the full pipeline against a local
 * stand-in for the Certum cloud (fresh keys, nothing persisted) and, if a TSA
 * URL is given, the real timestamp authority:
 *
 *   node tools/local-crosscheck.ts tests/fixtures/hello.exe out/signed.exe http://time.certum.pl/
 *
 * Then check the result with Windows: `signtool verify /pa /v out/signed.exe`
 * (expect only the "root certificate which is not trusted" error — the test
 * CA is written next to the output as `signed.exe.ca.cer`) or
 * `Get-AuthenticodeSignature`. This is the check that validated the action
 * against Microsoft's verifier; it never touches the Certum signing API.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { consoleLogger } from '../src/log.ts';
import { CloudSession, signPe } from '../src/signer.ts';
import { verifySignedPe } from '../src/verify.ts';
import { parseCertificate } from '../src/x509.ts';
import { OID_EKU_CODE_SIGNING, OID_EKU_TIME_STAMPING, makeCertificate } from '../tests/helpers/mini-x509.ts';
import { startMockCertum } from '../tests/helpers/mock-certum.ts';

const [input, output, tsaUrl] = process.argv.slice(2);
if (!input || !output) {
  console.error('usage: node tools/local-crosscheck.ts <in.exe> <out.exe> [tsa-url]');
  process.exit(2);
}

const ca = makeCertificate({ commonName: 'SSS Local Test CA', ca: true });
const leaf = makeCertificate({ commonName: 'SSS Local Test Publisher', issuer: ca, extendedKeyUsage: [OID_EKU_CODE_SIGNING] });
const tsa = makeCertificate({ commonName: 'unused mock TSA', extendedKeyUsage: [OID_EKU_TIME_STAMPING] });
const mock = await startMockCertum({ email: 'me@example.com', acceptCode: () => true, signingCert: leaf, tsaCert: tsa });
try {
  const log = consoleLogger(true);
  const session = await CloudSession.open({ email: 'me@example.com', otpCode: '123456', endpoints: mock.endpoints, log });
  const result = await signPe(session, readFileSync(input), {
    description: 'SSS local cross-check',
    url: 'https://example.com/sss',
    timestampUrl: tsaUrl || null,
    extraCertificates: [parseCertificate(ca.der)],
    log,
  });
  mkdirSync(path.dirname(output), { recursive: true });
  writeFileSync(output, result.signed);
  writeFileSync(`${output}.ca.cer`, ca.der);
  const verified = verifySignedPe(readFileSync(output));
  const stamp = verified.timestamp ? `${verified.timestamp.genTime.toISOString()} by ${verified.timestamp.tsa.x509.subject.split('\n').join(', ')}` : 'none';
  console.log(`written ${output}: ${result.signed.length} bytes; certificates embedded: ${verified.certificates.length}; timestamp: ${stamp}`);
} finally {
  await mock.close();
}
