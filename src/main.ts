/**
 * The GitHub Action entry point: inputs → guard rails → one cloud session →
 * sign every matched file → outputs and a job summary.
 */
import * as core from '@actions/core';
import * as glob from '@actions/glob';
import { createHash } from 'node:crypto';
import { mkdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { writeBackup, writeFileAtomic } from './fsutil.ts';
import type { Logger } from './log.ts';
import { CloudSession, USER_AGENT, signPe } from './signer.ts';
import { isValidOtpCode, parseTotpSecret, secondsLeftInWindow, totpCode, wipe } from './totp.ts';
import { oneLineName, parseCertificate, pemBlocks, type CertificateInfo } from './x509.ts';

/** Images are read whole; anything larger than this is almost certainly a mistake. */
const MAX_FILE_BYTES = 1024 * 1024 * 1024;

interface Inputs {
  readonly files: readonly string[];
  readonly email: string;
  readonly otpSeed: string;
  readonly otpCode: string;
  readonly timestampUrl: string;
  readonly description: string;
  readonly url: string;
  readonly outputDir: string;
  readonly backup: boolean;
  readonly replaceExistingSignature: boolean;
  readonly chainFile: string;
  readonly cardSerial: string;
  readonly verify: boolean;
  readonly allowPullRequest: boolean;
  readonly failOnNoFiles: boolean;
}

function readInputs(): Inputs {
  const text = (name: string): string => core.getInput(name).trim();
  const env = (name: string): string => (process.env[name] ?? '').trim();
  return {
    files: core
      .getMultilineInput('files')
      .flatMap((line) => line.split(','))
      .map((s) => s.trim())
      .filter((s) => s.length > 0),
    email: text('email') || env('CERTUM_EMAIL'),
    otpSeed: text('otp-seed') || env('CERTUM_OTP'),
    otpCode: text('otp-code') || env('CERTUM_TOKEN'),
    timestampUrl: text('timestamp-url'),
    description: text('description'),
    url: text('url'),
    outputDir: text('output-dir'),
    backup: core.getBooleanInput('backup'),
    replaceExistingSignature: core.getBooleanInput('replace-existing-signature'),
    chainFile: text('chain-file'),
    cardSerial: text('card-serial'),
    verify: core.getBooleanInput('verify'),
    allowPullRequest: core.getBooleanInput('allow-pull-request'),
    failOnNoFiles: core.getBooleanInput('fail-on-no-files'),
  };
}

const actionLogger: Logger = {
  info: (m) => core.info(m),
  debug: (m) => core.debug(m),
  warning: (m) => core.warning(m),
  secret: (v) => {
    if (v) core.setSecret(v);
  },
};

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Turn the seed or the literal code input into the code to log in with. */
async function resolveOtpCode(inputs: Inputs): Promise<string> {
  if (inputs.otpSeed && inputs.otpCode) throw new Error('set only one of otp-seed and otp-code');
  if (!inputs.otpSeed && !inputs.otpCode) throw new Error('authentication required: set otp-seed (TOTP seed) or otp-code (a current 6-digit code)');
  if (inputs.otpCode) {
    core.setSecret(inputs.otpCode);
    if (!isValidOtpCode(inputs.otpCode)) throw new Error('otp-code must be exactly 6 digits');
    return inputs.otpCode;
  }
  core.setSecret(inputs.otpSeed);
  const params = parseTotpSecret(inputs.otpSeed);
  try {
    // A code submitted seconds before its window closes may be rejected; wait for a fresh one.
    const left = secondsLeftInWindow(params);
    if (left < 4) {
      core.info(`waiting ${left}s for the next one-time-code window`);
      await sleep(left * 1000 + 250);
    }
    const code = totpCode(params);
    core.setSecret(code);
    return code;
  } finally {
    wipe(params.secret);
  }
}

function guardEvent(inputs: Inputs): void {
  const event = process.env['GITHUB_EVENT_NAME'] ?? '';
  if ((event === 'pull_request' || event === 'pull_request_target') && !inputs.allowPullRequest) {
    throw new Error(
      `refusing to sign on a ${event} event: code signing must not be triggerable by a pull request. ` +
        'Run it from workflow_dispatch, a tag or a protected-branch push behind a protected environment (or set allow-pull-request: true if you really mean it).',
    );
  }
}

async function resolveFiles(patterns: readonly string[]): Promise<string[]> {
  if (patterns.length === 0) throw new Error('the files input is empty');
  const globber = await glob.create(patterns.join('\n'), { followSymbolicLinks: false, matchDirectories: false, implicitDescendants: false });
  const files = [...new Set(await globber.glob())].sort();
  for (const file of files) {
    const info = await stat(file);
    if (!info.isFile()) throw new Error(`${file} is not a regular file`);
    if (info.size > MAX_FILE_BYTES) throw new Error(`${file} is larger than ${MAX_FILE_BYTES} bytes`);
  }
  return files;
}

async function loadChain(chainFile: string): Promise<CertificateInfo[]> {
  if (!chainFile) return [];
  const blocks = pemBlocks(await readFile(chainFile, 'utf8'));
  if (blocks.length === 0) throw new Error(`${chainFile} contains no CERTIFICATE PEM block`);
  return blocks.map((der) => parseCertificate(der));
}

interface SignedFile {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
  readonly timestamp: string | null;
}

async function run(): Promise<void> {
  const inputs = readInputs();
  guardEvent(inputs);
  if (!inputs.email) throw new Error('email is required (input or $CERTUM_EMAIL)');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(inputs.email)) throw new Error('email does not look like an e-mail address');
  if (inputs.timestampUrl && !/^https?:\/\//i.test(inputs.timestampUrl)) throw new Error('timestamp-url must be an http(s) URL');
  if (!inputs.timestampUrl) core.warning('timestamping is disabled: these signatures will stop validating when the certificate expires');

  const files = await resolveFiles(inputs.files);
  if (files.length === 0) {
    if (inputs.failOnNoFiles) throw new Error(`no files matched: ${inputs.files.join(', ')}`);
    core.warning('no files matched the given patterns; nothing to sign');
    core.setOutput('signed-files', '[]');
    core.setOutput('signed-count', 0);
    return;
  }
  if (inputs.outputDir) {
    const names = files.map((f) => path.basename(f));
    const duplicate = names.find((n, i) => names.indexOf(n) !== i);
    if (duplicate) throw new Error(`two input files are both named "${duplicate}"; they would overwrite each other in output-dir`);
    await mkdir(inputs.outputDir, { recursive: true });
  }
  const extraCertificates = await loadChain(inputs.chainFile);
  core.info(`${files.length} file(s) to sign`);

  const otpCode = await resolveOtpCode(inputs);
  const session = await CloudSession.open({
    email: inputs.email,
    otpCode,
    cardSerial: inputs.cardSerial || undefined,
    userAgent: USER_AGENT,
    log: actionLogger,
  });
  const cert = session.certificate.x509;
  core.setOutput('certificate-subject', oneLineName(cert.subject));
  core.setOutput('certificate-fingerprint', cert.fingerprint256);
  core.setOutput('certificate-not-after', cert.validToDate.toISOString());

  const signed: SignedFile[] = [];
  for (const file of files) {
    await core.group(`Signing ${file}`, async () => {
      const original = await readFile(file);
      const result = await signPe(session, original, {
        description: inputs.description || undefined,
        url: inputs.url || undefined,
        timestampUrl: inputs.timestampUrl || null,
        extraCertificates,
        replaceExistingSignature: inputs.replaceExistingSignature,
        verify: inputs.verify,
        userAgent: USER_AGENT,
        log: actionLogger,
      });
      const target = inputs.outputDir ? path.join(inputs.outputDir, path.basename(file)) : file;
      if (inputs.backup && !inputs.outputDir) core.info(`original kept as ${await writeBackup(file, original)}`);
      await writeFileAtomic(target, result.signed);
      const sha256 = createHash('sha256').update(result.signed).digest('hex');
      const timestamp = result.timestamp?.genTime.toISOString() ?? null;
      signed.push({ path: target, sha256, bytes: result.signed.length, timestamp });
      core.info(`signed ${target} (${result.signed.length} bytes, sha256 ${sha256}${timestamp ? `, timestamped ${timestamp}` : ', not timestamped'})`);
    });
  }

  core.setOutput('signed-files', JSON.stringify(signed));
  core.setOutput('signed-count', signed.length);

  await core.summary
    .addHeading('Super Simply Sign', 2)
    .addRaw(`Signed **${signed.length}** file(s) with \`${oneLineName(cert.subject)}\` (SHA-256 \`${cert.fingerprint256}\`).`, true)
    .addTable([
      [
        { data: 'File', header: true },
        { data: 'SHA-256 (signed)', header: true },
        { data: 'Timestamp', header: true },
      ],
      ...signed.map((s) => [s.path, `<code>${s.sha256}</code>`, s.timestamp ?? '—']),
    ])
    .write();
}

run().catch((err: unknown) => {
  if (err instanceof Error) {
    core.debug(err.stack ?? err.message);
    core.setFailed(err.message);
  } else {
    core.setFailed(String(err));
  }
});
