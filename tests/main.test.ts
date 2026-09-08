/**
 * Runs the built bundle (dist/index.cjs) the way the runner does — inputs as
 * INPUT_* variables, outputs through GITHUB_OUTPUT — for the paths that need
 * no network: the guard rails and the "nothing to sign" exit.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const distPath = fileURLToPath(new URL('../dist/index.cjs', import.meta.url));
const repoRoot = fileURLToPath(new URL('..', import.meta.url));

const DEFAULTS: Record<string, string> = {
  'timestamp-url': 'http://time.certum.pl/',
  backup: 'false',
  'replace-existing-signature': 'false',
  verify: 'true',
  'allow-pull-request': 'false',
  'fail-on-no-files': 'true',
};

interface ActionRun {
  readonly code: number;
  readonly output: string;
  readonly outputs: Record<string, string>;
}

function runAction(inputs: Record<string, string>, extraEnv: Record<string, string> = {}): ActionRun {
  const dir = mkdtempSync(path.join(tmpdir(), 'sss-main-'));
  const outputFile = path.join(dir, 'output.txt');
  const summaryFile = path.join(dir, 'summary.md');
  writeFileSync(outputFile, '');
  writeFileSync(summaryFile, '');
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v !== undefined && !/^(CERTUM_|INPUT_|GITHUB_|RUNNER_)/i.test(k)) env[k] = v;
  }
  for (const [k, v] of Object.entries({ ...DEFAULTS, ...inputs })) env[`INPUT_${k.toUpperCase()}`] = v;
  const result = spawnSync(process.execPath, [distPath], {
    cwd: repoRoot,
    env: { ...env, GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: summaryFile, ...extraEnv },
    encoding: 'utf8',
    timeout: 60_000,
  });
  const outputs: Record<string, string> = {};
  for (const m of readFileSync(outputFile, 'utf8').matchAll(/^(.+?)<<(ghadelimiter_[^\r\n]+)\r?\n([\s\S]*?)\r?\n\2\r?\n/gm)) {
    outputs[m[1]!] = m[3]!;
  }
  return { code: result.status ?? -1, output: `${result.stdout}${result.stderr}`, outputs };
}

test('the bundle stops on missing authentication with a clear error', () => {
  const run = runAction({ files: 'tests/fixtures/hello.exe', email: 'nobody@example.com' });
  assert.equal(run.code, 1);
  assert.match(run.output, /^::error::authentication required: set otp-seed \(TOTP seed\) or otp-code \(a current 6-digit code\)$/m);
  const visible = run.output.split(/\r?\n/).filter((line) => !line.startsWith('::debug::'));
  assert.ok(visible.every((line) => !/\sat .*\.cjs:\d+/.test(line)), 'stack traces only ever go to the debug log');
});

test('input validation happens before any network activity', () => {
  assert.match(runAction({ files: 'tests/fixtures/hello.exe', email: 'nobody@example.com', 'otp-code': '12ab' }).output, /otp-code must be exactly 6 digits/);
  assert.match(runAction({ files: 'tests/fixtures/hello.exe', email: 'nobody@example.com', 'otp-code': '123456', 'otp-seed': 'GEZDGNBV' }).output, /set only one of otp-seed and otp-code/);
  assert.match(runAction({ files: 'tests/fixtures/hello.exe', 'otp-code': '123456' }).output, /email is required/);
  assert.match(runAction({ files: 'tests/fixtures/hello.exe', email: 'not-an-address', 'otp-code': '123456' }).output, /does not look like an e-mail address/);
  assert.match(runAction({ files: 'tests/fixtures/hello.exe', email: 'nobody@example.com', 'otp-code': '123456', 'timestamp-url': 'ftp://x' }).output, /timestamp-url must be an http\(s\) URL/);
  assert.match(runAction({ files: 'tests/fixtures/*.nothing', email: 'nobody@example.com', 'otp-code': '123456' }).output, /::error::no files matched/);
});

test('pull_request events are refused unless explicitly allowed', () => {
  const refused = runAction({ files: 'tests/fixtures/hello.exe', email: 'nobody@example.com', 'otp-code': '123456' }, { GITHUB_EVENT_NAME: 'pull_request' });
  assert.equal(refused.code, 1);
  assert.match(refused.output, /::error::refusing to sign on a pull_request event/);
  const allowed = runAction(
    { files: 'tests/fixtures/*.nothing', email: 'nobody@example.com', 'otp-code': '123456', 'allow-pull-request': 'true', 'fail-on-no-files': 'false' },
    { GITHUB_EVENT_NAME: 'pull_request' },
  );
  assert.equal(allowed.code, 0);
});

test('with nothing to sign and fail-on-no-files off, the action succeeds with empty outputs', () => {
  const run = runAction({ files: 'tests/fixtures/*.nothing\ntests/fixtures/*.alsonothing', email: 'nobody@example.com', 'otp-code': '123456', 'fail-on-no-files': 'false' });
  assert.equal(run.code, 0, run.output);
  assert.match(run.output, /::warning::no files matched/);
  assert.equal(run.outputs['signed-count'], '0');
  assert.equal(run.outputs['signed-files'], '[]');
});
