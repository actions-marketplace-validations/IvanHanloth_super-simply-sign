import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AuthError, extractHiddenInput, login } from '../src/auth.ts';
import { HttpClient } from '../src/http.ts';
import { consoleLogger } from '../src/log.ts';
import { OID_EKU_CODE_SIGNING, OID_EKU_TIME_STAMPING, makeCertificate } from './helpers/mini-x509.ts';
import { startMockCertum, type MockCertum } from './helpers/mock-certum.ts';

test('extractHiddenInput tolerates attribute order, quoting and entities', () => {
  assert.equal(extractHiddenInput('<input type="hidden" name="execution" value="e1s1_abc"/>', 'execution'), 'e1s1_abc');
  assert.equal(extractHiddenInput("<INPUT value='v&amp;w' type='hidden' name='execution'>", 'execution'), 'v&w');
  assert.equal(extractHiddenInput('<input name="lt" value="">', 'lt'), '');
  assert.equal(extractHiddenInput('<input name="other" value="x">', 'execution'), null);
  assert.equal(extractHiddenInput('<input name="execution.x" value="no">', 'execution'), null);
});

function clientFor(mock: MockCertum): HttpClient {
  const o = mock.endpoints.oauth;
  return new HttpClient({ userAgent: 'test', timeoutMs: 5000, allowedOrigins: [o.authorizeUrl, o.loginUrl, o.tokenUrl, o.redirectUri] });
}

test('the CAS authorization-code dance yields a bearer token without ever requesting the redirect target', async () => {
  const signingCert = makeCertificate({ commonName: 'Signer', extendedKeyUsage: [OID_EKU_CODE_SIGNING] });
  const tsaCert = makeCertificate({ commonName: 'TSA', extendedKeyUsage: [OID_EKU_TIME_STAMPING] });
  const mock = await startMockCertum({ email: 'me@example.com', acceptCode: (c) => c === '123456' || c === '654321', signingCert, tsaCert });
  try {
    const log = consoleLogger();
    const token = await login(clientFor(mock), mock.endpoints.oauth, 'me@example.com', '123456', log);
    assert.equal(token.accessToken, mock.accessTokens[0]);
    assert.equal(token.expiresIn, 1800);
    assert.ok(log.secrets.includes(token.accessToken), 'the token must be registered as a secret');
    assert.ok(log.secrets.some((s) => s.startsWith('TGT-')), 'the CAS session cookie must be registered as a secret');
    assert.ok(log.secrets.some((s) => s.startsWith('OC-')), 'the authorization code must be registered as a secret');
    assert.equal(mock.requests.some((r) => r.path === '/redirect'), false, 'the redirect_uri must never be fetched');
    assert.deepEqual(
      mock.requests.map((r) => `${r.method} ${r.path}`),
      [
        'GET /idp/oauth2.0/authorize',
        'GET /idp/login',
        'POST /idp/login',
        'GET /idp/oauth2.0/callbackAuthorize',
        'GET /idp/oauth2.0/authorize',
        'POST /idp/oauth2.0/accessToken',
      ],
    );
    assert.ok(mock.requests.every((r) => r.headers['user-agent'] === 'test'));

    // A one-time code is single use, and a wrong one is reported as a login rejection.
    await assert.rejects(login(clientFor(mock), mock.endpoints.oauth, 'me@example.com', '123456', log), (err: unknown) => err instanceof AuthError && /rejected/.test(err.message));
    await assert.rejects(login(clientFor(mock), mock.endpoints.oauth, 'me@example.com', '000000', log), /rejected by the identity provider/);
    await assert.rejects(login(clientFor(mock), mock.endpoints.oauth, 'someone@else.com', '654321', log), /rejected/);
    assert.deepEqual(mock.usedCodes, ['123456']);
  } finally {
    await mock.close();
  }
});
