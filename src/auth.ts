/**
 * Step 1 — OAuth 2.0 authorization-code login against Certum's CAS identity
 * provider (`cloudsign.webnotarius.pl`), driven purely over HTTPS:
 *
 *   GET  /idp/oauth2.0/authorize   → 302 … → the login page (hidden `execution`)
 *   POST /idp/login?service=…       → 302 … → redirect_uri?code=…
 *   POST /idp/oauth2.0/accessToken  → {"access_token": …}
 *
 * The credentials are the account e-mail and the current 6-digit TOTP code —
 * there is no account password. The OAuth *client* credentials below are
 * application-level constants shipped identically to every SimplySign
 * Desktop install (a public client in the RFC 8252 sense); they are not the
 * account holder's secret.
 */
import { redactUrl, type HttpClient } from './http.ts';
import type { Logger } from './log.ts';

export interface OAuthConfig {
  readonly authorizeUrl: string;
  readonly loginUrl: string;
  readonly tokenUrl: string;
  readonly scope: string;
  readonly redirectUri: string;
  readonly clientId: string;
  readonly clientSecret: string;
}

export const CERTUM_OAUTH: OAuthConfig = {
  authorizeUrl: 'https://cloudsign.webnotarius.pl/idp/oauth2.0/authorize',
  loginUrl: 'https://cloudsign.webnotarius.pl/idp/login',
  tokenUrl: 'https://cloudsign.webnotarius.pl/idp/oauth2.0/accessToken',
  scope: 'https://cloudsign.webnotarius.pl/idp/oauth2.0/profile',
  redirectUri: 'https://cloudsign.webnotarius.pl/redirect',
  clientId: '44rvDKKEWY53a7xBeF5w',
  clientSecret: 'BRSE2u2nY3p3m77QHTt8',
};

export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

export interface AccessToken {
  readonly accessToken: string;
  readonly expiresIn: number | null;
}

const ENTITIES: Readonly<Record<string, string>> = {
  '&amp;': '&',
  '&quot;': '"',
  '&#39;': "'",
  '&#x27;': "'",
  '&lt;': '<',
  '&gt;': '>',
};

const decodeEntities = (s: string): string => s.replace(/&(?:amp|quot|#39|#x27|lt|gt);/g, (m) => ENTITIES[m] ?? m);

/** The value of `<input name="…" value="…">`, whichever attribute comes first. */
export function extractHiddenInput(html: string, name: string): string | null {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const byNameThenValue = new RegExp(`<input[^>]*\\bname=["']${escaped}["'][^>]*\\bvalue=["']([^"']*)["']`, 'is');
  const byValueThenName = new RegExp(`<input[^>]*\\bvalue=["']([^"']*)["'][^>]*\\bname=["']${escaped}["']`, 'is');
  const m = byNameThenValue.exec(html) ?? byValueThenName.exec(html);
  const value = m?.[1];
  return value === undefined ? null : decodeEntities(value);
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Log in with the account e-mail and a current one-time code; returns the bearer token. */
export async function login(http: HttpClient, config: OAuthConfig, email: string, otpCode: string, log: Logger): Promise<AccessToken> {
  // 1. authorize → (redirects) → the login page carrying the CAS flow token.
  const authorize = new URL(config.authorizeUrl);
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    api_key: '',
  }).toString();
  const page = await http.follow(authorize, { method: 'GET', headers: { accept: 'text/html,*/*' } }, { maxHops: 20 });
  if (page.status !== 200) throw new AuthError(`the login page returned HTTP ${page.status} (${redactUrl(page.url)})`);
  const html = page.body.toString('utf8');
  const execution = extractHiddenInput(html, 'execution');
  if (!execution) throw new AuthError('could not find the CAS "execution" field on the login page — has the SimplySign login flow changed?');
  const lt = extractHiddenInput(html, 'lt') ?? '';
  const service = new URL(page.url).searchParams.get('service');
  for (const cookie of http.jar.values()) if (cookie.length >= 16) log.secret(cookie);
  log.debug(`login page loaded after ${page.hops.length} redirect(s)`);

  // 2. submit the credentials (the OTP is the password); the authorization
  //    code travels on the redirect chain and is captured *before* the
  //    redirect target is ever requested.
  const loginUrl = new URL(config.loginUrl);
  if (service) loginUrl.searchParams.set('service', service);
  const form = new URLSearchParams({
    username: email,
    password: otpCode,
    execution,
    _eventId: 'submit',
    geolocation: '',
    submit: 'LOGIN',
    lt,
  });
  const redirectOrigin = new URL(config.redirectUri).origin;
  const found: { code: string | null } = { code: null };
  const result = await http.follow(
    loginUrl,
    { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'text/html,*/*' }, body: form.toString() },
    {
      maxHops: 20,
      onRedirect: (target) => {
        const code = target.searchParams.get('code');
        if (code && target.origin === redirectOrigin) {
          found.code = code;
          return true;
        }
        return false;
      },
    },
  );
  for (const cookie of http.jar.values()) if (cookie.length >= 16) log.secret(cookie);
  if (!found.code) {
    const finalUrl = new URL(result.url);
    if (finalUrl.origin === redirectOrigin) found.code = finalUrl.searchParams.get('code');
  }
  if (!found.code) {
    const errorPage = /class=["'][^"']*\berrors?\b[^"']*["']/i.test(result.body.toString('utf8'));
    throw new AuthError(
      errorPage
        ? 'login rejected by the identity provider — wrong e-mail or OTP, or a one-time code that was already used'
        : `login did not produce an authorization code (HTTP ${result.status} at ${redactUrl(result.url)})`,
    );
  }
  log.secret(found.code);
  log.debug(`authorization code received after ${result.hops.length} redirect(s)`);

  // 3. exchange the code for a bearer token (parameters in the query string,
  //    empty body — exactly what the desktop client sends).
  const tokenUrl = new URL(config.tokenUrl);
  tokenUrl.search = new URLSearchParams({
    client_id: config.clientId,
    client_secret: config.clientSecret,
    scope: config.scope,
    code: found.code,
    redirect_uri: config.redirectUri,
    grant_type: 'authorization_code',
  }).toString();
  const tokenResponse = await http.fetch(tokenUrl, { method: 'POST', headers: { accept: 'application/json' } });
  let json: unknown;
  try {
    json = JSON.parse(tokenResponse.body.toString('utf8'));
  } catch {
    throw new AuthError(`token exchange returned HTTP ${tokenResponse.status} with a non-JSON body`);
  }
  const obj = isRecord(json) ? json : {};
  const accessToken = obj['access_token'];
  if (tokenResponse.status !== 200 || typeof accessToken !== 'string' || accessToken.length === 0) {
    const detail = [obj['error'], obj['error_description']].filter((v): v is string => typeof v === 'string').join(': ');
    throw new AuthError(`token exchange failed (HTTP ${tokenResponse.status})${detail ? `: ${detail}` : ''}`);
  }
  log.secret(accessToken);
  const refresh = obj['refresh_token'];
  if (typeof refresh === 'string' && refresh) log.secret(refresh);
  http.jar.clear();
  return { accessToken, expiresIn: typeof obj['expires_in'] === 'number' ? obj['expires_in'] : null };
}
