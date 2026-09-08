/**
 * A local stand-in for the Certum SimplySign cloud, faithful to the captured
 * protocol in docs/PROTOCOL.md: the CAS OAuth login dance, the async SCS task
 * endpoints for cards / certificates / signatures, and an RFC 3161 TSA.
 * Everything runs on 127.0.0.1 over plain HTTP; the pipeline allows that for
 * loopback only.
 */
import { createHash, randomBytes, sign } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { OID_CONTENT_TYPE, OID_MESSAGE_DIGEST, OID_PKCS7_SIGNED_DATA, OID_RSA_ENCRYPTION, OID_SHA256, OID_SIGNING_TIME } from '../../src/cms.ts';
import * as der from '../../src/der.ts';
import { multipartPart } from '../../src/scs.ts';
import type { SigningEndpoints } from '../../src/signer.ts';
import { OID_TST_INFO } from '../../src/timestamp.ts';
import { parseCertificate } from '../../src/x509.ts';
import type { TestCert } from './mini-x509.ts';
import { signDigestPkcs1v15Sha256 } from './rsa-raw.ts';

export type TsaBehaviour = 'ok' | 'reject' | 'wrong-imprint' | 'drop-nonce' | 'garbage';

/** The OAuth client the mock IdP expects (stands in for the SimplySign Desktop constants). */
export const TEST_CLIENT_ID = 'test-client-id';

export interface MockCertumOptions {
  readonly email: string;
  /** The code the IdP accepts; each code is accepted once. */
  readonly acceptCode: (code: string) => boolean;
  readonly signingCert: TestCert;
  readonly tsaCert: TestCert;
  readonly cardSerial?: string;
  readonly pinRequired?: boolean;
  readonly extraCards?: number;
  /** Return a corrupt signature (to exercise the "refuse to embed" path). */
  readonly corruptSignature?: boolean;
  readonly tsaBehaviour?: TsaBehaviour;
  /** Send `atom:link`s pointing at another origin (must be refused). */
  readonly foreignAtomLink?: string;
}

export interface RequestRecord {
  readonly method: string;
  readonly path: string;
  readonly headers: IncomingMessage['headers'];
}

export interface MockCertum {
  readonly baseUrl: string;
  readonly endpoints: SigningEndpoints;
  readonly tsaUrl: string;
  readonly requests: RequestRecord[];
  readonly usedCodes: string[];
  readonly signedDigests: string[];
  readonly accessTokens: string[];
  close(): Promise<void>;
}

interface Task {
  readonly status: number;
  readonly contentType: string;
  readonly body: Buffer;
}

const readBody = (req: IncomingMessage): Promise<Buffer> =>
  new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });

const attribute = (oid: string, value: Uint8Array): Buffer => der.seq(der.oid(oid), der.set(value));

/** A TimeStampResp for `requestBytes`, signed by `tsa` (RFC 3161 §2.4.2). */
export function buildTimeStampResp(requestBytes: Uint8Array, tsa: TestCert, behaviour: TsaBehaviour = 'ok'): Buffer {
  if (behaviour === 'reject') {
    return der.seq(der.seq(der.integer(2), der.seq(der.utf8String('policy not supported')), der.bitString(Buffer.from([0x01]), 7)));
  }
  const req = der.children(der.readExact(requestBytes));
  const imprintTlv = der.expectTag(req[1], 0x30, 'messageImprint');
  let imprint = imprintTlv.raw;
  if (behaviour === 'wrong-imprint') {
    const [alg] = der.children(imprintTlv);
    imprint = der.seq(alg!.raw, der.octetString(randomBytes(32)));
  }
  const nonce = req.slice(2).find((t) => t.tag === 0x02);
  const tstInfoParts = [der.integer(1), der.oid('1.3.6.1.4.1.99999.1'), imprint, der.integer(randomBytes(8)), der.generalizedTime(new Date())];
  if (nonce && behaviour !== 'drop-nonce') tstInfoParts.push(nonce.raw);
  const tstInfo = der.seq(...tstInfoParts);

  const sha256AlgId = der.seq(der.oid(OID_SHA256), der.nul());
  const signedAttrs = der.setOf([
    attribute(OID_CONTENT_TYPE, der.oid(OID_TST_INFO)),
    attribute(OID_SIGNING_TIME, der.time(new Date())),
    attribute(OID_MESSAGE_DIGEST, der.octetString(createHash('sha256').update(tstInfo).digest())),
  ]);
  const signature = sign('sha256', signedAttrs, tsa.privateKey);
  const signerInfo = der.seq(
    der.integer(1),
    parseCertificate(tsa.der).issuerAndSerialNumber,
    sha256AlgId,
    der.ctx(0, der.readExact(signedAttrs).content),
    der.seq(der.oid(OID_RSA_ENCRYPTION), der.nul()),
    der.octetString(signature),
  );
  const signedData = der.seq(
    der.integer(3),
    der.set(sha256AlgId),
    der.seq(der.oid(OID_TST_INFO), der.ctx(0, der.octetString(tstInfo))),
    der.ctx(0, tsa.der),
    der.set(signerInfo),
  );
  const token = der.seq(der.oid(OID_PKCS7_SIGNED_DATA), der.ctx(0, signedData));
  return der.seq(der.seq(der.integer(0)), token);
}

export async function startMockCertum(options: MockCertumOptions): Promise<MockCertum> {
  const requests: RequestRecord[] = [];
  const usedCodes: string[] = [];
  const signedDigests: string[] = [];
  const accessTokens: string[] = [];
  const tasks = new Map<string, Task>();
  const pendingAuthCodes = new Set<string>();
  const sessions = new Set<string>(); // TGT cookie values
  const serial = options.cardSerial ?? '1234567890';
  const execution = `e1s1_${randomBytes(48).toString('base64url')}`;
  let baseUrl = '';

  const json = (res: ServerResponse, status: number, value: unknown, headers: Record<string, string> = {}): void => {
    res.writeHead(status, { 'content-type': 'application/json;charset=UTF-8', ...headers });
    res.end(JSON.stringify(value));
  };
  const redirect = (res: ServerResponse, location: string, headers: Record<string, string> = {}): void => {
    res.writeHead(302, { location, ...headers });
    res.end();
  };
  const cookies = (req: IncomingMessage): Map<string, string> => {
    const out = new Map<string, string>();
    for (const pair of (req.headers.cookie ?? '').split(';')) {
      const [k, ...v] = pair.trim().split('=');
      if (k) out.set(k, v.join('='));
    }
    return out;
  };
  const link = (path: string): string => (options.foreignAtomLink ? `${options.foreignAtomLink}${path}` : path);

  /** Register an async task: 202 → poll (303) → result. */
  const startTask = (res: ServerResponse, kind: string, result: Task): void => {
    const id = randomBytes(6).toString('hex');
    tasks.set(id, result);
    json(res, 202, { state: 'pending', 'atom:link': link(`/scs1/${kind}/task/${id}`), message: 'created', 'ping-after': 20 });
  };

  const bearerOk = (req: IncomingMessage): boolean => {
    const auth = req.headers.authorization ?? '';
    return auth.startsWith('Bearer ') && accessTokens.includes(auth.slice(7));
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? '/', baseUrl);
    requests.push({ method: req.method ?? '', path: url.pathname, headers: req.headers });
    const body = await readBody(req);

    // ---- CAS / OAuth ----
    if (url.pathname === '/idp/oauth2.0/authorize' && req.method === 'GET') {
      const tgc = cookies(req).get('TGC');
      if (tgc && sessions.has(tgc)) {
        const code = `OC-${randomBytes(12).toString('hex')}`;
        pendingAuthCodes.add(code);
        redirect(res, `${url.searchParams.get('redirect_uri')}?code=${code}`);
        return;
      }
      const service = `${baseUrl}/idp/oauth2.0/callbackAuthorize?client_id=${url.searchParams.get('client_id')}&redirect_uri=${encodeURIComponent(url.searchParams.get('redirect_uri') ?? '')}&client_name=CasOAuthClient`;
      redirect(res, `/idp/login?service=${encodeURIComponent(service)}`, { 'set-cookie': 'JSESSIONID=sess-' + randomBytes(8).toString('hex') + '; Path=/idp; HttpOnly' });
      return;
    }
    if (url.pathname === '/idp/login' && req.method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html;charset=UTF-8' });
      res.end(
        `<html><body><form method="post"><input type="hidden" value="${execution}" name="execution"/><input type="hidden" name="lt" value="LT-1"/>` +
          `<input name="username"/><input name="password" type="password"/></form></body></html>`,
      );
      return;
    }
    if (url.pathname === '/idp/login' && req.method === 'POST') {
      const form = new URLSearchParams(body.toString('utf8'));
      const code = form.get('password') ?? '';
      const ok =
        form.get('username') === options.email && form.get('execution') === execution && form.get('_eventId') === 'submit' && !usedCodes.includes(code) && options.acceptCode(code);
      if (!ok) {
        res.writeHead(200, { 'content-type': 'text/html;charset=UTF-8' });
        res.end('<html><body><div id="msg" class="errors"><span>The credentials you provided cannot be determined to be authentic.</span></div></body></html>');
        return;
      }
      usedCodes.push(code);
      const tgc = `TGT-${randomBytes(16).toString('hex')}`;
      sessions.add(tgc);
      const service = url.searchParams.get('service') ?? '';
      redirect(res, `${service}&ticket=ST-${randomBytes(8).toString('hex')}`, { 'set-cookie': `TGC=${tgc}; Path=/idp; Secure; HttpOnly` });
      return;
    }
    if (url.pathname === '/idp/oauth2.0/callbackAuthorize' && req.method === 'GET') {
      redirect(res, `/idp/oauth2.0/authorize?response_type=code&client_id=${url.searchParams.get('client_id')}&redirect_uri=${encodeURIComponent(url.searchParams.get('redirect_uri') ?? '')}`);
      return;
    }
    if (url.pathname === '/idp/oauth2.0/accessToken' && req.method === 'POST') {
      const code = url.searchParams.get('code') ?? '';
      if (!pendingAuthCodes.delete(code) || url.searchParams.get('client_id') !== TEST_CLIENT_ID || url.searchParams.get('grant_type') !== 'authorization_code') {
        json(res, 400, { error: 'invalid_grant' });
        return;
      }
      const token = `AT-${randomBytes(24).toString('hex')}`;
      accessTokens.push(token);
      json(res, 200, { access_token: token, token_type: 'bearer', expires_in: 1800, refresh_token: `RT-${randomBytes(24).toString('hex')}` });
      return;
    }

    // ---- SCS (bearer protected) ----
    if (url.pathname.startsWith('/card/') || url.pathname.startsWith('/scs1/')) {
      if (!bearerOk(req)) {
        json(res, 401, { error: 'unauthorized' });
        return;
      }
      const task = /^\/scs1\/(.+)\/task\/([0-9a-f]+)$/.exec(url.pathname);
      if (task) {
        json(res, 303, { state: 'ready', 'atom:link': link(`/scs1/${task[1]}/result/${task[2]}`), message: 'done' });
        return;
      }
      const result = /^\/scs1\/(.+)\/result\/([0-9a-f]+)$/.exec(url.pathname);
      if (result) {
        const t = tasks.get(result[2] ?? '');
        if (!t) {
          json(res, 404, { error: 'no such task' });
          return;
        }
        res.writeHead(t.status, { 'content-type': t.contentType });
        res.end(t.body);
        return;
      }
      if (url.pathname === '/card/v1/cards/tasks' && req.method === 'POST') {
        const cards = [{ profile: 'CodeSigning', label: 'Code Signing card', cardno: serial, pinrequired: options.pinRequired ?? false, maxkeysno: 1, validthru: '2030-12-31' }];
        for (let i = 0; i < (options.extraCards ?? 0); i++) cards.push({ ...cards[0]!, label: `Other card ${i + 1}`, cardno: `${serial}${i + 1}` });
        startTask(res, 'card/v1/cards', { status: 200, contentType: 'application/json;charset=UTF-8', body: Buffer.from(JSON.stringify(cards)) });
        return;
      }
      if (url.pathname === `/card/v1/cards/${serial}/certificates/tasks` && req.method === 'POST') {
        const boundary = `----MockBoundary${randomBytes(8).toString('hex')}`;
        const multipart = Buffer.concat([
          Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="certificate"; filename="cert.pem"\r\nContent-Type: application/octet-stream\r\n\r\n`),
          Buffer.from(options.signingCert.pem),
          Buffer.from(`\r\n--${boundary}\r\nContent-Disposition: form-data; name="res"\r\nContent-Type: application/json\r\n\r\n[{}]\r\n--${boundary}--\r\n`),
        ]);
        startTask(res, `card/v1/cards/${serial}/certificates`, { status: 200, contentType: `multipart/form-data; boundary=${boundary}`, body: multipart });
        return;
      }
      if (url.pathname === `/card/v1/cards/${serial}/certificates/signature` && req.method === 'POST') {
        const reqJson = JSON.parse(multipartPart(body, 'req').toString('utf8')) as { digests: string[]; digesttype: string };
        const certPart = multipartPart(body, 'certificate');
        if (reqJson.digesttype !== 'SHA256' || !certPart.equals(Buffer.from(options.signingCert.pem))) {
          json(res, 400, { state: 'failed', message: 'bad request' });
          return;
        }
        const results: Record<string, string> = {};
        for (const digestHex of reqJson.digests) {
          signedDigests.push(digestHex);
          const signature = options.corruptSignature ? randomBytes(256) : signDigestPkcs1v15Sha256(Buffer.from(digestHex, 'hex'), options.signingCert.privateKey);
          results[digestHex] = signature.toString('hex');
        }
        startTask(res, `card/v1/cards/${serial}/certificates/signature`, { status: 200, contentType: 'application/json;charset=UTF-8', body: Buffer.from(JSON.stringify([results])) });
        return;
      }
      json(res, 404, { error: `no route for ${req.method} ${url.pathname}` });
      return;
    }

    // ---- TSA ----
    if (url.pathname === '/tsa' && req.method === 'POST') {
      if (options.tsaBehaviour === 'garbage') {
        res.writeHead(200, { 'content-type': 'application/timestamp-reply' });
        res.end(Buffer.from('this is not a timestamp'));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/timestamp-reply' });
      res.end(buildTimeStampResp(body, options.tsaCert, options.tsaBehaviour ?? 'ok'));
      return;
    }

    res.writeHead(404, { 'content-type': 'text/plain' });
    res.end('not found');
  };

  const server: Server = createServer((req, res) => {
    handle(req, res).catch((err: unknown) => {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end(`mock error: ${err instanceof Error ? err.stack ?? err.message : String(err)}`);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('mock server did not bind');
  baseUrl = `http://127.0.0.1:${address.port}`;

  const endpoints: SigningEndpoints = {
    apiBase: baseUrl,
    oauth: {
      authorizeUrl: `${baseUrl}/idp/oauth2.0/authorize`,
      loginUrl: `${baseUrl}/idp/login`,
      tokenUrl: `${baseUrl}/idp/oauth2.0/accessToken`,
      scope: `${baseUrl}/idp/oauth2.0/profile`,
      redirectUri: `${baseUrl}/redirect`,
      clientId: TEST_CLIENT_ID,
      clientSecret: 'test-client-secret',
    },
  };

  return {
    baseUrl,
    endpoints,
    tsaUrl: `${baseUrl}/tsa`,
    requests,
    usedCodes,
    signedDigests,
    accessTokens,
    close: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
  };
}
