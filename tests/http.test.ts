import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { test } from 'node:test';
import { CookieJar, HttpClient, HttpError, bodySnippet, redactUrl } from '../src/http.ts';

async function withServer(handler: (req: IncomingMessage, res: ServerResponse, body: string) => void, fn: (base: string) => Promise<void>): Promise<void> {
  const server: Server = createServer((req, res) => {
    let body = '';
    req.on('data', (c: Buffer) => (body += c.toString()));
    req.on('end', () => handler(req, res, body));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('no address');
  try {
    await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('redactUrl and bodySnippet never leak query strings or control characters', () => {
  assert.equal(redactUrl('https://idp.example/idp/login?service=x&ticket=ST-secret'), 'https://idp.example/idp/login');
  assert.equal(redactUrl('nonsense'), '<invalid url>');
  assert.equal(bodySnippet(Buffer.from('a\x00b\r\n c')), 'a b c');
  assert.equal(bodySnippet(Buffer.from('x'.repeat(300))).length, 201);
  assert.equal(new HttpError('m', 'https://a.example/p?code=1').url, 'https://a.example/p');
});

test('the cookie jar is per origin and keeps the latest value', () => {
  const jar = new CookieJar();
  jar.store('https://a.example', ['JSESSIONID=one; Path=/; HttpOnly', 'TGC=tgt-1; Secure']);
  jar.store('https://a.example', ['TGC=tgt-2']);
  jar.store('https://b.example', ['x=y']);
  assert.equal(jar.header('https://a.example'), 'JSESSIONID=one; TGC=tgt-2');
  assert.equal(jar.header('https://b.example'), 'x=y');
  assert.equal(jar.header('https://c.example'), undefined);
  assert.deepEqual(jar.values().sort(), ['one', 'tgt-2', 'y']);
  jar.clear();
  assert.equal(jar.header('https://a.example'), undefined);
});

test('requests outside the allowlist or over plain http to remote hosts are refused before any I/O', async () => {
  const http = new HttpClient({ userAgent: 'test', timeoutMs: 1000, allowedOrigins: ['https://api.example', 'http://127.0.0.1:9'] });
  await assert.rejects(http.fetch('https://evil.example/x'), /not one of the configured origins/);
  await assert.rejects(http.fetch('http://api.example/x'), /not one of the configured origins/);
  const plain = new HttpClient({ userAgent: 'test', timeoutMs: 1000, allowedOrigins: ['http://time.example'] });
  await assert.rejects(plain.fetch('http://time.example/'), /only https is allowed/);
  const tsa = new HttpClient({ userAgent: 'test', timeoutMs: 1000, allowedOrigins: ['http://time.example'], allowHttp: true });
  assert.doesNotThrow(() => tsa.assertAllowed(new URL('http://time.example/')));
});

test('follow() walks redirects by hand: same origin, hop limit, POST→GET, cookies, early stop', async () => {
  const log: string[] = [];
  await withServer((req, res, body) => {
    log.push(`${req.method} ${req.url} cookie=${req.headers.cookie ?? '-'} body=${body}`);
    switch (req.url) {
      case '/start':
        res.writeHead(302, { location: '/second', 'set-cookie': 'sid=abc; Path=/' });
        return res.end();
      case '/second':
        res.writeHead(303, { location: '/third' });
        return res.end();
      case '/third':
        res.writeHead(200, { 'content-type': 'text/plain' });
        return res.end(`ok ua=${req.headers['user-agent']}`);
      case '/loop':
        res.writeHead(301, { location: '/loop' });
        return res.end();
      case '/away':
        res.writeHead(302, { location: 'https://evil.example/steal' });
        return res.end();
      case '/code':
        res.writeHead(302, { location: 'https://app.example/redirect?code=SECRET' });
        return res.end();
      case '/nolocation':
        res.writeHead(302);
        return res.end();
      default:
        res.writeHead(404);
        return res.end();
    }
  }, async (base) => {
    const http = new HttpClient({ userAgent: 'sss-test', timeoutMs: 5000, allowedOrigins: [base] });
    const done = await http.follow(`${base}/start`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'payload' }, { maxHops: 5 });
    assert.equal(done.status, 200);
    assert.equal(done.body.toString(), 'ok ua=sss-test');
    assert.deepEqual(done.hops, [`${base}/second`, `${base}/third`]);
    assert.equal(done.stoppedAt, null);
    assert.deepEqual(log, [
      'POST /start cookie=- body=payload',
      'GET /second cookie=sid=abc body=',
      'GET /third cookie=sid=abc body=',
    ]);

    await assert.rejects(http.follow(`${base}/loop`, {}, { maxHops: 3 }), /too many redirects/);
    await assert.rejects(http.follow(`${base}/away`), /not one of the configured origins/);
    await assert.rejects(http.follow(`${base}/nolocation`), /no Location header/);

    log.length = 0;
    const stopped = await http.follow(`${base}/code`, {}, { onRedirect: (target) => target.searchParams.has('code') });
    assert.equal(stopped.status, 302);
    assert.equal(stopped.stoppedAt?.searchParams.get('code'), 'SECRET');
    assert.equal(log.length, 1, 'the redirect target carrying the code must never be requested');
  });
});

test('a hanging server hits the timeout with a redacted error', async () => {
  await withServer(() => undefined, async (base) => {
    const http = new HttpClient({ userAgent: 'test', timeoutMs: 200, allowedOrigins: [base] });
    await assert.rejects(http.fetch(`${base}/hang?secret=1`), (err: unknown) => err instanceof HttpError && /timed out/.test(err.message) && !err.message.includes('secret'));
  });
});
