import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { test } from 'node:test';
import { HttpClient } from '../src/http.ts';
import { silentLogger } from '../src/log.ts';
import { ScsError, buildMultipart, multipartPart, parseSignatureResponse, resolveLink, runTask } from '../src/scs.ts';

test('multipartPart extracts named parts from a multipart/form-data body', () => {
  const body = Buffer.from(
    '----BND\r\nContent-Disposition: form-data; name="certificate"; filename="x.cer"\r\nContent-Type: application/octet-stream\r\n\r\n\x01\x02\x03DER\r\n----BND\r\nContent-Disposition: form-data; name="res"\r\nContent-Type: application/json\r\n\r\n[{}]\r\n----BND--\r\n',
    'latin1',
  );
  assert.equal(multipartPart(body, 'certificate').toString('latin1'), '\x01\x02\x03DER');
  assert.equal(multipartPart(body, 'res').toString(), '[{}]');
  assert.throws(() => multipartPart(body, 'missing'), /not found/);
  assert.throws(() => multipartPart(Buffer.from('no boundary here'), 'x'), ScsError);
});

test('buildMultipart round-trips binary parts that contain CRLF and dashes', () => {
  const binary = Buffer.from('--\r\n\r\n--boundary-like\r\n\x00\xff', 'latin1');
  const { contentType, body } = buildMultipart([
    { name: 'req', contentType: 'application/json;charset=UTF-8', data: '{"digests":["ab"],"digesttype":"SHA256"}' },
    { name: 'certificate', filename: 'blob', contentType: 'application/octet-stream', data: binary },
  ]);
  assert.match(contentType, /^multipart\/form-data; boundary=----SuperSimplySign[0-9a-f]{32}$/);
  assert.equal(multipartPart(body, 'req').toString(), '{"digests":["ab"],"digesttype":"SHA256"}');
  assert.equal(multipartPart(body, 'certificate').equals(binary), true);
  assert.match(body.toString('latin1'), /name="certificate"; filename="blob"\r\nContent-Type: application\/octet-stream/);
});

test('parseSignatureResponse picks the signature for the requested digest', () => {
  const sig = 'ab'.repeat(256);
  const digest = '0123456789abcdef'.repeat(4);
  assert.equal(parseSignatureResponse(Buffer.from(`[{"${digest.toUpperCase()}":"${sig}"}]`), digest).toString('hex'), sig);
  assert.throws(() => parseSignatureResponse(Buffer.from('[{"other":"aa"}]'), digest), /did not return a signature/);
  assert.throws(() => parseSignatureResponse(Buffer.from(`[{"${digest}":"zz"}]`), digest), /did not return a signature/);
  assert.throws(() => parseSignatureResponse(Buffer.from(`[{"${digest}":"abcd"}]`), digest), /unexpectedly short/);
  assert.throws(() => parseSignatureResponse(Buffer.from('{"nope":1}'), digest), /not the expected JSON array/);
});

test('resolveLink keeps atom:links on the API origin', () => {
  assert.equal(resolveLink('https://api.example/', '/scs1/x').toString(), 'https://api.example/scs1/x');
  assert.equal(resolveLink('https://api.example', 'scs1/x').toString(), 'https://api.example/scs1/x');
  assert.equal(resolveLink('https://api.example', 'https://api.example/scs1/y').toString(), 'https://api.example/scs1/y');
  assert.throws(() => resolveLink('https://api.example', 'https://evil.example/scs1/x'), /outside https:\/\/api.example/);
  assert.throws(() => resolveLink('https://api.example', 'http://api.example/scs1/x'), /outside/);
});

async function withServer(handler: Parameters<typeof createServer>[1], fn: (base: string) => Promise<void>): Promise<void> {
  const server: Server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('no address');
  try {
    await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('runTask follows atom:links until the result, honouring ping-after and bearer auth', async () => {
  const seen: string[] = [];
  await withServer((req, res) => {
    seen.push(`${req.method} ${req.url} ${req.headers.authorization}`);
    if (req.url === '/card/v1/cards/tasks') {
      res.writeHead(202, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ state: 'pending', 'atom:link': '/scs1/task/1', 'ping-after': 10 }));
    } else if (req.url === '/scs1/task/1') {
      res.writeHead(303, { 'content-type': 'application/json', location: '/ignored' });
      res.end(JSON.stringify({ state: 'ready', 'atom:link': '/scs1/result/1' }));
    } else if (req.url === '/scs1/result/1') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('[{"cardno":"42"}]');
    } else {
      res.writeHead(404);
      res.end();
    }
  }, async (base) => {
    const http = new HttpClient({ userAgent: 'test', timeoutMs: 5000, allowedOrigins: [base] });
    const { body, contentType } = await runTask({ http, apiBase: base, token: 'tok', log: silentLogger }, `${base}/card/v1/cards/tasks`, { method: 'POST' });
    assert.equal(contentType, 'application/json');
    assert.equal(body.toString(), '[{"cardno":"42"}]');
    assert.deepEqual(seen, ['POST /card/v1/cards/tasks Bearer tok', 'GET /scs1/task/1 Bearer tok', 'GET /scs1/result/1 Bearer tok']);
  });
});

test('runTask surfaces failed tasks, HTTP errors, foreign links and poll limits', async () => {
  await withServer((req, res) => {
    res.setHeader('content-type', 'application/json');
    if (req.url === '/failed') {
      res.writeHead(200);
      res.end(JSON.stringify({ state: 'failed', message: 'no can do' }));
    } else if (req.url === '/http500') {
      res.writeHead(500);
      res.end('{"error":"boom"}');
    } else if (req.url === '/foreign') {
      res.writeHead(202);
      res.end(JSON.stringify({ 'atom:link': 'https://evil.example/steal' }));
    } else if (req.url === '/forever') {
      res.writeHead(202);
      res.end(JSON.stringify({ 'atom:link': '/forever', 'ping-after': 1 }));
    } else if (req.url === '/location-only') {
      res.writeHead(303, { location: '/done' });
      res.end();
    } else if (req.url === '/done') {
      res.writeHead(200);
      res.end('"done"');
    }
  }, async (base) => {
    const http = new HttpClient({ userAgent: 'test', timeoutMs: 5000, allowedOrigins: [base] });
    const client = { http, apiBase: base, token: 't', log: silentLogger, pollLimit: 3 };
    await assert.rejects(runTask(client, `${base}/failed`, { method: 'POST' }), /rejected the task: .*no can do/);
    await assert.rejects(runTask(client, `${base}/http500`, { method: 'POST' }), /HTTP 500/);
    await assert.rejects(runTask(client, `${base}/foreign`, { method: 'POST' }), /outside/);
    await assert.rejects(runTask(client, `${base}/forever`, { method: 'POST' }), /after 3 polls/);
    const { body } = await runTask(client, `${base}/location-only`, { method: 'POST' });
    assert.equal(body.toString(), '"done"');
  });
});
