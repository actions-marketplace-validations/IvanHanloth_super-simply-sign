/**
 * Steps 2 and 4 — the Certum SCS ("SimplySign Cloud Signing") REST surface:
 * the async task protocol every endpoint speaks, the card + certificate
 * lookup, and the SCS1_ATOM signature request.
 *
 *   POST …/tasks               → 202 {"atom:link": <poll url>, "ping-after": ms}
 *   GET  <poll url>            → 303 {"atom:link": <result url>}   (when ready)
 *   GET  <result url>          → 200 <the payload>
 *
 * `runTask` drives that loop. It only ever follows links on the API origin,
 * so the bearer token cannot be coaxed to another host by a crafted link.
 */
import { randomBytes } from 'node:crypto';
import { asBuffer } from './der.ts';
import { bodySnippet, redactUrl, type HttpClient, type HttpRequest } from './http.ts';
import type { Logger } from './log.ts';

export class ScsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScsError';
  }
}

export interface ScsClient {
  readonly http: HttpClient;
  readonly apiBase: string;
  readonly token: string;
  readonly log: Logger;
  readonly pollLimit?: number;
  readonly taskTimeoutMs?: number;
}

const ACCEPT = 'multipart/form-data, application/json';
const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));
const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

function tryJson(body: Uint8Array): unknown {
  try {
    return JSON.parse(Buffer.from(body).toString('utf8'));
  } catch {
    return undefined;
  }
}

/** Resolve an absolute or root-relative `atom:link`, refusing any other origin. */
export function resolveLink(apiBase: string, link: string): URL {
  const base = new URL(apiBase);
  let url: URL;
  try {
    url = new URL(link, base);
  } catch {
    throw new ScsError('the cloud returned an invalid atom:link');
  }
  if (url.origin !== base.origin) throw new ScsError(`refusing to follow an atom:link outside ${base.origin}`);
  return url;
}

function authHeaders(client: ScsClient, extra?: Readonly<Record<string, string>>): Record<string, string> {
  return { ...extra, accept: ACCEPT, authorization: `Bearer ${client.token}` };
}

/**
 * Send the initial request, then follow `atom:link` until a response no
 * longer carries one — that final response *is* the result.
 */
export async function runTask(client: ScsClient, url: string | URL, request: HttpRequest): Promise<{ contentType: string; body: Buffer }> {
  const deadline = Date.now() + (client.taskTimeoutMs ?? 5 * 60_000);
  const pollLimit = client.pollLimit ?? 120;
  let response = await client.http.fetch(url, { ...request, headers: authHeaders(client, request.headers) });
  for (let poll = 0; poll <= pollLimit; poll++) {
    const contentType = response.headers.get('content-type') ?? '';
    if (response.status >= 400) {
      throw new ScsError(`cloud task failed (HTTP ${response.status}) at ${redactUrl(response.url)}: ${bodySnippet(response.body)}`);
    }
    let next: URL | null = null;
    let pingAfter = 0;
    if (!contentType.includes('multipart')) {
      const value = tryJson(response.body);
      if (isRecord(value)) {
        if (value['state'] === 'failed') throw new ScsError(`the cloud rejected the task: ${bodySnippet(response.body)}`);
        const link = value['atom:link'];
        if (typeof link === 'string') {
          next = resolveLink(client.apiBase, link);
          pingAfter = typeof value['ping-after'] === 'number' ? value['ping-after'] : 0;
        }
      }
      if (!next && response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (location) next = resolveLink(client.apiBase, location);
      }
    }
    if (!next) return { contentType, body: response.body };
    if (Date.now() > deadline) throw new ScsError('the cloud task did not complete in time');
    await sleep(Math.min(Math.max(pingAfter, 200), 2000));
    response = await client.http.fetch(next, { method: 'GET', headers: authHeaders(client) });
  }
  throw new ScsError(`the cloud task did not complete after ${pollLimit} polls`);
}

// ---- multipart ------------------------------------------------------------

/** The raw bytes of the part named `name` in a `multipart/form-data` body. */
export function multipartPart(body: Uint8Array, name: string): Buffer {
  const b = asBuffer(body);
  const firstLineEnd = b.indexOf('\r\n');
  if (firstLineEnd < 0) throw new ScsError('multipart body has no CRLF');
  const delimiter = b.subarray(0, firstLineEnd);
  if (!delimiter.toString('latin1').startsWith('--')) throw new ScsError('multipart body does not start with a boundary');
  const separator = Buffer.concat([Buffer.from('\r\n'), delimiter]);

  let pos = delimiter.length;
  while (pos + 2 <= b.length) {
    if (b[pos] === 0x2d && b[pos + 1] === 0x2d) break; // closing delimiter "--"
    if (b[pos] !== 0x0d || b[pos + 1] !== 0x0a) throw new ScsError('malformed multipart boundary line');
    pos += 2;
    const next = b.indexOf(separator, pos);
    if (next < 0) throw new ScsError('multipart body has no closing boundary');
    const part = b.subarray(pos, next);
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd >= 0) {
      const headers = part.subarray(0, headerEnd).toString('latin1');
      const disposition = /content-disposition:\s*([^\r\n]*)/i.exec(headers)?.[1] ?? '';
      const partName = /\bname="([^"]*)"/i.exec(disposition)?.[1];
      if (partName === name) return Buffer.from(part.subarray(headerEnd + 4));
    }
    pos = next + separator.length;
  }
  throw new ScsError(`multipart part "${name}" not found`);
}

export interface MultipartPart {
  readonly name: string;
  readonly filename?: string;
  readonly contentType: string;
  readonly data: Uint8Array | string;
}

export function buildMultipart(parts: readonly MultipartPart[]): { contentType: string; body: Buffer } {
  const boundary = `----SuperSimplySign${randomBytes(16).toString('hex')}`;
  const chunks: Buffer[] = [];
  for (const part of parts) {
    const filename = part.filename ? `; filename="${part.filename}"` : '';
    chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${part.name}"${filename}\r\nContent-Type: ${part.contentType}\r\n\r\n`, 'latin1'));
    chunks.push(typeof part.data === 'string' ? Buffer.from(part.data, 'utf8') : asBuffer(part.data));
    chunks.push(Buffer.from('\r\n'));
  }
  chunks.push(Buffer.from(`--${boundary}--\r\n`, 'latin1'));
  return { contentType: `multipart/form-data; boundary=${boundary}`, body: Buffer.concat(chunks) };
}

// ---- cards & certificates -------------------------------------------------

export interface CardEntry {
  readonly serial: string;
  readonly label: string | null;
  readonly profile: string | null;
  readonly validThru: string | null;
  readonly pinRequired: boolean | null;
}

export interface CloudCard {
  /** `cardno`, used in the per-card URLs. */
  readonly serial: string;
  readonly label: string | null;
  /** The signing certificate exactly as the cloud returned it (PEM). The sign request wants it back verbatim. */
  readonly certificateRaw: Buffer;
}

const SERIAL_PATTERN = /^[A-Za-z0-9._-]{1,128}$/;
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);

export async function listCards(client: ScsClient): Promise<CardEntry[]> {
  const { body } = await runTask(client, `${client.apiBase}/card/v1/cards/tasks`, { method: 'POST', headers: { 'content-type': 'application/json' } });
  const value = tryJson(body);
  if (!Array.isArray(value)) throw new ScsError(`the card list was not a JSON array: ${bodySnippet(body)}`);
  return value
    .filter(isRecord)
    .map((c) => ({
      serial: str(c['cardno']) ?? '',
      label: str(c['label']),
      profile: str(c['profile']),
      validThru: str(c['validthru']),
      pinRequired: typeof c['pinrequired'] === 'boolean' ? c['pinrequired'] : null,
    }))
    .filter((c) => c.serial.length > 0);
}

/** Pick the signing card (the first one, or the one with `wantedSerial`) and fetch its certificate. */
export async function fetchCard(client: ScsClient, wantedSerial?: string): Promise<CloudCard> {
  const cards = await listCards(client);
  if (cards.length === 0) throw new ScsError('the account has no signing card');
  const card = wantedSerial ? cards.find((c) => c.serial === wantedSerial) : cards[0];
  if (!card) throw new ScsError(`the account has no card with serial "${wantedSerial}" (${cards.length} card(s) available)`);
  if (!SERIAL_PATTERN.test(card.serial)) throw new ScsError('the card serial has an unexpected format');
  if (card.pinRequired === true) throw new ScsError('this card requires a PIN, which the SimplySign HTTPS flow cannot supply');
  if (cards.length > 1 && !wantedSerial) {
    client.log.warning(`the account has ${cards.length} cards; using "${card.label ?? card.serial}" — set card-serial to pick another one`);
  }

  const { contentType, body } = await runTask(client, `${client.apiBase}/card/v1/cards/${encodeURIComponent(card.serial)}/certificates/tasks`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
  });
  if (!contentType.includes('multipart')) {
    throw new ScsError(`unexpected certificate response (${contentType || 'no content type'}): ${bodySnippet(body)}`);
  }
  return { serial: card.serial, label: card.label, certificateRaw: multipartPart(body, 'certificate') };
}

// ---- signing --------------------------------------------------------------

/** Ask the cloud HSM to sign one SHA-256 digest; returns the raw RSA PKCS#1 v1.5 signature. */
export async function requestSignature(client: ScsClient, card: CloudCard, digest: Uint8Array): Promise<Buffer> {
  if (digest.length !== 32) throw new ScsError('only SHA-256 digests can be sent for signing');
  const digestHex = asBuffer(digest).toString('hex');
  const { contentType, body } = buildMultipart([
    { name: 'req', contentType: 'application/json;charset=UTF-8', data: JSON.stringify({ digests: [digestHex], digesttype: 'SHA256' }) },
    { name: 'certificate', filename: 'blob', contentType: 'application/octet-stream', data: card.certificateRaw },
  ]);
  const result = await runTask(client, `${client.apiBase}/card/v1/cards/${encodeURIComponent(card.serial)}/certificates/signature`, {
    method: 'POST',
    headers: { 'content-type': contentType },
    body,
  });
  return parseSignatureResponse(result.body, digestHex);
}

/** Result shape: `[ { "<digest hex>": "<signature hex>" } ]`. */
export function parseSignatureResponse(body: Uint8Array, digestHex: string): Buffer {
  const value = tryJson(body);
  const first = Array.isArray(value) ? value[0] : undefined;
  if (!isRecord(first)) throw new ScsError(`the signature result was not the expected JSON array: ${bodySnippet(body)}`);
  const wanted = digestHex.toLowerCase();
  const entry = Object.entries(first).find(([digest]) => digest.toLowerCase() === wanted);
  const hex = entry?.[1];
  if (typeof hex !== 'string' || hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new ScsError('the cloud did not return a signature for the requested digest');
  }
  const signature = Buffer.from(hex, 'hex');
  if (signature.length < 256) throw new ScsError(`the returned signature is unexpectedly short (${signature.length} bytes)`);
  return signature;
}
