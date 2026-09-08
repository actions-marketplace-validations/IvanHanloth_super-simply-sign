/**
 * A small DER (X.690) encoder/decoder — just enough to hand-build the
 * Microsoft Authenticode / PKCS#7 / RFC 3161 structures this action needs,
 * and to walk the ones it receives. No general-purpose ASN.1 library is
 * pulled in on purpose: the surface we need is tiny and every byte of it is
 * covered by tests, which keeps the supply chain of a *signing* tool short.
 */

export class DerError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DerError';
  }
}

/** Buffer view over any Uint8Array without copying. */
export function asBuffer(bytes: Uint8Array): Buffer {
  return Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export function concat(...parts: Uint8Array[]): Buffer {
  return Buffer.concat(parts);
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && asBuffer(a).equals(asBuffer(b));
}

// ---- encoding -------------------------------------------------------------

export function encodeLength(n: number): Buffer {
  if (!Number.isSafeInteger(n) || n < 0) throw new DerError(`invalid DER length ${n}`);
  if (n < 0x80) return Buffer.from([n]);
  const octets: number[] = [];
  let v = n;
  while (v > 0) {
    octets.unshift(v % 256);
    v = Math.floor(v / 256);
  }
  return Buffer.from([0x80 | octets.length, ...octets]);
}

/** A complete tag-length-value over `content`. Single-byte tags only. */
export function tlv(tag: number, content: Uint8Array): Buffer {
  if (tag < 0 || tag > 0xff || (tag & 0x1f) === 0x1f) throw new DerError(`unsupported tag 0x${tag.toString(16)}`);
  return Buffer.concat([Buffer.from([tag]), encodeLength(content.length), content]);
}

export const seq = (...parts: Uint8Array[]): Buffer => tlv(0x30, concat(...parts));

/** SET with the members in the order given (callers must know it is right). */
export const set = (...parts: Uint8Array[]): Buffer => tlv(0x31, concat(...parts));

/** X.690 §11.6 ordering: compare encodings, the shorter one padded with zeros. */
export function derCompare(a: Uint8Array, b: Uint8Array): number {
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    const x = i < a.length ? a[i]! : 0;
    const y = i < b.length ? b[i]! : 0;
    if (x !== y) return x - y;
  }
  return a.length - b.length;
}

/** DER SET OF: members sorted ascending by their encodings. */
export function setOf(parts: Uint8Array[]): Buffer {
  return tlv(0x31, concat(...[...parts].sort(derCompare)));
}

export const octetString = (v: Uint8Array): Buffer => tlv(0x04, v);
export const nul = (): Buffer => Buffer.from([0x05, 0x00]);
export const boolTrue = (): Buffer => Buffer.from([0x01, 0x01, 0xff]);

/** INTEGER from a non-negative number/bigint, or from an unsigned big-endian magnitude. */
export function integer(v: number | bigint | Uint8Array): Buffer {
  if (v instanceof Uint8Array) {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    let body = v.length === 0 ? Buffer.from([0]) : Buffer.from(v.subarray(i));
    if (body[0]! & 0x80) body = Buffer.concat([Buffer.from([0]), body]);
    return tlv(0x02, body);
  }
  const n = BigInt(v);
  if (n < 0n) throw new DerError('negative INTEGER values are not supported');
  const hex = n.toString(16);
  return integer(Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex'));
}

/** The unsigned magnitude of a DER INTEGER, leading zero stripped. */
export function integerMagnitude(t: Tlv): Buffer {
  if (t.tag !== 0x02 || t.length === 0) throw new DerError('expected a DER INTEGER');
  if (t.content[0]! & 0x80) throw new DerError('negative INTEGER values are not supported');
  let i = 0;
  while (i < t.content.length - 1 && t.content[i] === 0) i++;
  return Buffer.from(t.content.subarray(i));
}

export function integerValue(t: Tlv): bigint {
  return BigInt(`0x${integerMagnitude(t).toString('hex')}`);
}

export function oid(dotted: string): Buffer {
  const arcs = dotted.split('.').map((p) => {
    if (!/^\d+$/.test(p)) throw new DerError(`invalid OID "${dotted}"`);
    return BigInt(p);
  });
  const first = arcs[0];
  const second = arcs[1];
  if (first === undefined || second === undefined || first > 2n || (first < 2n && second >= 40n)) {
    throw new DerError(`invalid OID "${dotted}"`);
  }
  const body: number[] = [];
  const push = (value: bigint): void => {
    const stack = [Number(value & 0x7fn)];
    let n = value >> 7n;
    while (n > 0n) {
      stack.push(Number(n & 0x7fn) | 0x80);
      n >>= 7n;
    }
    body.push(...stack.reverse());
  };
  push(first * 40n + second);
  for (const arc of arcs.slice(2)) push(arc);
  return tlv(0x06, Buffer.from(body));
}

export function decodeOid(t: Tlv): string {
  if (t.tag !== 0x06 || t.length === 0) throw new DerError('expected an OBJECT IDENTIFIER');
  const content = t.content;
  if (content[content.length - 1]! & 0x80) throw new DerError('truncated OBJECT IDENTIFIER');
  const arcs: bigint[] = [];
  let n = 0n;
  for (const b of content) {
    n = (n << 7n) | BigInt(b & 0x7f);
    if ((b & 0x80) === 0) {
      arcs.push(n);
      n = 0n;
    }
  }
  const head = arcs[0]!;
  const first = head < 40n ? 0n : head < 80n ? 1n : 2n;
  const second = head - first * 40n;
  return [first, second, ...arcs.slice(1)].join('.');
}

/** Context-specific constructed tag `[n]`. */
export const ctx = (n: number, content: Uint8Array): Buffer => tlv(0xa0 | n, content);
/** Context-specific primitive tag `[n]`. */
export const ctxPrim = (n: number, content: Uint8Array): Buffer => tlv(0x80 | n, content);

export function bitString(bytes: Uint8Array, unusedBits = 0): Buffer {
  if (unusedBits < 0 || unusedBits > 7) throw new DerError('unusedBits must be 0..7');
  return tlv(0x03, concat(Buffer.from([unusedBits]), bytes));
}

export function ia5String(s: string): Buffer {
  if (!/^[\x00-\x7f]*$/.test(s)) throw new DerError('IA5String must be ASCII');
  return tlv(0x16, Buffer.from(s, 'latin1'));
}

/** BMPString (UTF-16BE). */
export function bmpString(s: string): Buffer {
  return tlv(0x1e, utf16be(s));
}

export function utf16be(s: string): Buffer {
  const out = Buffer.alloc(s.length * 2);
  for (let i = 0; i < s.length; i++) out.writeUInt16BE(s.charCodeAt(i), i * 2);
  return out;
}

export const utf8String = (s: string): Buffer => tlv(0x0c, Buffer.from(s, 'utf8'));
export const printableString = (s: string): Buffer => tlv(0x13, Buffer.from(s, 'latin1'));

const pad2 = (n: number): string => n.toString().padStart(2, '0');

function timeDigits(d: Date): string {
  return `${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}${pad2(d.getUTCHours())}${pad2(d.getUTCMinutes())}${pad2(d.getUTCSeconds())}Z`;
}

/** UTCTime `YYMMDDhhmmssZ` (only representable for 1950..2049). */
export function utcTime(d: Date): Buffer {
  const y = d.getUTCFullYear();
  if (y < 1950 || y > 2049) throw new DerError('UTCTime can only represent 1950..2049');
  return tlv(0x17, Buffer.from(`${pad2(y % 100)}${timeDigits(d)}`, 'latin1'));
}

/** GeneralizedTime `YYYYMMDDhhmmssZ`. */
export function generalizedTime(d: Date): Buffer {
  return tlv(0x18, Buffer.from(`${d.getUTCFullYear().toString().padStart(4, '0')}${timeDigits(d)}`, 'latin1'));
}

/** X.509/CMS `Time`: UTCTime while it can express the year, GeneralizedTime after 2049. */
export function time(d: Date): Buffer {
  const y = d.getUTCFullYear();
  return y >= 1950 && y <= 2049 ? utcTime(d) : generalizedTime(d);
}

/** Decode a UTCTime or GeneralizedTime (with optional fractional seconds) to a Date. */
export function decodeTime(t: Tlv): Date {
  const s = t.content.toString('latin1');
  if (t.tag === 0x17) {
    const m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$/.exec(s);
    if (!m) throw new DerError(`malformed UTCTime "${s}"`);
    const yy = Number(m[1]);
    const year = yy >= 50 ? 1900 + yy : 2000 + yy;
    return new Date(Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? '0')));
  }
  if (t.tag === 0x18) {
    const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:[.,](\d+))?Z$/.exec(s);
    if (!m) throw new DerError(`malformed GeneralizedTime "${s}"`);
    const ms = m[7] ? Math.round(Number(`0.${m[7]}`) * 1000) : 0;
    return new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6] ?? '0'), ms));
  }
  throw new DerError(`expected a time value, got tag 0x${t.tag.toString(16)}`);
}

// ---- decoding -------------------------------------------------------------

export interface Tlv {
  /** The full identifier octet. */
  readonly tag: number;
  readonly tagClass: 0 | 1 | 2 | 3;
  readonly tagNumber: number;
  readonly constructed: boolean;
  readonly headerLength: number;
  /** Content length in octets. */
  readonly length: number;
  /** The complete TLV (header + content), as a view into the source buffer. */
  readonly raw: Buffer;
  /** The content octets, as a view into the source buffer. */
  readonly content: Buffer;
  /** Offset just past this TLV, relative to the buffer it was read from. */
  readonly end: number;
}

/**
 * Read one TLV at `offset`. Indefinite lengths (BER) and multi-byte tags are
 * rejected; non-minimal length encodings are tolerated because everything we
 * parse is either used as opaque bytes or re-checked field by field.
 */
export function readTlv(bytes: Uint8Array, offset = 0): Tlv {
  const b = asBuffer(bytes);
  if (offset < 0 || offset + 2 > b.length) throw new DerError('unexpected end of DER data');
  const tag = b[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError('multi-byte DER tags are not supported');
  const first = b[offset + 1]!;
  let length: number;
  let headerLength: number;
  if (first < 0x80) {
    length = first;
    headerLength = 2;
  } else {
    const n = first & 0x7f;
    if (n === 0) throw new DerError('indefinite-length encoding is not DER');
    if (n > 4) throw new DerError('DER length is too large');
    if (offset + 2 + n > b.length) throw new DerError('truncated DER length');
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + b[offset + 2 + i]!;
    headerLength = 2 + n;
  }
  const contentStart = offset + headerLength;
  const end = contentStart + length;
  if (end > b.length) throw new DerError('truncated DER value');
  return {
    tag,
    tagClass: (tag >> 6) as 0 | 1 | 2 | 3,
    tagNumber: tag & 0x1f,
    constructed: (tag & 0x20) !== 0,
    headerLength,
    length,
    raw: b.subarray(offset, end),
    content: b.subarray(contentStart, end),
    end,
  };
}

/** Parse a buffer that must contain exactly one TLV (no trailing bytes). */
export function readExact(bytes: Uint8Array): Tlv {
  const t = readTlv(bytes, 0);
  if (t.end !== bytes.length) throw new DerError('trailing bytes after DER value');
  return t;
}

/** Split a constructed value into its child TLVs. */
export function children(t: Tlv | Uint8Array): Tlv[] {
  const content = t instanceof Uint8Array ? readExact(t).content : t.content;
  const out: Tlv[] = [];
  let offset = 0;
  while (offset < content.length) {
    const child = readTlv(content, offset);
    out.push(child);
    offset = child.end;
  }
  return out;
}

export function expectTag(t: Tlv | undefined, tag: number, what: string): Tlv {
  if (!t) throw new DerError(`missing ${what}`);
  if (t.tag !== tag) throw new DerError(`${what}: expected tag 0x${tag.toString(16)}, got 0x${t.tag.toString(16)}`);
  return t;
}

/** Content of an OCTET STRING, or throw. */
export function octets(t: Tlv | undefined, what: string): Buffer {
  return expectTag(t, 0x04, what).content;
}
