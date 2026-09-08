/**
 * TOTP (RFC 6238) for the seed-based login path.
 *
 * Certum's SimplySign authenticator uses SHA-256 (not the SHA-1 most TOTP
 * libraries default to), 6 digits and a 30 s period. The seed may be given as
 * a full `otpauth://totp/...` URI (self-describing) or as a bare base32
 * secret, in which case the Certum defaults apply.
 */
import { createHmac } from 'node:crypto';

export class TotpError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TotpError';
  }
}

export type TotpAlgorithm = 'sha1' | 'sha256' | 'sha512';

export interface TotpParams {
  readonly secret: Buffer;
  readonly algorithm: TotpAlgorithm;
  readonly digits: number;
  readonly period: number;
}

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32, case-insensitive; whitespace, dashes and `=` padding are ignored. */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/[\s=-]/g, '');
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) throw new TotpError('the TOTP secret is not valid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}

/** Parse an `otpauth://totp/...` URI or a bare base32 secret. */
export function parseTotpSecret(input: string): TotpParams {
  const trimmed = input.trim();
  let secretB32 = trimmed;
  let algorithm: TotpAlgorithm = 'sha256';
  let digits = 6;
  let period = 30;

  if (/^otpauth:\/\//i.test(trimmed)) {
    let url: URL;
    try {
      url = new URL(trimmed);
    } catch {
      throw new TotpError('malformed otpauth:// URI');
    }
    if (url.host.toLowerCase() !== 'totp') throw new TotpError(`unsupported otpauth type "${url.host}" (only totp is supported)`);
    const params = url.searchParams;
    const secret = params.get('secret');
    if (!secret) throw new TotpError('the otpauth:// URI carries no secret');
    secretB32 = secret;
    const algo = params.get('algorithm');
    if (algo) {
      const norm = algo.toLowerCase().replace('-', '');
      if (norm !== 'sha1' && norm !== 'sha256' && norm !== 'sha512') throw new TotpError(`unsupported TOTP algorithm "${algo}"`);
      algorithm = norm;
    }
    const d = params.get('digits');
    if (d) {
      digits = Number(d);
      if (!Number.isInteger(digits) || digits < 6 || digits > 10) throw new TotpError(`unsupported TOTP digits "${d}"`);
    }
    const p = params.get('period');
    if (p) {
      period = Number(p);
      if (!Number.isInteger(period) || period < 1 || period > 300) throw new TotpError(`unsupported TOTP period "${p}"`);
    }
  }

  const secret = base32Decode(secretB32);
  if (secret.length === 0) throw new TotpError('the TOTP secret is empty');
  return { secret, algorithm, digits, period };
}

/** The code for the window containing `unixSeconds` (RFC 4226 dynamic truncation). */
export function totpCode(params: TotpParams, unixSeconds: number = Math.floor(Date.now() / 1000)): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(unixSeconds / params.period)));
  const mac = createHmac(params.algorithm, params.secret).update(counter).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return (bin % 10 ** params.digits).toString().padStart(params.digits, '0');
}

/** Seconds until the current TOTP window rolls over. */
export function secondsLeftInWindow(params: TotpParams, unixSeconds: number = Math.floor(Date.now() / 1000)): number {
  return params.period - (unixSeconds % params.period);
}

/** A literal one-time code: exactly `digits` decimal digits. */
export function isValidOtpCode(code: string, digits = 6): boolean {
  return code.length === digits && /^\d+$/.test(code);
}

/** Best-effort wipe of key material we no longer need. */
export function wipe(...buffers: Buffer[]): void {
  for (const b of buffers) b.fill(0);
}
