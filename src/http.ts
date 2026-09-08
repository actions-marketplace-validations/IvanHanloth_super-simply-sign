/**
 * A deliberately small HTTP layer over Node's built-in fetch (undici):
 *
 *  - every client is bound to an allowlist of origins, so a bearer token or a
 *    login form can never be sent anywhere but the hosts we configured — a
 *    redirect or an `atom:link` pointing elsewhere is an error, not a hop;
 *  - plain `http:` is refused unless the client was created with `allowHttp`
 *    (only the RFC 3161 TSA client is, because its reply is itself signed);
 *  - redirects are never followed implicitly; `follow()` walks them by hand
 *    with a hop limit, the same origin check, and a callback that can stop
 *    early — that is how the OAuth code is picked off the redirect chain
 *    without ever requesting the redirect target;
 *  - a cookie jar scoped per origin, because the CAS login is cookie-based;
 *  - a hard timeout on every request;
 *  - errors carry URLs with the query string stripped, so codes, tickets and
 *    tokens never leak into logs.
 */

export class HttpError extends Error {
  readonly status: number | undefined;
  readonly url: string;

  constructor(message: string, url: string, status?: number) {
    super(message);
    this.name = 'HttpError';
    this.url = redactUrl(url);
    this.status = status;
  }
}

/** `origin + pathname` — never the query string. */
export function redactUrl(url: string | URL): string {
  try {
    const u = new URL(url);
    return `${u.origin}${u.pathname}`;
  } catch {
    return '<invalid url>';
  }
}

/** The first printable characters of a body, for error messages. */
export function bodySnippet(body: Uint8Array, max = 200): string {
  const text = Buffer.from(body)
    .toString('utf8')
    .replace(/[^\x21-\x7e]+/g, ' ')
    .trim();
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

export function isLoopbackHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]' || hostname === '::1';
}

export class CookieJar {
  readonly #cookies = new Map<string, Map<string, string>>();

  store(origin: string, setCookieHeaders: readonly string[]): void {
    for (const header of setCookieHeaders) {
      const pair = header.split(';', 1)[0] ?? '';
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (!name) continue;
      let jar = this.#cookies.get(origin);
      if (!jar) {
        jar = new Map();
        this.#cookies.set(origin, jar);
      }
      jar.set(name, value);
    }
  }

  header(origin: string): string | undefined {
    const jar = this.#cookies.get(origin);
    if (!jar || jar.size === 0) return undefined;
    return [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
  }

  /** Every cookie value held (so the caller can mask them in logs). */
  values(): string[] {
    const out: string[] = [];
    for (const jar of this.#cookies.values()) out.push(...jar.values());
    return out;
  }

  clear(): void {
    this.#cookies.clear();
  }
}

export interface HttpClientOptions {
  readonly userAgent: string;
  readonly timeoutMs: number;
  /** Origins this client may talk to; anything else is refused. */
  readonly allowedOrigins: readonly string[];
  /** Permit `http:` for non-loopback hosts (only for the TSA, whose reply is signed). */
  readonly allowHttp?: boolean;
}

export interface HttpRequest {
  readonly method?: 'GET' | 'POST';
  readonly headers?: Readonly<Record<string, string>>;
  readonly body?: Uint8Array | string;
}

export interface HttpResponse {
  readonly status: number;
  readonly headers: Headers;
  /** The URL that was requested (redirects are never followed here). */
  readonly url: string;
  readonly body: Buffer;
}

export interface FollowOptions {
  readonly maxHops?: number;
  /**
   * Called with each redirect target *before* it is requested. Return true to
   * stop: the redirecting response is returned and the target is never fetched.
   */
  readonly onRedirect?: (target: URL) => boolean;
}

export interface FollowResult extends HttpResponse {
  /** Redacted URLs of the hops that were followed. */
  readonly hops: readonly string[];
  /** The redirect target `onRedirect` stopped at, if it did. */
  readonly stoppedAt: URL | null;
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function describeFetchError(err: unknown): string {
  if (!(err instanceof Error)) return 'unknown error';
  if (err.name === 'TimeoutError' || err.name === 'AbortError') return 'timed out';
  const cause = (err as { cause?: unknown }).cause;
  if (cause instanceof Error) {
    const code = (cause as { code?: unknown }).code;
    return typeof code === 'string' ? `${code} (${cause.message})` : cause.message;
  }
  return err.message;
}

function copyBody(body: Uint8Array | string | undefined): Uint8Array<ArrayBuffer> | string | undefined {
  if (body === undefined || typeof body === 'string') return body;
  return new Uint8Array(body);
}

export class HttpClient {
  readonly jar = new CookieJar();
  readonly #options: HttpClientOptions;
  readonly #origins: ReadonlySet<string>;

  constructor(options: HttpClientOptions) {
    this.#options = options;
    this.#origins = new Set(options.allowedOrigins.map((o) => new URL(o).origin));
  }

  assertAllowed(url: URL): void {
    if (!this.#origins.has(url.origin)) {
      throw new HttpError(`refusing to contact ${url.origin}: it is not one of the configured origins`, url.toString());
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && (this.#options.allowHttp || isLoopbackHost(url.hostname)))) {
      throw new HttpError(`refusing to use ${url.protocol} for ${url.origin}: only https is allowed here`, url.toString());
    }
  }

  /** One request, no redirect following, cookies applied and captured. */
  async fetch(url: string | URL, request: HttpRequest = {}): Promise<HttpResponse> {
    const u = new URL(url);
    this.assertAllowed(u);
    const headers = new Headers(request.headers ?? {});
    headers.set('user-agent', this.#options.userAgent);
    if (!headers.has('accept')) headers.set('accept', '*/*');
    const cookie = this.jar.header(u.origin);
    if (cookie) headers.set('cookie', cookie);

    let response: Response;
    let body: Buffer;
    try {
      response = await fetch(u, {
        method: request.method ?? 'GET',
        headers,
        body: copyBody(request.body),
        redirect: 'manual',
        signal: AbortSignal.timeout(this.#options.timeoutMs),
      });
      body = Buffer.from(await response.arrayBuffer());
    } catch (err) {
      throw new HttpError(`request to ${redactUrl(u)} failed: ${describeFetchError(err)}`, u.toString());
    }
    this.jar.store(u.origin, response.headers.getSetCookie());
    return { status: response.status, headers: response.headers, url: u.toString(), body };
  }

  /** Request and follow redirects by hand (same origins only, bounded, observable). */
  async follow(url: string | URL, request: HttpRequest = {}, options: FollowOptions = {}): Promise<FollowResult> {
    const maxHops = options.maxHops ?? 10;
    const hops: string[] = [];
    let current = new URL(url);
    let currentRequest: HttpRequest = request;
    for (;;) {
      const response = await this.fetch(current, currentRequest);
      if (!REDIRECT_STATUSES.has(response.status)) return { ...response, hops, stoppedAt: null };

      const location = response.headers.get('location');
      if (!location) throw new HttpError(`redirect from ${redactUrl(current)} carries no Location header`, current.toString(), response.status);
      let target: URL;
      try {
        target = new URL(location, current);
      } catch {
        throw new HttpError(`redirect from ${redactUrl(current)} points at an invalid URL`, current.toString(), response.status);
      }
      if (options.onRedirect?.(target)) return { ...response, hops, stoppedAt: target };
      this.assertAllowed(target);
      if (hops.length >= maxHops) throw new HttpError(`too many redirects (more than ${maxHops})`, target.toString());
      hops.push(redactUrl(target));

      if (response.status === 307 || response.status === 308) {
        currentRequest = request;
      } else {
        // 301/302/303: switch to a body-less GET, as browsers do.
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(request.headers ?? {})) {
          if (!['content-type', 'content-length'].includes(k.toLowerCase())) headers[k] = v;
        }
        currentRequest = { method: 'GET', headers };
      }
      current = target;
    }
  }
}
