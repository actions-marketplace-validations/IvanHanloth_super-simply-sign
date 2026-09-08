/** The tiny logging surface the pipeline needs; `main.ts` maps it onto @actions/core. */
export interface Logger {
  info(message: string): void;
  debug(message: string): void;
  warning(message: string): void;
  /** Register a value that must never appear in logs (tokens, codes, cookies). */
  secret(value: string): void;
}

export const silentLogger: Logger = {
  info: () => undefined,
  debug: () => undefined,
  warning: () => undefined,
  secret: () => undefined,
};

/** Console-backed logger for local runs and tests; secrets are only recorded, never printed. */
export function consoleLogger(verbose = false): Logger & { readonly secrets: string[] } {
  const secrets: string[] = [];
  const redact = (s: string): string => secrets.reduce((acc, sec) => (sec ? acc.split(sec).join('***') : acc), s);
  return {
    secrets,
    info: (m) => console.log(redact(m)),
    debug: (m) => (verbose ? console.log(`[debug] ${redact(m)}`) : undefined),
    warning: (m) => console.warn(`[warning] ${redact(m)}`),
    secret: (v) => {
      if (v) secrets.push(v);
    },
  };
}
