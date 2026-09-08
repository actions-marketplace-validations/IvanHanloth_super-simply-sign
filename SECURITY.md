# Security

This action signs code with a certificate that vouches for *you*. A signature
made by mistake — or by someone who got hold of your credentials — is a
reputational and, potentially, a supply-chain incident. This document says what
the action does to keep that from happening, what it cannot do, and what is
expected from the workflow that uses it.

## What the action protects

### The credentials

| Secret | Nature | Handling |
| --- | --- | --- |
| `otp-seed` (`CERTUM_OTP`) | The TOTP seed behind the SimplySign authenticator. **Long-lived**: whoever holds it plus the e-mail can sign as you until the seed is re-issued. | Registered with `core.setSecret` before anything else runs; read once, turned into the current 6-digit code, then the key bytes are wiped. Never written to disk, never sent anywhere — only the 6-digit code is. |
| `otp-code` (`CERTUM_TOKEN`) | A single 6-digit code, valid for one login within ~30 s. Low value. | Masked in logs. |
| OAuth bearer token | Signs anything for ~30 minutes. | Masked, kept in memory only, sent only to `cloudsign.webnotarius.pl` over HTTPS, discarded when the process ends. There is deliberately **no session cache on disk**. |
| CAS cookies, authorization code | Login-flow artefacts. | Masked and dropped after the token exchange. |
| Card serial | A stable identifier for your signing card. | Masked. |

The account e-mail is not treated as a secret.

### Where secrets can travel

Every HTTP client is pinned to an allowlist of origins, and redirects are never
followed implicitly:

* the login form and the bearer token can only go to the configured Certum
  hosts, over `https:`;
* a redirect or an `atom:link` that points anywhere else is an **error**, not
  a hop — a compromised or misconfigured endpoint cannot bounce the token to a
  third party;
* the OAuth authorization code is read off the redirect chain *before* the
  redirect target is requested; the target itself is never fetched;
* the timestamp authority is the only client allowed to use plain `http:`
  (as RFC 3161 servers commonly are). It only ever receives a SHA-256 digest of
  the signature, and its reply is checked (see below) before it is trusted;
* error messages carry URLs with the query string stripped, so codes, tickets
  and tokens cannot leak through logs or annotations;
* the production endpoints are compiled in. No input or environment variable
  can point the action at another API host.

### What gets signed

* The signing certificate is fetched from the cloud, parsed, and checked for
  validity dates and the Code Signing extended key usage before any digest is
  sent.
* The cloud only ever sees a SHA-256 digest, never the file.
* The RSA signature that comes back is verified against the certificate's
  public key **before** it is embedded. A signature that does not verify is
  refused.
* The RFC 3161 token is accepted only if it is a CMS SignedData over a TSTInfo
  whose `messageImprint` is the digest of *this* signature, whose `nonce` is
  the random one the action sent, whose signature verifies with the TSA
  certificate carried in the token, and whose TSA certificate has the
  time-stamping extended key usage. Anything else aborts the file (no silent
  "unsigned but green" outcome).
* After assembly the signed image is parsed again and verified end to end —
  Authenticode digest recomputed, signed attributes, RSA signature, timestamp
  — exactly as a Windows verifier would, short of chain trust. Only then is
  the file written, atomically (temp file + fsync + rename), so a crash can
  never leave a half-written binary behind.
* A file that already carries a signature is refused unless
  `replace-existing-signature: true` is set.

### The runtime

* Node 24 (`runs.using: node24`), the current GitHub Actions JavaScript
  runtime.
* No third-party cryptography: TOTP, DER, PKCS#7, Authenticode hashing and
  RFC 3161 are implemented on top of `node:crypto`, in this repository, under
  test. The only runtime dependencies are `@actions/core` and `@actions/glob`.
* The bundled `dist/index.cjs` is what the runner executes; CI fails if it
  does not match the sources.
* Third-party actions in this repository's own workflows are pinned to commit
  SHAs.

### Guard rails

* The action refuses to run on `pull_request` / `pull_request_target` events
  unless `allow-pull-request: true` is set explicitly. A pull request must
  never be able to trigger a signature.
* Timestamping is on by default; disabling it produces a loud warning, because
  an untimestamped signature stops validating when the certificate expires.
* Exactly one authentication method must be provided; a literal `otp-code` is
  validated as six digits.

## What the action cannot protect you from

* **A leaked seed.** If `CERTUM_OTP` leaks, rotate it: re-issue the SimplySign
  QR code from your Certum account. Nothing in the action can help after the
  fact.
* **A workflow that hands the secret to the wrong job.** Secrets are only as
  safe as the workflow. See below.
* **A compromised runner.** Anything with code execution on the runner during
  the signing step can read the bearer token from memory and sign for ~30
  minutes. Keep the signing job minimal: check out only what you need, run no
  untrusted build steps in the same job, and pin every action by SHA.
* **What you sign.** The action signs the bytes it is given. It cannot know
  whether they are the artifact you meant to release.

## Recommended workflow setup

1. Create a GitHub **environment** (for example `signing`) with a **required
   reviewers** protection rule. Store `CERTUM_EMAIL` and `CERTUM_OTP` as
   *environment* secrets there — not repository secrets.
2. Put the signing step in a job that declares `environment: signing`. The job
   pauses for a reviewer's approval before it can read the secrets; a pull
   request — even a malicious one — cannot get past that click.
3. Trigger signing only from `workflow_dispatch`, tags, or pushes to a
   protected branch. Never from `pull_request`.
4. Make signing a job in the same workflow as the build, with the release job
   `needs:` it, so a tag becomes *build → approve → signed release*.
5. Pin actions (including this one) to a commit SHA, and let Dependabot move
   the pin.
6. Prefer `otp-code` over `otp-seed` for manual, one-off signing on your own
   machine, so the seed never leaves your authenticator.

## Reporting a vulnerability

Please do not open a public issue for security problems. E-mail the maintainer
listed in `package.json` / the repository profile with a description and, if
possible, a reproduction. You will get an acknowledgement within a few days.
