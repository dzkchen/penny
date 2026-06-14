# Penny Detection Coverage

This is the full catalogue of what Penny can find. Findings are grouped by how they
are produced: **static** detectors read source code only, **dynamic/active** probes
talk to a live target, **AI** findings come from the Claude review pass, and
**network** findings come from the port scan.

Every finding is redacted before it is persisted, and every probe that touches a live
target goes through the same `TargetGate` (read-only methods, rate limited,
same-origin, no redirects off target). See the **Safety Model** section of the
[README](README.md) for the guardrails.

---

## Static detectors (source code only)

These run on every scan, with no target and no network. They cover `.py`, `.js`/`.jsx`,
`.ts`/`.tsx`, and relevant config/rule files.

| ID | What it detects |
|------|-----------------|
| `D001` | Service-role / admin key in client-visible code. |
| `D002` | Committed secret: known prefixes (Stripe, GitHub, AWS, Google, OpenAI/Anthropic, …) plus entropy heuristics. |
| `D003` | Permissive RLS / access policy (SQL). |
| `D005` | Vulnerable dependency. Offline uses a small curated list; with `--osv` it queries [OSV.dev](https://osv.dev) for every parsed npm/PyPI dependency and reports real advisory IDs, CVEs, severities, and fixed versions. All vulnerable deps **collapse into one finding**. |
| `D006` | Permissive CORS policy (`*` wildcard), with dynamic header confirmation when a target is set. |
| `D007` | Committed private key (PEM material in source control). |
| `D008` | Dangerous execution sinks: `os.system` / `subprocess(shell=True)` / `child_process.exec`, `pickle` / `yaml.load` deserialization, dynamic `eval` / `exec`. |
| `D009` | SQL injection from string-built queries handed to `execute` / `query`. |
| `D010` | Disabled TLS verification (`verify=False`, `rejectUnauthorized: false`, unverified SSL context). |
| `D011` | Production debug mode (`app.run(debug=True)`, `DEBUG = True`). |
| `D012` | Client-side DB write with no server-side authorization: direct Supabase / Firebase / Firestore / Realtime DB mutations shipped to the browser (server paths like `api/`, `server/`, `functions/` are excluded). The core trust-boundary risk for apps with "no real backend". |
| `D013` | Permissive Firebase security rules: `allow read, write: if true`, `".read"/".write": true`. Auth-only rules with no ownership check are flagged Medium. |
| `D014` | Server-side request forgery (SSRF): an outbound HTTP call whose URL is built from request-controlled input. |
| `D015` | Path traversal: a filesystem read/serve sink fed request-controlled input. |
| `D016` | Insecure JWT handling: the `none` algorithm, or decoding with signature verification disabled. |
| `D017` | Weak cryptography: ECB / DES / RC4, plus MD5/SHA-1 or non-cryptographic randomness used in a security context. |
| `D018` | DOM XSS sinks in client code: dynamic `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `insertAdjacentHTML`, jQuery `.html()`, `document.write`. |
| `D019` | Open redirect: a redirect target taken directly from request input. |
| `D020` | Secret exposed in the client bundle via a public build-time env var (`VITE_`, `NEXT_PUBLIC_`, …). |
| `D023` | Prompt injection (OWASP LLM01): request-controlled input concatenated into an LLM prompt or system message. The `--ai` pass reasons about the rest of the LLM Top 10. |

The data-flow-style detectors (`D014` / `D015` / `D019` / `D023`) stay high-precision by
firing only when a dangerous sink and a request-derived input appear together.

---

## AI-assisted review (opt-in via `--ai`)

| ID | What it detects |
|------|-----------------|
| `AI001` | Issues regex can't catch: broken auth/authorization, injection through indirect data flow, SSRF, unsafe deserialization, missing ownership checks (route to middleware to data access), and the OWASP LLM Top 10. Reported Critical/High. |

`--ai` also runs a **secret triage** pass that drops false-positive-prone high-entropy
`D002` hits judged benign (hashes, fingerprints, fixtures). Known-prefix secrets are
never triaged away. All context sent to the model is redacted, and each AI finding's
snippet is rebuilt from the real source line and redacted before storage.

---

## Active probes (opt-in via `--active`)

Non-destructive attack payloads against a live, consented target. Read-only methods only.

| ID | What it detects |
|------|-----------------|
| `A001` | SQL injection: error-, boolean-, and time-based, using benign `GET`-only payloads. |
| `A002` | Firebase database readable without authentication (`/.json?shallow=true`). Stores only status code + top-level key count. |
| `A003` | Weak or missing browser security headers. |
| `A004` | Session cookies missing protective attributes (HttpOnly, Secure, SameSite). |
| `A005` | Unsafe advertised HTTP methods (state-changing PUT/DELETE/PATCH, WebDAV, TRACE). |
| `A006` | Exposed sensitive files / admin metadata / API schemas (`.env`, `.git`, backups). |
| `A007` | Directory listing enabled. |
| `A008` | Verbose errors / stack traces leaked to clients. |
| `A009` | Permissive CORS preflight (untrusted origin with credentials or state-changing methods). |
| `A010` | Sensitive responses cacheable by clients (missing `Cache-Control: no-store`). |
| `A011` | Transport / MitM exposure: weak TLS (version/cipher/cert), shallow or missing HSTS, cleartext `http://` that doesn't redirect. Reports what enables a MitM; never performs one. |
| `A012` | Reflected XSS: unescaped input reflected into HTML. |
| `A013` | Fingerprinted tech surfaces (Spring Actuator, Prometheus, Jenkins, Laravel Telescope, …). |

---

## Browser, brute-force, network, load, and write probes

| ID | Mode | What it detects |
|------|------|-----------------|
| `D021` | `--brute` | Weak default credentials accepted by a login endpoint (read-only basic-auth spray). |
| `D022` | `--browser` | Secrets exposed in rendered browser pages (Playwright). |
| `D024` | `--browser` | Form submitted over insecure HTTP. |
| `A014` | `--load-test` | Resilience benchmark: bounded ramp-to-failure to find the capacity knee. |
| `A015` | `--i-accept` | Write-path probe: unauthenticated POST creates / mass assignment. POST-only, benign marked records, never PUT/PATCH/DELETE. |
| `N001` | `--netscan` | Open ports on the target host (informational inventory). |
| `N002` | `--netscan` | Reachable sensitive services: unauthenticated datastores/caches (Critical), databases / remote-management daemons (High), cleartext legacy protocols (Medium). Read-only TCP-connect scan. |

`--brute` path discovery is also reported under `D020` (secrets / VCS / config / backup /
admin / debug / api wordlist, severity escalates to Critical when a secret/VCS/backup
file is reachable).

---

## Scan scope and noise control

- **Gitignore-aware.** Inside a git work tree, Penny skips git-ignored files, so a
  gitignored local `.env` (the recommended place for secrets) is not flagged. A
  committed `.env` is still scanned, because a committed secret is a real finding.
- **Documentation isn't a credential store.** The generic high-entropy heuristic is
  skipped in `.md` / `.txt` / `.rst`, known-benign shapes (SRI hashes, content hashes,
  git SHAs, UUIDs) are ignored everywhere, and high-entropy strings inside URLs are
  ignored, so README badges, lockfile integrity hashes, and asset fingerprints don't
  become findings. Real known-prefix secrets are still flagged even in docs.
- **Generated output is excluded.** `.next/`, `.nuxt/`, `.svelte-kit/`, `.turbo/`,
  `dist/`, `build/`, `out/`, `coverage/`, and lock/cache artifacts are ignored.

## Finding status

- **confirmed**: dynamically proven (an active probe succeeded).
- **unconfirmed**: a static detector found it but the probe was blocked or failed.
- **suspected**: static detector only, no dynamic confirmation attempted.
