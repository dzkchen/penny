# Penny

Penny is a local-first Python CLI penetration-testing assistant for AI-built apps. It scans a small repository, proves safe localhost vulnerabilities when a target is supplied, writes redacted findings, and generates a developer-focused remediation report.

Penny is meant to be driven from interactive mode. Start it with no arguments:

```bash
python -m penny            # or, after install: penny
```

Then run the security workflow from the `penny ›` prompt:

```text
penny › /target http://127.0.0.1:8787
penny › /audit ./planted-app
penny › /findings
penny › /show F-001
penny › what should Blue fix first?
penny › /report
```

The same scanner, report writer, assistant, and fix engine are still available as one-shot commands for CI and scripts, but the README follows the interactive flow first.

## Architecture maps

```text
+--------------------+
| Developer / REPL   |
+---------+----------+
          |
          v
+--------------------+        +----------------------+
| penny REPL / CLI   |------->| Source resolver      |
| cli.py / repl.py   |        | sources.py           |
+---------+----------+        +----------+-----------+
          |                              |
          |                              v
          |                   +----------------------+
          |                   | Repo walker          |
          |                   | repo.py              |
          |                   +----------+-----------+
          |                              |
          v                              v
+----------------------------------------------------+
| Scan orchestrator                                  |
| scanner.py                                         |
+----+-----------+-----------+-----------+-----------+
     |           |           |           |
     v           v           v           v
+----------+ +----------+ +----------+ +-------------+
| Static   | | Dynamic  | | Active   | | AI / OSV    |
|detectors | | probes   | | probes   | | optional    |
|detectors | |probes.py | |active.py | |ai/advisory |
+----+-----+ +----+-----+ +----+-----+ +------+------+
     |            |            |              |
     +------------+------------+--------------+
                  |
                  v
        +----------------------+
        | Finding models       |
        | models.py            |
        +----------+-----------+
                   |
                   v
        +----------------------+
        | Redaction            |
        | redaction.py         |
        +----------+-----------+
                   |
                   v
        +----------------------+
        | Findings store       |
        | store.py             |
        | .penny/runs/*        |
        +----+-------------+---+
             |             |
             v             v
+------------------+   +------------------+
| Report generator |   | Ask / Fix actions  |
| reporting.py     |   | ask.py patches.py |
+--------+---------+   +------------------+
         |
         v
+------------------+
| Local output     |
| findings.json    |
| report.md        |
| store.py         |
+------------------+
```

### Trust / data boundaries

```text
+---------------- LOCAL MACHINE ----------------+
|                                                |
|  +-----------+        +---------------------+  |
|  | Source    |------->| Penny process       |  |
|  | repo      |        | scanner/report/ask  |  |
|  +-----------+        +----------+----------+  |
|                                  |             |
|                                  v             |
|                       +---------------------+  |
|                       | Local output        |  |
|                       | findings/report     |  |
|                       +---------------------+  |
|                                                |
+--------------------------+---------------------+
                           |
                           | guarded GET/HEAD/OPTIONS
                           v
              +--------------------------+
              | Consented target app     |
              | localhost/private/public |
              +--------------------------+

Optional outbound paths:

Penny ---> Anthropic Claude
          - /scan --ai and /audit send bounded source code
          - questions send redacted findings
          - /fix sends explicit local file content

Penny ---> OSV.dev
          - /scan --osv and /audit send package names and versions only

Penny ---> MongoDB
          - redacted stats and generic patterns only

Penny ---> Git remote
          - only when scan source is a git URL
```

### Planted app fixture

```text
+-------------------- planted-app --------------------+
|                                                     |
|  +-------------------+                              |
|  | frontend/src      |                              |
|  | planted secrets   |                              |
|  +---------+---------+                              |
|            |                                        |
|            v                                        |
|  +-------------------+        +------------------+  |
|  | server/app.py     |<-------| seed_data.json   |  |
|  | mock REST target  |        +------------------+  |
|  +----+---------+----+                              |
|       |         |                                   |
|       v         v                                   |
|  /health   /rest/v1/private_notes                  |
|    |              |                                 |
|    v              v                                 |
|  CORS       service-key confirmation                |
|                                                     |
|  /api/orders/<id>                                  |
|       |                                             |
|       v                                             |
|  BOLA confirmation                                  |
|                                                     |
|  policies/private_notes.sql                         |
|       |                                             |
|       v                                             |
|  permissive RLS static finding                      |
+-----------------------------------------------------+
```

## Interactive Mode

Run `penny` with no arguments to launch a styled REPL with no extra dependencies. The shell auto-loads the most recent scan, shows whether AI is available, and keeps the current findings and target in session so you can move through scan, triage, report, and fix without copying file paths between commands.

```bash
python -m penny            # or: penny
```

### 1. Set a Live Target

Use `/target` when you want Penny to confirm issues against a running app. Without a target, Penny still performs static and code-aware checks.

```text
penny › /target http://127.0.0.1:8787
```

### 2. Audit the App

`/audit` is the full interactive path: scan source, run AI review when configured, run dependency and live-probe checks, then write a report. Natural language routes here too, so "pentest ./planted-app" and "run a full audit on ./planted-app" work.

```text
penny › /audit ./planted-app
```

For a narrower pass, use `/scan` directly:

```text
penny › /scan ./planted-app --osv --ai
penny › /scan ./planted-app --static-only
penny › /scan ./app --active --i-own-this --target https://app.example.com
```

### 3. Inspect and Ask

After a scan, `/findings` gives the ranked table, `/show` opens one finding, and plain questions ask the assistant about the loaded run.

```text
penny › /findings
penny › /show F-001
penny › what should Blue fix first?
```

Questions use Claude when `ANTHROPIC_API_KEY` is configured and `/ai on` is active. If not, Penny answers with deterministic local logic so the flow still works offline.

### 4. Report and Fix

Generate the Markdown report at any point from the current findings — it is written to `.penny/runs/<session>/report.md` (and `.penny/runs/latest/`). Use `/fix` when you want Penny to propose and apply local code changes with approval.

```text
penny › /report
penny › /fix
penny › /exit
```

Available interactive commands:

```text
/audit <path> [--target <url>]    full audit: scan + AI + probes + report
/full <path> [--target <url>]     alias for /audit
/scan <path> [--osv] [--ai] [--active] [--agentic] [--brute] [--browser] [--static-only] [--target <url>]
/report                           write report.md to .penny/runs/
/fix [--yes]                      fix flagged files with approval
/findings                         list current findings
/show <F-001>                     show one finding in detail
/target <url|off>                 set or clear the dynamic-probe target
/ai <on|off>                      toggle AI answers/review
/clear                            clear the screen
/help                             show help
/exit                             leave
```

Colour is used on a TTY and disabled automatically when output is piped.

## Scriptable Equivalents

Use these when you need automation outside the interactive shell. They read and write the same `.penny/runs/latest` state that the REPL auto-loads.

```bash
python -m penny scan <path> [--target <url>] [--static-only] [--out <dir>] [--osv] [--ai] [--active] [--i-own-this] [--fail-on <severity>] [--diff <ref>] [--endpoint <path?param>]
python -m penny report [--findings <path>] [--out <dir>]
python -m penny ask "question" [--findings <path>] [--target <url>] [--no-ai]
python -m penny ask-loop [--findings <path>] [--target <url>] [--no-ai]
python -m penny run <path> --target <url> [--out <dir>] [--osv] [--ai] [--active] [--i-own-this] [--fail-on <severity>] [--diff <ref>] [--endpoint <path?param>]
python -m penny patch [--findings <path>] --repo <path> [--out penny.patch] [--apply]
python -m penny knowledge "query" [--limit 5]
python -m penny trends [--days 7] [--limit 10]
python -m penny demo-replay [--recording <path>] [--out <dir>]
```

The CLI uses Typer/Rich when installed and falls back to a standard-library CLI/feed when they are not available. Running `python -m penny` with no subcommand is still the recommended starting point.

## AI Assistant

Inside the REPL, plain-language questions answer against the loaded findings:

```text
penny › what did Red confirm and what should Blue fix first?
penny › /ai off
penny › summarize F-001 and how to fix it
```

Penny reads `ANTHROPIC_API_KEY` from the environment or a local `.env`, and the model from `PENNY_DEEP_MODEL` (default `claude-sonnet-4-6`). Questions only send the already-redacted findings JSON to the model — not raw source snippets, raw secrets, or `secret_value` fields. When no key is configured, the request fails, or AI is off, Penny falls back to deterministic answers.

### AI-assisted detection (`--ai`)

In interactive mode, `/audit` enables the AI review pass as part of the full workflow. For narrower scans, pass `--ai` to `/scan`:

```text
penny › /scan ./planted-app --ai
```

The AI review sends bounded, line-numbered source to Claude (the deep model) and folds back vulnerabilities it finds — broken auth/authorization, injection through indirect data flow, SSRF, unsafe deserialization, and similar issues the regex detectors cannot reason about. The pass also **traces authorization across files** (route → middleware → data access) to surface missing ownership checks, and audits any LLM integration against the **OWASP LLM Top 10** (prompt injection, insecure output handling, unauthorized tool/function use, system-prompt or key leakage). Security-relevant files (auth/api/route/db/LLM) are bundled first so large repos do not truncate the important code away. These land as `AI001` findings (`source: ai`) alongside the deterministic ones; each finding's snippet is rebuilt from the real source line and redacted, so the model cannot smuggle an unredacted secret into persisted output.

`--ai` also runs a **secret triage** step: a fast-model pass over the false-positive-prone high-entropy `D002` hits that drops ones it judges benign (hashes, fingerprints, fixtures). Known-prefix secrets are never triaged away, and the context sent to the model is redacted.

Unlike normal question-answering, `--ai` sends source code to Anthropic, so it remains opt-in for `/scan` and explicit in the `/audit` flow. It respects the same walker, so gitignored files (e.g. a local `.env`) are never included. Without a key it is a no-op.

### Active probing (`--active`)

By default Penny's dynamic checks are read-only confirmations against the REPL target. `/scan --active` and `/audit` go further and send **non-destructive attack payloads** to a live target to demonstrate real weaknesses:

- **SQL injection (`A001`):** appends benign SQL metacharacters (`'`, `' OR '1'='1`, …) to query-string parameters discovered in the source and looks for database error signatures. Read-only `GET` requests only.
- **Firebase open rules (`A002`):** for Firebase apps, reads the Realtime Database REST endpoint (`/.json?shallow=true`) **without authentication** to prove whether the security rules expose data to anonymous clients — the meaningful "pentest" for a NoSQL/Firebase backend. Only the status code and top-level key count are stored, never the data.
- **Checklist baseline (`A003`-`A010`):** runs bounded OWASP/API/WSTG-style probes for browser security headers, session cookie attributes, advertised HTTP verbs, exposed deployment files/admin metadata/API schemas, directory listings, verbose errors/stack traces, permissive CORS preflights, and cache controls on sensitive-looking responses.

```text
penny › /target https://my-owned-app.example
penny › /scan ../my-firebase-app --active --i-own-this
```

Active probes go through the same `TargetGate` as every other request: only `GET`/`HEAD`/`OPTIONS`, rate-limited, same-origin, no redirects off the target. Reaching any **public** host (e.g. `*.firebaseio.com`) requires `--i-own-this` — without it the probe is blocked, not sent. Payloads are detection-only; Penny never sends destructive input (`DROP TABLE`, writes, deletes).

`<path>` can be a local directory or a git source URL ending in `.git`, including an optional ref suffix:

```text
penny › /scan https://github.com/owner/repo.git#main --static-only
```

Git sources are cloned into a temporary local directory and scanned with the same deterministic repo walker as normal local paths.

## Local Demo

Start the deterministic planted target in one terminal:

```bash
python planted-app/server/app.py
```

Then drive the demo from another terminal through interactive mode:

```text
$ python -m penny
penny › /target http://127.0.0.1:8787
penny › /audit ./planted-app
penny › what did Red confirm and what should Blue fix first?
penny › /report
penny › /fix
```

Expected outputs:

- `.penny/runs/<session_id>/findings.json`
- `.penny/runs/<session_id>/report.md`
- `.penny/runs/latest/findings.json`
- `.penny/runs/latest/report.md`

### Gating CI/PRs

Interactive mode is for local triage. For CI, use the scriptable `scan` command with `--fail-on <severity>` (Critical/High/Medium/Low/Info). Penny exits `1` when any finding is at or above that severity, so it can fail a build; usage and scan errors use exit code `2`.

```bash
python -m penny scan . --osv --fail-on high   # non-zero exit if any High+ finding
```

### Faster scans and targeted probes

Use `/scan` from the REPL when you want a smaller or more directed pass:

```text
penny › /scan . --osv
penny › /scan ./app --active --i-own-this --target https://app.example.com
```

For CI and other scriptable runs, `--diff <ref>` scans only files changed versus a git ref (committed, staged, unstaged, and untracked), so PR/pre-commit runs stay fast. It falls back to a full scan when the path is not a git tree or the ref does not resolve. `--endpoint <path?param>` adds endpoints for active SQLi probing. SPAs build URLs dynamically, so source discovery often finds nothing; point A001 at the endpoints you know exist:

```bash
python -m penny scan . --diff main --osv --fail-on high
python -m penny scan ./app --active --i-own-this --target https://app.example.com --endpoint '/api/users?id=1'
```

The planted app includes a client-visible service-role key, a committed fake secret, a permissive RLS-style policy, a mock Supabase REST endpoint, a BOLA-style order endpoint, known-vulnerable dependency fixtures, and a permissive CORS header.

## Safety Model

Penny only runs read-only HTTP probes (`GET`/`HEAD`/`OPTIONS`). Localhost and private-network targets are allowed by default. Public targets require `--i-own-this`; unsafe methods, request overages, and redirects away from the approved target are blocked by Python guardrails before any request is made.

`--active` probing (SQLi, Firebase open-rules, and the checklist baseline) is more intrusive but stays within these guardrails: read-only methods only, rate-limited, same-origin, and detection-only payloads — Penny never sends destructive input or writes. Public hosts still require `--i-own-this`, so active probes against a hosted backend (e.g. Firebase) are blocked unless you explicitly assert ownership.

Reports and findings are written locally. Store-layer redaction masks service keys, JWTs, API keys, private keys, database URLs, emails, and high-entropy token-shaped values before persistence.

By default Penny only talks to the scan target's localhost. Three features add opt-in outbound calls, and each sends the minimum needed: interactive questions send the already-redacted findings to the configured Claude model; `/scan --osv` and `/audit` send only dependency names and versions to OSV.dev; `/scan --ai` and `/audit` send source code (never gitignored files) to the Claude model. All three degrade to local-only behavior when disabled or unconfigured.

## Coverage

Current deterministic checks:

- `D001`: service-role key in client-visible code.
- `D002`: committed secret using known prefixes (Stripe, GitHub, AWS, Google, OpenAI/Anthropic, etc.) and entropy heuristics.
- `D003`: permissive RLS/access policy.
- `D004`: dynamic BOLA/IDOR order-read probe.
- `D005`: vulnerable dependency detector. Offline it uses a small curated list; with `--osv` it queries the public [OSV.dev](https://osv.dev) feed for every parsed dependency (npm + PyPI) and reports real advisory IDs, CVEs, severities, and fixed versions. Only package names and versions leave the machine. All vulnerable dependencies **collapse into a single finding** that lists each package with its CVEs and recommended fixed version — so one outdated package with a dozen advisories is one finding, not a dozen.
- `D006`: permissive CORS detector with dynamic header confirmation.
- `D007`: committed private key (PEM key material in source control).
- `D008`: dangerous execution sinks — `os.system`/`subprocess(shell=True)`/`child_process.exec`, `pickle`/`yaml.load` deserialization, and dynamic `eval`/`exec`.
- `D009`: SQL injection from string-built queries handed to an `execute`/`query` call.
- `D010`: disabled TLS verification (`verify=False`, `rejectUnauthorized: false`, unverified SSL context).
- `D011`: production debug mode (`app.run(debug=True)`, `DEBUG = True`).
- `D012`: client-side database write with no server-side authorization — direct Supabase/Firebase mutations (Supabase `.insert/.update/.delete`, Firestore `setDoc/updateDoc/.collection().add/.doc().set`, Realtime Database `set(ref())`/`.ref().push`) in browser-shipped code (server paths like `api/`, `server/`, `functions/` are excluded). This is the core trust-boundary risk for apps that "lack a proper backend": the browser is attacker-controlled, so access control can't be enforced there.
- `D013`: permissive Firebase security rules — `allow read, write: if true` (Firestore/Storage) or `".read"/".write": true` (Realtime Database) in `firestore.rules`, `storage.rules`, `*.rules`, or `database.rules.json`. Auth-only rules (`if request.auth != null`, no ownership check) are flagged Medium.
- `D014`: server-side request forgery (SSRF) — an outbound HTTP call (`requests`/`httpx`/`urlopen`/`axios`/`fetch`/`got`) whose URL is built from request-controlled input.
- `D015`: path traversal — a filesystem read/serve sink (`open`/`fs.readFile`/`sendFile`/`send_file`/`createReadStream`) fed request-controlled input.
- `D016`: insecure JWT handling — the `none` (unsigned) algorithm, or decoding with signature verification disabled (`verify=False`, `verify_signature: false`).
- `D017`: weak cryptography — ECB cipher mode and broken ciphers (DES/RC4) unconditionally, plus MD5/SHA-1 hashing or non-cryptographic randomness (`Math.random`, `random.*`) used in a security context (password/token/secret/salt).
- `D018`: DOM XSS sinks in client code — dynamic `innerHTML`/`outerHTML`, `dangerouslySetInnerHTML`, `v-html`, `insertAdjacentHTML`, jQuery `.html()`, or `document.write` (static markup is not flagged).
- `D019`: open redirect — a redirect target (`res.redirect`/`redirect`/`window.location`) taken directly from request input.
- `D023`: prompt injection (OWASP LLM01) — request-controlled input concatenated/interpolated into an LLM prompt or system message (High when it lands in a system prompt). The `--ai` pass reasons about the rest of the LLM Top 10.
- `AI001`: AI-assisted review (opt-in via `--ai`) for issues regex can't catch — including the client/server trust boundary (missing backend / client-trusted mutations), reported as Critical/High. See "AI-assisted detection" above.
- `A001` / `A002`: active-probe findings (opt-in via `--active`) — confirmed SQL injection and an anonymously-readable Firebase database.
- `A003`-`A010`: active checklist findings (opt-in via `--active`) — weak security headers, weak cookie attributes, unsafe advertised HTTP methods, exposed files/admin metadata/API schemas, directory listings, verbose errors, permissive CORS preflight, and cacheable sensitive-looking responses. See "Active probing" above.

Dynamic probes are still read-only. `D004` stores only status codes, object IDs, and ownership comparison results; `D006` stores only CORS headers. The code-pattern detectors (`D008`–`D011`, `D014`–`D019`, `D023`) only scan source files (`.py`, `.js`/`.jsx`, `.ts`/`.tsx`); the data-flow-style ones (`D014`/`D015`/`D019`/`D023`) stay high-precision by firing only when a dangerous sink and a request-derived input appear together on the same line.

### Scan scope and noise control

- **Gitignore-aware.** When the scan path is inside a git work tree, Penny skips files git ignores — so a gitignored local `.env` (the recommended place to keep secrets) is not flagged. A `.env` that is actually tracked/committed is still scanned, since a committed secret is a real finding.
- **Documentation isn't a credential store.** The generic high-entropy heuristic is skipped in `.md`/`.txt`/`.rst`, known-benign high-entropy shapes (subresource-integrity hashes, content hashes / git SHAs, UUIDs) are ignored everywhere, and high-entropy strings inside URLs (Google Docs/Drive share ids, CDN asset hashes) are ignored — so README badges (e.g. `shields.io`), lockfile integrity hashes, asset fingerprints, and doc links don't become findings. Real known-prefix secrets are still flagged even in docs and URLs.
- **Generated output is excluded.** Penny ignores common build/cache directories such as `.next/`, `.nuxt/`, `.svelte-kit/`, `.turbo/`, `dist/`, `build/`, `out/`, `coverage/`, and lock/cache artifacts so reports focus on source code rather than generated manifests.

## Interactive Fix Workflow

Penny does not require or ship a web UI. From the REPL, `/fix` reads the current findings and proposes local code changes with approval:

```text
penny › /fix
penny › /fix --yes
```

The scriptable `patch` command still exists for non-interactive patch previews. Patch previews are redacted so they can be reviewed without writing raw secrets into a patch file. `--apply` is explicit and modifies only the local repo path supplied with `--repo`.

## Mongo Boundary

MongoDB is optional. The interactive scan, triage, report, and fix loop works without Mongo, Atlas, RAG, Vultr, or GitHub clone support.

When `MONGODB_URI` is configured, Penny mirrors only safe data:

- `vuln_patterns`: generic detector knowledge, remediation text, observation counts, and Atlas-vector-index-ready embeddings.
- `scan_history`: aggregate counts by severity, status, and detector.

Penny does not write reports, app names, target URLs, source snippets, raw evidence, secrets, or code to Mongo.

The optional knowledge library is available as scriptable commands:

```bash
python -m penny knowledge "service key in client code"
python -m penny trends --days 7
```

When Mongo is unavailable, scans and reports continue without this lookup.

## Development

```bash
python -m pytest
```

The integration test starts the planted app locally and verifies that the service-role finding is confirmed while raw planted values are absent from persisted outputs.
