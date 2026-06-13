# Penny

Penny is a local-first Python CLI penetration-testing assistant for AI-built apps. It scans a small repository, proves safe localhost vulnerabilities when a target is supplied, writes redacted findings, and generates a developer-focused remediation report.

The MVP is demo-first:

```bash
python -m penny run ./planted-app --target http://127.0.0.1:8787
```

Installable CLI metadata is included, so after installing the package the same command is:

```bash
penny run ./planted-app --target http://127.0.0.1:8787
```

## Interactive mode

Run `penny` with no arguments to launch an interactive session (a styled REPL — no extra dependencies required). Type a question to ask the assistant about the loaded findings, or a `/command` to act:

```bash
python -m penny            # or: penny
```

```text
penny › /scan ./planted-app --osv --ai
penny › /findings
penny › /show F-001
penny › what should Blue fix first?
penny › /report --export
penny › /exit
```

Available commands: `/scan`, `/report`, `/findings`, `/show <id>`, `/target`, `/ai on|off`, `/clear`, `/help`, `/exit`. On startup Penny auto-loads the most recent scan's findings if present, and shows whether AI is enabled. Colour is used on a TTY and disabled automatically when output is piped. The one-shot subcommands below remain available for scripting.

## Commands

Replace the `<...>` placeholders with your own values (e.g. `--target http://localhost:3000`, `--out .`).

```bash
python -m penny scan <path> [--target <url>] [--static-only] [--out <dir>] [--osv] [--ai] [--active] [--i-own-this]
python -m penny report [--findings <path>] [--out <dir>]
python -m penny ask "question" [--findings <path>] [--target <url>] [--no-ai]
python -m penny ask-loop [--findings <path>] [--target <url>] [--no-ai]
python -m penny run <path> --target <url> [--out <dir>] [--osv] [--ai] [--active] [--i-own-this]
python -m penny patch [--findings <path>] --repo <path> [--out penny.patch] [--apply]
python -m penny knowledge "query" [--limit 5]
python -m penny trends [--days 7] [--limit 10]
python -m penny demo-replay [--recording <path>] [--out <dir>]
```

The CLI uses Typer/Rich when installed and falls back to a standard-library CLI/feed when they are not available.

## AI Assistant

`ask` and `ask-loop` answer questions about a scan using Claude. Penny reads `ANTHROPIC_API_KEY` from the environment or a local `.env`, and the model from `PENNY_DEEP_MODEL` (default `claude-sonnet-4-6`). The model only ever sees the already-redacted findings JSON — Penny never sends source snippets, raw secrets, or `secret_value` fields. When no key is configured, the request fails, or you pass `--no-ai`, Penny falls back to deterministic answers, so the demo always works offline.

```bash
cp .env.example .env   # then set ANTHROPIC_API_KEY
python -m penny ask "What did Red confirm and what should Blue fix first?" --findings .penny/runs/latest/findings.json
python -m penny ask "Summarize F-001 and how to fix it" --no-ai   # deterministic, no API call
```

### AI-assisted detection (`--ai`)

`scan --ai` / `run --ai` add an AI review pass: Penny sends bounded, line-numbered source to Claude (the deep model) and folds back any vulnerabilities it finds — broken auth/authorization, injection through indirect data flow, SSRF, unsafe deserialization, and similar issues the regex detectors can't reason about. These land as `AI001` findings (`source: ai`) alongside the deterministic ones; each finding's snippet is rebuilt from the real source line and redacted, so the model can't smuggle an unredacted secret into persisted output.

Unlike the rest of Penny, `--ai` sends source code to Anthropic, so it is opt-in. It respects the same walker, so gitignored files (e.g. a local `.env`) are never included. Without a key it is a no-op.

### Active probing (`--active`)

By default Penny's dynamic checks are read-only confirmations. `scan --active` / `run --active` go further and send **non-destructive attack payloads** to a live target to demonstrate real weaknesses:

- **SQL injection (`A001`):** appends benign SQL metacharacters (`'`, `' OR '1'='1`, …) to query-string parameters discovered in the source and looks for database error signatures. Read-only `GET` requests only.
- **Firebase open rules (`A002`):** for Firebase apps, reads the Realtime Database REST endpoint (`/.json?shallow=true`) **without authentication** to prove whether the security rules expose data to anonymous clients — the meaningful "pentest" for a NoSQL/Firebase backend. Only the status code and top-level key count are stored, never the data.

```bash
python -m penny scan ../my-firebase-app --active --i-own-this --out .
```

Active probes go through the same `TargetGate` as every other request: only `GET`/`HEAD`/`OPTIONS`, rate-limited, same-origin, no redirects off the target. Reaching any **public** host (e.g. `*.firebaseio.com`) requires `--i-own-this` — without it the probe is blocked, not sent. Payloads are detection-only; Penny never sends destructive input (`DROP TABLE`, writes, deletes).

`<path>` can be a local directory or a git source URL ending in `.git`, including an optional ref suffix:

```bash
python -m penny scan https://github.com/owner/repo.git#main --static-only
```

Git sources are cloned into a temporary local directory and scanned with the same deterministic repo walker as normal local paths.

## Local Demo

Start the deterministic planted target:

```bash
python planted-app/server/app.py
```

Then scan it from another terminal:

```bash
python -m penny run ./planted-app --target http://127.0.0.1:8787
python -m penny ask "What did Red confirm and what should Blue fix first?" --findings .penny/runs/latest/findings.json
python -m penny report --findings .penny/runs/latest/findings.json --export
python -m penny patch --findings .penny/runs/latest/findings.json --repo ./planted-app --out penny.patch
```

Expected outputs:

- `.penny/runs/<session_id>/findings.json`
- `.penny/runs/<session_id>/report.md`
- `.penny/runs/latest/findings.json`
- `.penny/runs/latest/report.md`
- `findings.json`
- `report.md`
- `report.html` and `findings.csv` when `report --export` is used
- `penny.patch` when `patch` is used

The planted app includes a client-visible service-role key, a committed fake secret, a permissive RLS-style policy, a mock Supabase REST endpoint, a BOLA-style order endpoint, known-vulnerable dependency fixtures, and a permissive CORS header.

## Safety Model

Penny only runs read-only HTTP probes (`GET`/`HEAD`/`OPTIONS`). Localhost and private-network targets are allowed by default. Public targets require `--i-own-this`; unsafe methods, request overages, and redirects away from the approved target are blocked by Python guardrails before any request is made.

`--active` probing (SQLi, Firebase open-rules) is more intrusive but stays within these guardrails: read-only methods only, rate-limited, same-origin, and detection-only payloads — Penny never sends destructive input or writes. Public hosts still require `--i-own-this`, so active probes against a hosted backend (e.g. Firebase) are blocked unless you explicitly assert ownership.

Reports and findings are written locally. Store-layer redaction masks service keys, JWTs, API keys, private keys, database URLs, emails, and high-entropy token-shaped values before persistence.

By default Penny only talks to the scan target's localhost. Three features add opt-in outbound calls, and each sends the minimum needed: `ask`/`ask-loop` send the already-redacted findings to the configured Claude model; `--osv` sends only dependency names and versions to OSV.dev; `--ai` sends source code (never gitignored files) to the Claude model. All three degrade to local-only behavior when disabled or unconfigured.

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
- `AI001`: AI-assisted review (opt-in via `--ai`) for issues regex can't catch — including the client/server trust boundary (missing backend / client-trusted mutations), reported as Critical/High. See "AI-assisted detection" above.
- `A001` / `A002`: active-probe findings (opt-in via `--active`) — confirmed SQL injection and an anonymously-readable Firebase database. See "Active probing" above.

Dynamic probes are still read-only. `D004` stores only status codes, object IDs, and ownership comparison results; `D006` stores only CORS headers. The code-pattern detectors (`D008`–`D011`) only scan source files (`.py`, `.js`/`.jsx`, `.ts`/`.tsx`).

### Scan scope and noise control

- **Gitignore-aware.** When the scan path is inside a git work tree, Penny skips files git ignores — so a gitignored local `.env` (the recommended place to keep secrets) is not flagged. A `.env` that is actually tracked/committed is still scanned, since a committed secret is a real finding.
- **Documentation isn't a credential store.** The generic high-entropy heuristic is skipped in `.md`/`.txt`/`.rst`, known-benign high-entropy shapes (subresource-integrity hashes, content hashes / git SHAs, UUIDs) are ignored everywhere, and high-entropy strings inside URLs (Google Docs/Drive share ids, CDN asset hashes) are ignored — so README badges (e.g. `shields.io`), lockfile integrity hashes, asset fingerprints, and doc links don't become findings. Real known-prefix secrets are still flagged even in docs and URLs.
- **Generated output is excluded.** Penny ignores common build/cache directories such as `.next/`, `.nuxt/`, `.svelte-kit/`, `.turbo/`, `dist/`, `build/`, `out/`, `coverage/`, and lock/cache artifacts so reports focus on source code rather than generated manifests.

## CLI-Only Fix Workflow

Penny does not require or ship a web UI. The P2 fix workflow is CLI-only:

```bash
python -m penny patch --findings .penny/runs/latest/findings.json --repo ./planted-app --out penny.patch
python -m penny patch --findings .penny/runs/latest/findings.json --repo ./planted-app --apply
```

Patch previews are redacted so they can be reviewed without writing raw secrets into a patch file. `--apply` is explicit and modifies only the local repo path supplied with `--repo`.

## Mongo Boundary

MongoDB is optional. The core demo works without Mongo, Atlas, RAG, Vultr, GitHub clone support, or a REPL.

When `MONGODB_URI` is configured, Penny mirrors only safe data:

- `vuln_patterns`: generic detector knowledge, remediation text, observation counts, and Atlas-vector-index-ready embeddings.
- `scan_history`: aggregate counts by severity, status, and detector.

Penny does not write reports, app names, target URLs, source snippets, raw evidence, secrets, or code to Mongo.

The CLI can also query the optional knowledge library:

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
