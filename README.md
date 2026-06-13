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

## Commands

```bash
python -m penny scan <path> [--target URL] [--static-only] [--out DIR]
python -m penny report [--findings PATH] [--out DIR]
python -m penny ask "question" [--findings PATH] [--target URL]
python -m penny ask-loop [--findings PATH] [--target URL]
python -m penny run <path> --target URL [--out DIR]
python -m penny patch [--findings PATH] --repo PATH [--out penny.patch] [--apply]
python -m penny demo-replay [--recording PATH] [--out DIR]
```

The CLI uses Typer/Rich when installed and falls back to a standard-library CLI/feed when they are not available.

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

Penny only runs read-only HTTP probes. Localhost and private-network targets are allowed by default. Public targets require `--i-own-this`; unsafe methods, request overages, and redirects away from the approved target are blocked by Python guardrails before any request is made.

Reports and findings are written locally. Store-layer redaction masks service keys, JWTs, API keys, database URLs, emails, and high-entropy token-shaped values before persistence.

## Coverage

Current deterministic checks:

- `D001`: service-role key in client-visible code.
- `D002`: committed secret using known prefixes and entropy heuristics.
- `D003`: permissive RLS/access policy.
- `D004`: dynamic BOLA/IDOR order-read probe.
- `D005`: vulnerable dependency detector for curated high-signal package/version pairs.
- `D006`: permissive CORS detector with dynamic header confirmation.

Dynamic probes are still read-only. `D004` stores only status codes, object IDs, and ownership comparison results; `D006` stores only CORS headers.

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

## Development

```bash
python -m pytest
```

The integration test starts the planted app locally and verifies that the service-role finding is confirmed while raw planted values are absent from persisted outputs.
