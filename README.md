<div align="center">

# 🪙 Penny

### A local-first CLI pentesting assistant for AI-built apps

Scan the code, prove the vulns, fix them, all from one prompt.

<br>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-22c55e.svg)](#license)
[![Built with Claude](https://img.shields.io/badge/AI-Claude-d97757?logo=anthropic&logoColor=white)](https://www.anthropic.com/)
[![MongoDB Atlas](https://img.shields.io/badge/MongoDB-Atlas-47A248?logo=mongodb&logoColor=white)](https://www.mongodb.com/atlas)
[![Vultr](https://img.shields.io/badge/Cloud-Vultr-007BFC?logo=vultr&logoColor=white)](https://www.vultr.com/)
[![OSV.dev](https://img.shields.io/badge/Advisories-OSV.dev-4285F4)](https://osv.dev)
[![Local-first](https://img.shields.io/badge/Local--first-✓-22c55e)](#safety-model)

</div>

---

## What is Penny?

**Penny** is a security tool for the era of vibe-coded apps. Someone ships a Supabase +
Next.js app in a weekend, the service-role key ends up in the client bundle, the database
rules say `allow read, write: if true`, and nobody runs a pentest because pentests are
expensive and slow.

Penny is the pentest. Point it at a repo and it reads the source for real
vulnerabilities, points it at the running app and it proves them with safe, read-only
probes, then writes a developer-focused remediation report, and will even apply the
fixes for you. It runs entirely on your machine by default; every outbound call (Claude,
MongoDB, OSV.dev, Vultr) is **opt-in** and degrades gracefully when it's off.

It is named Penny because good security shouldn't cost a fortune.

```bash
python -m penny            # interactive mode, the recommended way to drive it
```

```text
penny › /target http://127.0.0.1:8787
penny › /audit ./my-app
penny › what should I fix first?
penny › /report
penny › /fix
```

---

## Hackathon write-up

### Inspiration

A wave of AI-built apps ship to production with no backend, no auth model, and secrets
sitting in the client bundle. The people building them aren't security engineers and
can't afford a pentest. We wanted a tool that does what a pentester does, reading the code,
attacking the running app, and explaining the risk in plain language, but one that runs
locally, costs pennies, and meets developers where they already are: a terminal.

### What it does

Penny scans a repository for real vulnerabilities, then confirms the exploitable ones
against a running target with non-destructive, read-only probes. It layers an AI review
pass on top to catch the bugs regex can't reason about, writes a ranked Markdown report,
answers plain-language questions about the findings, and can apply the fixes directly to
your code.

### How we built it

A Python CLI/REPL with a modular scan pipeline: source resolver → repo walker → static
detectors → dynamic/active probes → AI review → redaction → findings store → report/fix.
Claude powers the AI review, the assistant, and the fix engine; OSV.dev backs dependency
scanning; MongoDB Atlas + Voyage AI store a cross-scan knowledge base; and a Vultr GPU
tier runs an uncensored local model for deep, autonomous breach testing. Everything else
is standard-library Python so the core works with zero extra dependencies.

### Challenges we ran into

Keeping the offensive features genuinely safe was the hardest part. Every probe had to
be funneled through one guardrail (read-only methods, rate limits, DNS-proof ownership
checks) so Penny can never hit a target it isn't allowed to. The vLLM server was the
biggest time sink: each GPU box took 30 to 45 minutes to bake (driver, vLLM install,
model download, server warm-up), so every bug fix and reiteration on the sandbox turned
into a waiting game, and we had to get CUDA/driver pinning, abliterated-model tokenizers,
and crash diagnostics right to stop burning whole bake cycles on a single mistake. On top
of that, making sure no raw secret ever reaches disk or an API meant redaction had to be
airtight end-to-end.

### Accomplishments that we're proud of

Penny proves vulnerabilities instead of just listing them, and it does so without ever
sending a destructive request. The safety model is real, not a disclaimer. The whole core
loop (scan, triage, report, fix) works completely offline. And the optional cloud tier
can spin up a GPU, run an autonomous red-team agent, and self-destruct, all behind a
hard cost cap.

### What we learned

A lot of practical offensive security: SQLi confirmation, BOLA/IDOR, the OWASP API and
LLM Top 10, TLS/MitM exposure, CORS preflight abuse, the client/server trust boundary
that breaks "no-backend" apps. On the infra side we learned to provision and tear down
GPU VPS boxes safely (Vultr), serve a model with **vLLM**, and use an **abliterated**
(decensored) model so a red-team agent doesn't refuse its own task, while keeping that
firepower fenced behind ownership proof and auto-destroy timers.

### What's next for Penny

Running a far larger abliterated model on the GPU tier for deeper, more capable autonomous
breach reasoning, and expanding the cloud functions: more attack types, multi-box
parallel runs, and longer agentic exploitation chains. Alongside that, broader language
coverage, deeper Atlas-vector knowledge sharing across scans, and a CI-native mode that
comments findings inline on pull requests.

---

## Quick start

```bash
git clone https://github.com/dzkchen/penny.git
cd penny
pip install -e .          # core: httpx, rich, typer
python -m penny           # launch interactive mode
```

Penny runs with **zero configuration** for static scanning. The optional integrations are
all enabled by dropping a key into a local `.env`:

```bash
cp .env.example .env      # then fill in only what you want
```

| Extra | Install | Unlocks |
|-------|---------|---------|
| AI | `pip install -e ".[llm]"` (or just `ANTHROPIC_API_KEY`) | AI review, the assistant, the fix engine |
| Mongo | `pip install -e ".[mongo]"` + `MONGODB_URI` | Cross-scan knowledge base & trends |
| Browser | `pip install playwright && playwright install` | `--browser` crawl/probe |
| Cloud | `VULTR_API_KEY` | GPU sandbox tier |

**Requires Python 3.11+.** Every optional dependency is optional; Penny degrades to
local-only behaviour when a key or package is absent.

---

## Main features

| Feature | What it does |
|---------|--------------|
| **Audit** | One command (`/audit`) runs the full pipeline: scan + AI review + every probe + report. |
| **Scan** | Static source analysis with 20+ deterministic detectors (secrets, RLS, SSRF, XSS, injection, weak crypto, the client/server trust boundary, and more). No target needed. |
| **AI scan / review** | `--ai` sends bounded, line-numbered source to Claude to catch what regex can't (broken auth, indirect-flow injection, missing ownership checks, the OWASP LLM Top 10), plus a secret-triage pass that drops benign high-entropy noise. |
| **Active probing** | `--active` sends non-destructive, read-only payloads to a consented live target to confirm SQLi, open Firebase rules, weak headers/cookies/methods, CORS, TLS/MitM exposure, and more. |
| **Brute / browser / netscan** | Wordlist path & login discovery (`--brute`), a real Playwright crawl (`--browser`), and a read-only TCP-connect port scan (`--netscan`). |
| **OSV dependency scan** | `--osv` checks every npm/PyPI dependency against the live [OSV.dev](https://osv.dev) feed for real CVEs and fixed versions. |
| **VPS vLLM sandbox** | `sandbox-bake` / `sandbox-test` spin up a Vultr GPU box serving an **abliterated** model via **vLLM**, run an autonomous breach agent against a target you own, then self-destruct under a hard cost cap. |
| **Report & fix** | `/report` writes a ranked Markdown report; `/fix` proposes and applies local code changes with approval. |
| **AI assistant** | Ask plain-language questions about the loaded findings; answered by Claude when configured, by deterministic local logic otherwise. |
| **Knowledge base** | Optional MongoDB Atlas + Voyage AI store generic patterns and trends across scans (`/knowledge`, `/trends`). |

See **[coverage.md](coverage.md)** for the complete detector catalogue.

---

## Architecture

```text
        ┌────────────────────────────┐
        │   Developer (REPL / CLI)    │   repl.py, cli.py
        └─────────────┬──────────────┘
                      │
                      ▼
        ┌────────────────────────────┐
        │   Source resolver          │   sources.py   (local path or git URL#ref)
        └─────────────┬──────────────┘
                      │
                      ▼
        ┌────────────────────────────┐
        │   Repo walker              │   repo.py      (gitignore-aware)
        └─────────────┬──────────────┘
                      │
                      ▼
   ╔════════════════════════════════════════════════════════════╗
   ║                  Scan orchestrator                         ║   scanner.py
   ╚═══╤══════════╤══════════╤══════════╤══════════╤════════════╝
       │          │          │          │          │
       ▼          ▼          ▼          ▼          ▼
  ┌─────────┐┌─────────┐┌─────────┐┌─────────┐┌──────────────┐
  │ Static  ││ Dynamic ││ Active  ││   AI    ││ OSV advisory │
  │detectors││ probes  ││ probes  ││ review  ││    lookup    │
  │detectors││probes.py││active.py││ai_      ││advisories.py │
  │  .py    ││         ││transport││review   ││              │
  │         ││         ││netscan  ││  .py    ││              │
  │         ││         ││browser  ││         ││              │
  │         ││         ││writes   ││         ││              │
  │         ││         ││loadtest ││         ││              │
  └────┬────┘└────┬────┘└────┬────┘└────┬────┘└──────┬───────┘
       │          │          │          │            │
       └──────────┴──────────┴──────────┴────────────┘
                      │
                      ▼
        ┌────────────────────────────┐
        │   Finding models           │   models.py    (dedupe, IDs, fingerprint)
        └─────────────┬──────────────┘
                      │
                      ▼
        ┌────────────────────────────┐
        │   Redaction                │   redaction.py (mask before persist)
        └─────────────┬──────────────┘
                      │
                      ▼
        ┌────────────────────────────┐
        │   Findings store           │   store.py     .penny/runs/<id>/ + latest/
        └──┬───────────┬──────────┬──┘
           │           │          │
           ▼           ▼          ▼
   ┌──────────────┐ ┌────────┐ ┌──────────────────┐
   │   Report     │ │  Ask   │ │  Fix / Patch     │
   │ reporting.py │ │ ask.py │ │ agent_fix.py     │
   │  report.md   │ │        │ │ patches.py       │
   └──────────────┘ └────────┘ └──────────────────┘

  Optional, opt-in services
  =========================
   Claude    llm.py / ai_review.py / ask.py / agent_fix.py    (review, chat, fix)
   OSV.dev   advisories.py                                     (dependency CVEs)
   Mongo     mongo.py + embeddings.py (Voyage AI)              (knowledge base)
   Vultr     vultr.py / cloud.py / sandbox.py (vLLM)           (GPU breach sandbox)

  Every live request, from static probe to GPU sandbox, passes through one TargetGate
  (guardrails.py): read-only methods, rate limited, same-origin, ownership-proofed.
```

---

## Interactive mode

Run `penny` with no arguments to launch the REPL. It auto-loads the most recent scan,
shows whether AI is available, and keeps the current findings and target in session so
you can move through scan → triage → report → fix without copying file paths around.

```text
penny › /target http://127.0.0.1:8787   # confirm issues against a running app
penny › /audit ./my-app                 # full pipeline (natural language works too)
penny › /findings                       # ranked table
penny › /show F-001                     # one finding in detail
penny › what should I fix first?        # ask the assistant
penny › /report                         # write report.md
penny › /fix                            # propose & apply fixes with approval
```

Natural language routes to the right command: "pentest ./my-app", "explain F-002",
"set target to https://…", and "i own this" all work. Colour is used on a TTY and
disabled automatically when piped.

### Interactive commands

```text
/audit <path> [--target <url>] [--i-accept]   full audit: scan + AI + every probe + report
/full  <path> [--target <url>]                alias for /audit
/scan  <path> [flags]                          static or targeted scan (flags below)
/report                                        write report.md to .penny/runs/
/fix [--yes]                                    propose & apply fixes (approval unless --yes)
/findings  (/ls)                               list current findings
/show <F-001>                                  show one finding in detail
/target <url|off>                              set or clear the live probe target
/own <on|off>                                  confirm you own the target
/ai <on|off>                                   toggle AI answers / review
/model <auto|haiku|sonnet>                     pick the Claude model for the session
/knowledge [query]                             search the Mongo knowledge base
/cloud-attack <type> [opts]                    heavy attack on a Vultr box (auto-destroys)
/sandbox-bake [--yes]                          one-time: build the GPU vLLM snapshot
/sandbox-test [target] [--keep-alive]          ephemeral GPU breach, then self-destruct
/boxes  ·  /kill  ·  /destroy                  list / stop / destroy cloud boxes
/clear  ·  /help  ·  /exit
```

`/scan` flags: `--target <url>` `--osv` `--ai` `--active` `--agentic` `--brute`
`--browser` `--netscan` `--load-test` `--i-accept` `--i-own-this` `--static-only`.

---

## Scriptable equivalents (CI & automation)

These read and write the same `.penny/runs/latest` state the REPL auto-loads, so you can
mix interactive triage with scripted runs.

```bash
# Scan: full flag surface
python -m penny scan <path> [--target <url>] [--static-only] [--out <dir>] \
    [--osv] [--ai] [--active] [--agentic] [--brute] [--browser] [--netscan] \
    [--load-test] [--i-accept] [--i-own-this] [--fail-on <severity>] \
    [--diff <ref>] [--endpoint '<path?param>'] [--wordlist <file>] [--pages <n>] [-v] \
    [--sandbox-test] [--allow-destructive]

python -m penny run <path> --target <url> [...same flags as scan...]   # scan + report in one
python -m penny report  [--findings <path>] [--out <dir>] [--ai]
python -m penny ask "question" [--findings <path>] [--target <url>] [--no-ai]
python -m penny ask-loop [--findings <path>] [--target <url>] [--no-ai]
python -m penny fix     [--findings <path>] [--repo <path>] [--yes]
python -m penny patch   [--findings <path>] --repo <path> [--out penny.patch] [--apply]
python -m penny github-fix <owner/repo> [--branch <name>] [--yes] [--push]
python -m penny model   [auto|haiku|sonnet]
python -m penny knowledge "query" [--limit 5]
python -m penny trends  [--days 7] [--limit 10]
python -m penny sandbox-bake [--yes]
python -m penny sandbox-test --target <url> [--i-own-this] [--keep-alive] [--allow-destructive] [--yes]
python -m penny demo-replay [--recording <path>] [--out <dir>]
```

The CLI uses Typer/Rich when installed and falls back to a stdlib parser when they aren't.
Running `python -m penny` with no subcommand is still the recommended starting point.

### Gating CI / PRs

For CI, use `scan` with `--fail-on <severity>` (Critical/High/Medium/Low/Info). Penny
exits `1` when any finding is at or above that severity; usage/scan errors exit `2`.
`--diff <ref>` scans only files changed versus a git ref so PR runs stay fast, and
`--endpoint` points the SQLi probe at endpoints an SPA builds dynamically.

```bash
python -m penny scan . --diff main --osv --fail-on high
python -m penny scan ./app --active --i-own-this --target https://app.example.com \
    --endpoint '/api/users?id=1'
```

---

## AI assistant

Inside the REPL, plain-language questions answer against the loaded findings:

```text
penny › what did the active probes confirm, and what should I fix first?
penny › summarize F-001 and how to fix it
penny › /ai off
```

Penny reads `ANTHROPIC_API_KEY` from the environment or a local `.env`. `/model` (or
`PENNY_MODEL_MODE`) selects between `auto` (Haiku for chat, Sonnet for real work),
`haiku`, or `sonnet`. **Questions only send the already-redacted findings JSON**, never
raw source, raw secrets, or `secret_value` fields. With no key, the request off, or any
error, Penny falls back to deterministic local answers so the flow still works offline.

---

## Local demo

Penny ships with a deliberately vulnerable demo app. Start it in one terminal:

```bash
python planted-app/server/app.py
```

Then drive Penny from another terminal:

```text
$ python -m penny
penny › /target http://127.0.0.1:8787
penny › /audit ./planted-app
penny › what did the probes confirm, and what should I fix first?
penny › /report
penny › /fix
```

Outputs land in `.penny/runs/<session_id>/` and `.penny/runs/latest/`
(`findings.json` + `report.md`). The demo app contains a client-visible service-role key,
a committed fake secret, a permissive RLS policy, a mock REST endpoint, a BOLA-style order
endpoint, known-vulnerable dependency fixtures, and a permissive CORS header, so every
layer of the pipeline has something real to find and confirm.

---

## Safety model

Penny is built to be safe to run against software you own. The guardrails are code, not
guidelines; they sit in `guardrails.py` and block disallowed requests before they are
sent.

- **Read-only by default.** Only `GET` / `HEAD` / `OPTIONS`. Unsafe methods, request
  overages, and redirects away from the approved target are blocked.
- **Localhost / private targets** are allowed out of the box. **Public targets** require
  `--i-own-this` **and** a matching DNS `TXT` proof record (`_penny.<host>` publishing
  `penny-verify=authorized`, configurable). Without both, the probe is blocked, not sent.
- **One gate for everything.** Active probes, the `--netscan` TCP-connect scan, the
  `A011` TLS handshake, and the GPU sandbox all share the same `host_allowed` gate.
- **Detection-only payloads.** Penny never sends destructive input (`DROP TABLE`, writes,
  deletes). The `--i-accept` write probe is the one exception (POST-only, benign marked
  records, never PUT/PATCH/DELETE) and is strictly opt-in.
- **MitM exposure, not interception.** `A011` reports the weaknesses that enable a
  man-in-the-middle; Penny deliberately never implements interception.
- **Redaction before persistence.** The store layer masks service keys, JWTs, API keys,
  private keys, database URLs, emails, and high-entropy token-shaped values before
  anything is written to disk or sent to a model.

---

## What the optional services are used for

All four are **opt-in** (a key or flag turns them on) and **opt-out** (absent key, a
`PENNY_DISABLE_*` env var, or omitting the flag turns them off). Penny works fully without
any of them.

| Service | Used for | Turn on | Turn off | What leaves the machine |
|---------|----------|---------|----------|-------------------------|
| **Claude (Anthropic)** | AI review (`--ai`), the assistant, secret triage, the fix engine, agentic probes | `ANTHROPIC_API_KEY` | unset key, `PENNY_DISABLE_LLM=1`, `/ai off` | `--ai` sends bounded source (never gitignored); the assistant and report send only **redacted** findings |
| **MongoDB Atlas** | Cross-scan knowledge base (`vuln_patterns`) and history/trends (`scan_history`) | `MONGODB_URI` | unset URI, `PENNY_DISABLE_MONGO=1` | Only aggregate stats and generic patterns; never reports, app names, targets, snippets, secrets, or code |
| **Voyage AI** | Real semantic embeddings for the Mongo vector index (falls back to deterministic hash embeddings) | `VOYAGE_API_KEY` | unset key, `PENNY_DISABLE_VOYAGE=1` | Only generic pattern text (title/impact/remediation); no secrets or scan details |
| **OSV.dev** | Real dependency advisories: CVEs, severities, fixed versions (`--osv`) | `--osv` flag | omit `--osv` | Only package **names and versions** (public info) |
| **Vultr (+ vLLM)** | GPU box serving an abliterated model for autonomous breach testing (`sandbox-*`) | `VULTR_API_KEY` + `--i-own-this` + DNS proof | unset key | Only the (owned, proofed) target URL is sent to the remote agent; code, `.env`, and keys never leave |

---

## Development

```bash
python -m pytest
```

The integration test starts the planted app locally and verifies that the service-role
finding is confirmed while raw planted values are absent from persisted outputs.

---

## License

MIT. See the badge above. (Add a `LICENSE` file to make it official.)

<div align="center">
<br>
<sub>Built for developers shipping fast, so the security review doesn't have to wait for a budget.</sub>
</div>
