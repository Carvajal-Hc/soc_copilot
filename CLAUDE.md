# Project: SOC Copilot

A natural-language triage assistant over Splunk for DFIR / SOC work.

## What it is
The analyst asks a question in plain language. The system translates it to SPL, runs it
against a local Splunk instance over the REST API, reads the returned rows, and answers —
optionally pivoting with follow-up searches.

## Positioning (informs where to spend effort)
Splunk's own AI Assistant already does cloud-based NL->SPL. Do NOT try to out-engineer the
translator; "correct and grounded" is enough there. The differentiated value of this
project is:
  1. Air-gapped operation: a local LLM backend so nothing leaves the machine — usable
     where the cloud assistant is forbidden (sensitive evidence, restricted networks).
  2. Untrusted-input defense: log field values can contain attacker-planted instructions;
     the system treats them as untrusted and does not obey them (Stage 4).
  3. Honesty about scope: it answers what the indexed data supports and plainly says when
     it cannot, instead of fabricating.
Concentrate engineering effort on Stage 2 (pluggable LLM, incl. the local backend) and
Stage 4 (guardrails + injection defense).

## Non-negotiable architecture (do not violate)
- Splunk is the single source of truth. The LLM NEVER produces a literal value
  (hash, host, SID, IP, filename) from its own knowledge. Every literal in an answer
  MUST come from a row returned by Splunk.
- The LLM's only job is: (a) translate a natural-language question into SPL, and
  (b) interpret rows Splunk returned. It does not "know" answers; it queries them.
- The system is read-only against Splunk. It runs searches. It never mutates.

## Scope boundary (state it, don't paper over it)
- The tool answers questions answerable from data ingested into Splunk.
- Raw-artifact work (content resident inside $MFT, UTF-16 strings, byte-level carving) is
  OUT OF SCOPE and belongs to the human analyst. When a question cannot be answered from
  indexed data, the tool says so plainly. "Not found" means "not in what was ingested" —
  never "does not exist," and never a fabricated value.

## Credentials & configuration (secrets never touch code or the LLM)
- Required config: SPLUNK_HOST (e.g. https://localhost:8089) and SPLUNK_TOKEN.
- Load config from environment variables OR a local .env file (via python-dotenv),
  environment taking precedence. Never hardcode secrets. Never prompt for a password.
- The token is a secret for the deterministic Splunk client only. It MUST NEVER be passed
  into an LLM prompt or accepted through the chat interface — that would send it to an
  external model. Keep it on the deterministic side of the system.
- Ship a versioned .env.example (keys present, values blank) as a template. Add a
  .gitignore that ignores .env so the real secret never enters git.

## Auth failures fail legibly
- On HTTP 401 from Splunk, do not raise a raw exception. Return a clear, actionable
  message: the token was rejected (expired or invalid); regenerate it in Splunk under
  Settings > Tokens and re-provide SPLUNK_TOKEN.

## LLM is pluggable
Define one interface — generate_spl(question, schema, library) -> spl and
interpret(rows, question) -> answer. Behind it, support at least two backends: an API
backend (e.g. Anthropic) and a local backend (e.g. Ollama). Backend is chosen by
config/env, opt-in. The rest of the system must not know which backend is active. With no
backend configured, fail with a clear message — never silently guess SPL.

## Field names
Never invent Splunk field names or sourcetypes. Read the real schema from the live index
and generate SPL against those exact names.

## Known lab environment (build against this reality)
- Index: logforge   |   sourcetype: csv
- REST management API: https://localhost:8089 (self-signed cert — see Stage 1)
- Three artifacts share the one index and the one sourcetype, told apart only by `source`:
    logforge_evtx.csv   120,264   EvtxECmd; Sysmon + Security, values nested inside Payload
    logforge_mft.csv    163,385   MFTECmd; flat fields, no Payload
    logforge_pf.csv         172   PECmd;   flat fields, no Payload
  283,821 events in total.
- Data is historical: 2021-11-21 to 2025-08-11. Time ranges must not default to "last 24
  hours." The span is wide because the MFT carries file timestamps far older than the
  collection; the evtx activity itself is around 2025-08-11.
- Fields confirmed present from the ingest preview (non-exhaustive; Stage 1 enumerates the
  authoritative full set): _time, Channel, ChunkNumber, Computer, EventId, EventRecordId,
  ExecutableInfo, HiddenRecord, Keywords, Level, MapDescription.

## Style
Python 3.11+, typed, tested. Small, reviewable modules. Fail closed. Be honest about limits.