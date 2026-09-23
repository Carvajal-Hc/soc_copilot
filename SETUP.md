# Setup

Everything needed to run SOC Copilot against your own Splunk: install, choose a backend,
configure, build the demo index, and run it. The short version is the quickstart in the
[README](README.md).

## Install

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Python 3.11+ is required. Every command below is written as `python -m soc_copilot`, which
runs from the repository root without installing the package. If you would rather have the
`soc-copilot` command on your PATH, install the project itself as well:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
```

Then pick a backend. The tool will not generate SPL until you do, and will not pick one for
you.

**Local, air-gapped.** Install [Ollama](https://ollama.com/download), then pull the model:

```powershell
ollama pull qwen2.5-coder:14b
```

The 14B is the one to pull. `qwen2.5-coder:7b` is the code default and it is enough for
single-search questions, but it did not complete a two-step pivot in any of three attempts
(see [the trade-off](NOTES.md#backend-trade-off-and-limits)). Ollama must be running when you ask a question;
the client talks to `http://localhost:11434` unless `OLLAMA_HOST` says otherwise.

**Hosted.** The Anthropic SDK is an optional extra, deliberately not in `requirements.txt` so
the air-gapped path never needs it:

```powershell
.\.venv\Scripts\python.exe -m pip install anthropic
```

## Configure

Two Splunk settings, never hardcoded:

| Variable | Required | Default |
| --- | --- | --- |
| `SPLUNK_HOST` | no | `https://localhost:8089` |
| `SPLUNK_TOKEN` | **yes** | — |

Set them as environment variables, or copy `.env.example` to `.env` and fill it in.
**Environment variables take precedence over `.env`.** `.env` is git-ignored; only the
blank `.env.example` template is versioned.

Create the token in Splunk Web under **Settings > Tokens > New Token**. Token
Authentication must be *enabled* on that same page, otherwise Splunk answers every
tokenised request with `401 call not properly authenticated`.

> The token is a secret belonging solely to the deterministic client. It must never be
> placed in an LLM prompt or accepted through a chat interface. `SplunkConfig` keeps it out
> of its `repr()` and out of `describe()` so it cannot leak into logs.

Backend selection is explicit and opt-in. With none configured, generation fails with
instructions rather than guessing SPL.

```powershell
$env:SOC_LLM_BACKEND = "ollama"      # local; nothing leaves the machine
$env:SOC_LLM_BACKEND = "anthropic"   # hosted; needs ANTHROPIC_API_KEY
```

`SPLUNK_TOKEN` is never sent to either backend. Every prompt is scanned for it before
transmission, and a match is a hard failure. `.env.example` documents the remaining optional
settings (`SOC_LLM_MODEL`, `OLLAMA_HOST`, `SOC_LLM_TIMEOUT`, …).

## Use

```powershell
.\.venv\Scripts\python.exe -m soc_copilot verify   # known-good search, then the schema
.\.venv\Scripts\python.exe -m soc_copilot schema   # indexes, sourcetypes, full field list
.\.venv\Scripts\python.exe -m soc_copilot search "index=logforge | head 5"

# Stage 2: translate only; prints the SPL and time range, does not run it
.\.venv\Scripts\python.exe -m soc_copilot shape                      # nested structure
.\.venv\Scripts\python.exe -m soc_copilot generate "how many processes ran per host"
.\.venv\Scripts\python.exe -m soc_copilot generate --dry-run "..."   # prompt only, no LLM

# Stage 3/4: investigate, with pivots, guardrails, and a choice of view
.\.venv\Scripts\python.exe -m soc_copilot investigate "what did the cmd.exe process spawn?"
.\.venv\Scripts\python.exe -m soc_copilot investigate --max-steps 8 "..."
.\.venv\Scripts\python.exe -m soc_copilot investigate --view spl "question"     # the query
.\.venv\Scripts\python.exe -m soc_copilot investigate --view json "question"    # tooling

# the local web UI
.\.venv\Scripts\python.exe -m soc_copilot serve      # http://127.0.0.1:8765/
```

Common flags: `--index`, `--earliest`, `--latest`, `--limit`, `--include-internal`, `-v`.

| view | for | contains |
| --- | --- | --- |
| `human` | an analyst reading the result | the answer, the SPL behind it, the rows behind that, and every guardrail that fired |
| `spl` | pasting into Splunk | the queries and their time ranges, nothing else |
| `json` | case management, notebooks, diffing two runs | a versioned schema with every guardrail outcome machine-readable |

## The dataset this demo runs on

Everything assumes a Splunk index called `logforge`, and **you have to build that index
yourself**. No data ships with this repository. If you skip this section, `verify`
connects and every query returns nothing.

The demo data is the **[LogForge](https://app.hackthebox.com/sherlocks) Sherlock from Hack The
Box**, a Windows host triage collection. Any comparable evidence set works; this one is named
because it is what every number in `NOTES.md` was measured against.

**Parse the artifacts to CSV** with Eric Zimmerman's tools. Three of them, because the
questions in the library span three artifacts:

| tool | artifact | output used here |
| --- | --- | --- |
| `EvtxECmd` | Windows event logs (Sysmon + Security) | `logforge_evtx.csv` |
| `MFTECmd` | `$MFT` | `logforge_mft.csv` |
| `PECmd` | Prefetch | `logforge_pf.csv` |

**Ingest all three into one index named `logforge`, under one sourcetype (`csv`).** Two
details matter, and both were learned the hard way:

* **Keep the three filenames distinct, and keep them.** One index and one sourcetype means
  `source` is the *only* thing separating an MFT row from a Sysmon row. Two library entries
  scope on it directly (`prefetch-last-execution` on `source="*logforge_pf.csv"`,
  `mft-files-created-in-path` on `*logforge_mft.csv`), the library's header block maps all
  three filenames to the fields they carry, and `pick-the-source-for-the-question` exists
  purely to teach the model to route a question to the right artifact. Merge or rename them
  and that routing stops working. For scale, the reference ingest was 120,264 evtx rows, 163,385 MFT
  rows and 172 prefetch rows.
* **`_time` must come from the event, not from ingest time.** The all-time default
  (`earliest="0"`) exists precisely because this data is historical, but every `stats
  latest(_time)`, every timeline and every "when did X last run" depends on `_time` being the
  real timestamp. The catch is that the three CSVs do not share a timestamp column:
  EvtxECmd's is the event's creation time, MFT rows carry `Created0x10` / `LastModified0x10`,
  and prefetch carries `LastRun` / `PreviousRun0`. Only the evtx timestamp was verified to
  land in `_time` in the reference ingest; the MFT and prefetch entries read their time
  columns as ordinary fields and do not rely on `_time`. If you want a single unified
  timeline across all three, you have to do that props/transforms work yourself; this
  repository does not do it.

**Confirm it landed** before asking anything:

```powershell
.\.venv\Scripts\python.exe -m soc_copilot verify   # known-good search, then the schema
.\.venv\Scripts\python.exe -m soc_copilot schema   # per-sourcetype counts and the time range
```

`schema` prints the first and last event time it found. If that range is not what you
expect, fix the ingest before going further. A wrong `_time` produces queries that run
cleanly and answer nothing.

**Using a different index name?** Pass `--index yours` to any command. That covers the
engine, but not the shipped detections. See [the trade-off](NOTES.md#backend-trade-off-and-limits) for what
else has to change.

## Tests

```powershell
.\.venv\Scripts\python.exe -m pytest         # 482 tests, no Splunk or model needed
.\.venv\Scripts\python.exe -m ruff check .   # lint
.\.venv\Scripts\python.exe -m mypy           # types
.\.venv\Scripts\python.exe -m pytest -m live # 43 more, against a real Splunk
```

The first three run on every push, across Python 3.11/3.12/3.13 on Linux and Windows
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)). CI also fails the build if a real
`.env` is ever tracked or if the committed template stops being blank. `.gitignore` states
the intent, and that job is what enforces it. What the default, `live` and adversarial
suites cover: [`NOTES.md`](NOTES.md#tests--what-the-suites-cover).
