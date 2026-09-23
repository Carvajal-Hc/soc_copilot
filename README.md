# SOC Copilot

Ask a Splunk index a triage question in plain English — answered only from the rows Splunk
returns, and able to run fully air-gapped.

<!-- GIF here -->

- **Air-gapped by choice.** With the local backend (Ollama), the question, the schema and
  every row stay on the machine, so it works where a cloud assistant is forbidden. A hosted
  backend (Anthropic) is opt-in.
- **Every answer is anchored to real rows.** Each hash, path, GUID, SID and IP in an answer
  is traced to the step, row and field that supplied it. Anything that cannot be traced is
  rewritten to `[UNVERIFIED: …]`. Searches are read-only, enforced by an allowlist.
- **Log values are treated as hostile.** Every field value is sealed as data before a model
  sees it, so `ignore previous instructions` planted in a command line does not change the
  verdict. A test pins that.
- **Honest about its limits.** It says "not in this data" rather than guess. The trade-off:
  a local 14B is reliable on single searches but completed only **2 of 3** two-step pivots
  (7B: **0 of 3**), and its reach is roughly the coverage of the curated library.
  [See the trade-off ↓](#backend-trade-off)

### Quickstart

Needs a Splunk instance with evidence indexed ([dataset ↓](#dataset)) and
[Ollama](https://ollama.com/download) running.

```powershell
git clone https://github.com/Carvajal-Hc/soc_copilot.git; cd soc_copilot
python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt
ollama pull qwen2.5-coder:14b
copy .env.example .env   # set SPLUNK_TOKEN, SOC_LLM_BACKEND=ollama, SOC_LLM_MODEL=qwen2.5-coder:14b
.\.venv\Scripts\python.exe -m soc_copilot serve   # → http://127.0.0.1:8765/
```

How it works and what it learned along the way: [`NOTES.md`](NOTES.md) (findings F1–F6 and
the design reference).

---

<a name="backend-trade-off"></a>
<details>
<summary><b>What you get depends on which backend you run</b> — the trade-off and the limits</summary>

The pluggable LLM layer exists to give you this trade-off. Understand it before anything
else, because it decides what the tool can actually answer.

**Local (`ollama`, a 14B): fully air-gapped, and it leans on the library.** Nothing leaves
the machine: not the question, not the schema, not a row. The cost is reasoning. A 14B does
not work out an unfamiliar question from first principles; it adapts the closest example it
was shown. So its competence is roughly the coverage of
[`spl_library.toml`](soc_copilot/spl_library.toml). Ask something the library covers and it is
good. Ask something outside it and the realistic outcomes are a query that runs but answers a
near-miss question, or an honest "not in this data". When the data is in fact there, that
second outcome is the most dangerous failure this system has (F6 in [`NOTES.md`](NOTES.md)).
Extending the library is the normal way to extend the local path, not a workaround.

**Hosted (`anthropic`): handles questions nobody curated, but your evidence leaves the
machine.** The question and the discovered schema go to a third party. In return you get a
model that can compose a query for a question the library never anticipated. If the evidence
is sensitive or the network is restricted, you cannot make that trade, which is why the local
path exists.

Both paths run through identical guardrails. Read-only enforcement, literal anchoring and the
untrusted-input envelope are deterministic Python either way; the backend changes what gets
asked, never what is allowed.

**What the local path actually costs.** Measured on this lab (16GB, `qwen2.5-coder`):

| | 7B | 14B |
| --- | --- | --- |
| single-search questions | works | works |
| two-step pivot (find an event, then follow that exact process) | 0 of 3 attempts | 2 of 3 |
| per turn | ~60–90s | ~90–120s, growing with the transcript |

The 14B only reached 2 of 3 after the library was given an entry demonstrating the two-turn
shape. A two-hop investigation on the 14B takes minutes, not seconds. That is the cost of
the air-gapped path, and you should know it before choosing that path. Because those
numbers are normal rather than pathological, `SOC_LLM_TIMEOUT` defaults to **900s for the
local backend** and 120s for the hosted one. A hosted API silent for two minutes is broken,
whereas a local model silent for two minutes is thinking. A local timeout says so explicitly
instead of reading as an outage. See F3 and F5 in [`NOTES.md`](NOTES.md).

**The shipped detection library is tuned to this dataset and is not portable.** Field
*names* are discovered at runtime and nothing is hardcoded per dataset, but that claim stops
at field names:

* `schema.py` defaults `--index` to `logforge`.
* **15 of the 20** entries filter `Channel="Microsoft-Windows-Sysmon/Operational"`. On an
  index without Sysmon they return zero rows: valid SPL, real fields, nothing found.
* **2** filter a source filename directly (`source="*logforge_pf.csv"`,
  `*logforge_mft.csv`), and the library's header block names all three CSVs as the map of
  which artifact holds which fields.
* **1** filters `Channel="Security"` for logon events.
* **2** are artifact-agnostic and would run anywhere (`event-volume-by-type`,
  `pick-the-source-for-the-question`).

The engine is general; the shipped detections are a starter set for one collection. The
discovery layer will read your schema and the guardrails will police your
queries, but the examples the model adapts from are these.

`soc_copilot/spl_library.toml` holds known-good detections (attack -> canonical SPL). The
generator retrieves the closest entries and adapts their *pattern*; it does not improvise
from zero. Retrieval always includes both a flat-filtering and a payload-extraction example,
so the contrast is always in front of the model.

**On any dataset other than this one, you must replace the shipped entries before relying
on the tool.** The 20 entries here encode a specific collection: Sysmon channel names, three CSV
source filenames, the event ids that collection contains. Point the tool at a different index
and the majority of them match nothing, which on the local backend is the worst case: the
model has no near example to adapt, so it produces a near-miss query or concludes the data is
absent. Budget for writing entries against your own data before judging the local path. The
loader validates structure and fails closed on a malformed entry, so a bad one is a startup
error rather than a bad answer.

What the shipped set does cover, for calibration: Sysmon event ids 1, 3, 10, 11 and 22;
Security 4624 (interactive logon only); MFT file-creation by path; prefetch last-execution;
and several artifact-agnostic methodology entries (stack counting, outliers, payload
extraction, the two-step pivot). It does **not** cover registry persistence, scheduled tasks,
service creation, image/driver load, remote thread injection, named pipes, WMI, failed logons,
log clearing, PowerShell script-block logs, or browser history. Those questions have no
covering entry today.

**Validity is not correctness.** A query can pass every guardrail and still answer the wrong
question (F1). An advisory check warns when the query's output carries no field of the kind
the question asks about (F4), but it does not verify the answer is right. That is why every
view shows the SPL and the rows beside the answer.

**Scope.** SOC Copilot answers only what is indexed in Splunk. Raw-artifact work (content
resident inside `$MFT`, UTF-16 strings, byte-level carving) is out of scope and belongs to
the human analyst. "Not found" means "not in what was ingested", never "does not exist".
[`SCOPE-BOUNDARY.md`](SCOPE-BOUNDARY.md) works one such case end to end: the tool pivots to
find that a PowerShell process wrote `C:\Users\Public\README.txt`, correctly refuses to say
what the file *contains*, and the analyst recovers the text from `$MFT`, where it turns out
to be resident in 406 bytes behind a UTF-16 BOM. It also separates two mechanisms that
are easy to conflate: the model declining is behaviour; literal anchoring is the guarantee.

</details>

<details>
<summary><b>Full setup</b> — install, backends, configuration, commands</summary>

### Install

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
(see [the trade-off](#backend-trade-off)). Ollama must be running when you ask a question;
the client talks to `http://localhost:11434` unless `OLLAMA_HOST` says otherwise.

**Hosted.** The Anthropic SDK is an optional extra, deliberately not in `requirements.txt` so
the air-gapped path never needs it:

```powershell
.\.venv\Scripts\python.exe -m pip install anthropic
```

### Configure

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

### Use

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

</details>

<a name="dataset"></a>
<details>
<summary><b>The dataset this demo runs on</b> — you have to build the index</summary>

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
engine, but not the shipped detections. See [the trade-off](#backend-trade-off) for what
else has to change.

</details>

<details>
<summary><b>Architecture</b> — four stages, one source of truth</summary>

The analyst asks a question in plain language; the system translates it to SPL, runs it
read-only against a local Splunk instance, reads the rows that come back, and answers from
those rows. It can also pivot: take an identifier out of one search's rows and filter the
next search on it. The model decides *what to ask*; Splunk decides *what is true*.

| stage | what it adds |
| --- | --- |
| 1 | config, an authenticated read-only REST client, real schema discovery |
| 2 | question -> SPL, grounded in the discovered schema and a curated library |
| 3 | the tool-using loop: run a search, read the rows, pivot, answer |
| 4 | the guardrails as hard code, and three renderings of the result |

**Stage 1 contains no LLM code of any kind.** It loads configuration (host + token) from the
environment or a local `.env`, talks to Splunk's REST API over an authenticated, **read-only**
client, and discovers the *real* schema (indexes, sourcetypes and field names) off the live
index. Everything a later stage says about the data is grounded in rows this layer returned.
Time ranges default to all-time, not `-24h`, because evidence is historical; TLS is relaxed
for loopback only; a 401 surfaces as an actionable message, never a traceback.

**Stage 2** translates a question into SPL against the discovered schema, including 827
nested names found inside the `Payload` column at runtime, and adapts the closest entries in
the curated library. Every generated query is validated against that schema before it is
shown.

**Stage 3** gives the model exactly one capability, `run_search`. It emits a JSON action,
deterministic Python validates and runs it, and hands back the rows. Every executed query,
its time range, its row count and its outcome are printed as they happen.

**Stage 4** stops asking the model to behave: read-only enforcement by allowlist, literal
anchoring, and nonce-sealed untrusted input are deterministic code in
`soc_copilot/guardrails.py`, plus an advisory check that the query answers the question
asked. The web UI is a loopback-only skin over the same engine and the same guardrails.

How each of these works, and why: [Design reference in `NOTES.md`](NOTES.md#design-reference).

```
soc_copilot/
  config.py          SPLUNK_HOST / SPLUNK_TOKEN loading, TLS policy, secret hygiene
  splunk_client.py   authenticated read-only REST client; dispatch -> poll -> results
  schema.py          indexes, sourcetypes, real field names
  payload_shape.py   Stage 2: runtime discovery of nested payload structure
  library.py         Stage 2: curated known-good SPL, loaded from spl_library.toml
  llm/               Stage 2: pluggable backends (anthropic | ollama)
  generator.py       Stage 2: question -> grounded prompt -> SPL + time range
  validation.py      Stage 2: deterministic checks on whatever the model returns
  agent.py           Stage 3: the tool-using loop - search, read rows, pivot, answer
  guardrails.py      Stage 4: read-only enforcement, literal anchoring, untrusted input
  semantics.py       does the query answer the question? (advisory, see F4)
  views.py           Stage 4: one result, three renderings (human | spl | json)
  web.py             local web UI: loopback-only chat skin over investigate
  cli.py             verify / schema / shape / search / generate / investigate
tests/               482 tests, all offline against fakes — no live Splunk needed
```

</details>

<details>
<summary><b>Tests</b></summary>

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

</details>

## Security

[`SECURITY.md`](SECURITY.md) states the threat model, maps each defended property to the
code that enforces it and the test that pins it, and, just as importantly, lists what is *not*
defended: there is no user model, the hosted backend sends data off the machine by design,
and the model's reasoning is never a security control. Report a vulnerability through
GitHub's private vulnerability reporting rather than a public issue.

## License

MIT. See [`LICENSE`](LICENSE).
