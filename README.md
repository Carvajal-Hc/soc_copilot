# SOC Copilot

Ask a Splunk index a triage question in plain English — answered only from the rows Splunk
returns, and able to run fully air-gapped.

<!-- GIF here -->

- **Air-gapped.** With the local backend (Ollama), nothing leaves the machine. A hosted
  backend (Anthropic) is opt-in.
- **Anchored to real rows.** Every hash, path, GUID or IP in an answer is traced to a returned
  row; anything that can't be is marked `[UNVERIFIED]`. Searches are read-only.
- **Log values are treated as hostile.** Instructions planted in a log field are sealed as
  data and never obeyed.
- **Honest about its limits.** It says "not in this data" rather than guess.

## Quickstart

Needs a Splunk instance with evidence indexed ([dataset](SETUP.md#the-dataset-this-demo-runs-on))
and [Ollama](https://ollama.com/download) running.

```powershell
git clone https://github.com/Carvajal-Hc/soc_copilot.git; cd soc_copilot
python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt
ollama pull qwen2.5-coder:14b
copy .env.example .env   # set SPLUNK_TOKEN, SOC_LLM_BACKEND=ollama, SOC_LLM_MODEL=qwen2.5-coder:14b
.\.venv\Scripts\python.exe -m soc_copilot serve   # → http://127.0.0.1:8765/
```

## Limits

- **Local models are slower and weaker.** A local 14B handles single searches well but
  completed only 2 of 3 two-step pivots (7B: 0 of 3), at ~90–120s per turn.
- **The detection library is tuned to one dataset.** On other data, write your own entries.
- **It answers only what is indexed.** Raw-artifact work (file contents, carving) stays with
  the analyst; see [`SCOPE-BOUNDARY.md`](SCOPE-BOUNDARY.md).

Details: [backend trade-off and limits](NOTES.md#backend-trade-off-and-limits).

## More

| | |
| --- | --- |
| [`SETUP.md`](SETUP.md) | install, backends, configuration, the dataset, commands, tests |
| [`NOTES.md`](NOTES.md) | findings F1–F6 and the design reference (how each part works) |
| [`SECURITY.md`](SECURITY.md) | threat model, and what is *not* defended |

MIT licensed — see [`LICENSE`](LICENSE).
