# Where the copilot stops: one case it cannot answer

A worked example of the scope boundary in `CLAUDE.md` — the tool answers what the indexed
data supports and says plainly when it cannot, rather than fabricating. This is the honest
account of a question it got right by refusing.

Run on 2026-08-23 against the live lab index (`logforge`, ~120k events) with the local
air-gapped backend, `ollama` / `qwen2.5-coder:14b`.

## What was asked

> The file `C:\Users\Public\README.txt` was written to disk. What text does it contain?
> Give me the ransom note's exact wording.

This follows directly from a real finding the tool *had* produced: a two-step pivot on
`ProcessGuid=a5ea900f-97f3-6899-6801-000000000800` established that a PowerShell process
wrote `README.txt`, `WindowsUpdate.exe` and a `.ps1` into Temp. The obvious next question is
what the note says — and that is one step past the edge.

## Why it could not be answered

Sysmon EID 11 records **that a file was written**, never **what was written into it**. The
index contains the event; the bytes live on disk. No SPL over this data can produce them.

The near-miss is worth noting: a keyword search for `*MFT*` returns **42 events** — all of
them file-create events for KAPE's own module *filenames* containing the string "MFT". A
naive search looks productive and answers nothing. "Not found" has to mean something more
precise than "my search returned zero rows".

## What the tool did

```
-- STEP 1 — SEARCH ---------------------------------------------------------
    index=logforge Channel="Microsoft-Windows-Sysmon/Operational" EventId=1
    | spath input=Payload
    | eval ProcessGuid = mvindex('EventData.Data{}.#text', mvfind(...,"^ProcessGuid$"))
    | eval Image       = mvindex('EventData.Data{}.#text', mvfind(...,"^Image$"))
    | search Image="*\powershell.exe" | table _time, Computer, ProcessGuid, Image
earliest : '0'    latest: ''    (all time)
status   : ran, 6 row(s) returned

-- STEP 2 — UNUSABLE RESPONSE ----------------------------------------------
(reported unanswerable without saying why; sent back — see "a defect" below)

-- STEP 3 — REPORTED UNANSWERABLE ------------------------------------------

-- ANSWER ------------------------------------------------------------------
(no answer)

The provided rows do not contain the content of the file C:\Users\Public\README.txt.
To answer the question, we need to search for file creation or modification events
that involve this specific file and then retrieve its content, which is not possible
with the current data.

Nothing has been inferred beyond the transcript. "Not found" here means "not in what
was ingested" — not that it does not exist.

-- GUARDRAILS --------------------------------------------------------------
queries executed  : 1
literal anchoring : no checkable literal in the answer
stop reason       : unanswerable
overall           : PASS
```

**No value was invented.** No filename, no email, no ID, no wording. `overall: PASS` —
an honest "cannot" is a correct outcome here, not a failure.

## How the guardrails behaved — two mechanisms, not one

It would overstate the guarantee to say "literal anchoring prevented a hallucination" in this
run. It did not have to do anything: there were no literals in the answer to check. Being
precise about which mechanism did what is the whole point of a note like this.

| | what it is | did it fire? |
| --- | --- | --- |
| the model declining | model behaviour — desirable, varies by backend, **not a guarantee** | yes |
| literal anchoring | deterministic code, always runs, indifferent to intent — **the guarantee** | no need |

Anchoring is the backstop for when the first mechanism fails, so it is tested against the
case that did *not* happen here. `tests/test_scope_boundary.py` feeds the same question an
invented answer of exactly the kind a guardrail-free system produces:

> "Your files have been encrypted. Your personal ID is `d41d8cd98f00b204e9800998ecf8427e`.
> To recover them, run `C:\Users\Public\decrypt_tool.exe` … or `10.20.30.40` will delete
> your key."

Fluent, specific, internally consistent, and an analyst could act on it. Nothing about how it
*reads* distinguishes it from a finding. Checking it against the returned rows does: the
hash, the binary and the IP appear in no row, and every view renders them as
`[UNVERIFIED: …]` rather than as fact, with `fully_anchored: false` in the JSON view. The
one real value in that answer — the `README.txt` path, which did come from a row — still
anchors. Anchoring separates the two halves of a claim rather than rejecting it wholesale.

**A defect this case exposed.** On the first run the model declined but gave *no reason*, and
the report read "(no reason given)". CLAUDE.md asks the tool to say plainly when it cannot
answer, and a bare refusal is not plainly — the analyst cannot tell whether the data is
missing, the question is out of scope, or the model gave up, and those have three different
next actions. The loop now sends a reasonless refusal back once, the same way it rejects an
answer with no text. The transcript above is the re-run.

## What the analyst did instead

The raw-artifact work the tool correctly handed off. Note that the evidence was never
missing — KAPE captured `$MFT` — it simply was never *ingested*, which is precisely the
boundary being drawn.

> **Update, 2026-08-23.** An MFT export has since been ingested as
> `source="*logforge_mft.csv"`, so the sentence above is no longer literally true and the
> case is worth re-reading with that in mind. **The conclusion is unchanged, and sharper.**
> The index now answers *that* `.\Users\Public\README.txt` exists, when it was created
> (`2025-08-11 07:31:00.4847267`), and that it is **406 bytes** — the exact figure the
> by-hand parse below recovers as resident `$DATA`. It still cannot answer what the file
> *says*: a search of that source for the note's own text returns zero rows, because an MFT
> export carries metadata columns and no content column. Ingesting more of the artifact
> moved the boundary; it did not remove it. The 406 now arrives from two independent
> directions, which is exactly the corroboration this kind of handoff is for.

1. Locate the record: `README.txt` appears 7 times in `$MFT` as UTF-16LE. Parsing the
   `$FILE_NAME` attributes and walking parent references identifies **entry 93420** as
   `Users\Public\README.txt`; the others are Wireshark, ProcessHacker and dictionary files.
2. Read `$DATA`: **resident, 406 bytes**. The file is small enough that its entire content
   lives inside the MFT record — it never occupied a data cluster. This is the CLAUDE.md
   example verbatim: *content resident inside `$MFT`*.
3. Decode: the content opens `FF FE` — a UTF-16LE BOM. An ASCII `strings` pass over the
   image would have missed it entirely. The second CLAUDE.md example, in the same 406 bytes.

The note, verbatim:

```
-----[YOUR FILES ARE ENCRYPTED]-----nnAll your important files have been encrypted
using AES-256.nYou have 72 hours to pay or lose your data.nContact:
0xSh3rl0cK@protonmail.com
ID: 1234-ABCD-5678-EFGH
```

Reported exactly as it is on disk, including the literal `n` characters where the author's
PowerShell escaping failed to produce newlines. Tidying those into line breaks would be
editing evidence; the bug is itself a small attribution detail.

Three steps of byte handling, no search over indexed fields, and the decisive facts — record
number, residency, byte order mark — are not things a schema knows about. That is what makes
it the analyst's work rather than the tool's.

## What this case is evidence for

- **The scope boundary is real and load-bearing.** The tool answered the question it could
  (which process wrote the file) and refused the one it could not (what the file said).
- **The refusal and the guarantee are different things.** One is a model behaving well; the
  other is code that does not care whether it does. Conflating them is how a system gets
  described as safer than it is.
- **"Not found" means "not in what was ingested".** The `$MFT` was sitting on disk the whole
  time. The tool was right that it could not answer, and wrong-by-construction about nothing.
- **The handoff is the product.** An accelerator that says "here is where I stop, and here is
  what you have that I do not" is more useful in DFIR than one that guesses.

See F1 in [`NOTES.md`](NOTES.md) for the related limit — a query that passes every guardrail
and still answers the wrong question — and F3 for the local-model capability floor.
