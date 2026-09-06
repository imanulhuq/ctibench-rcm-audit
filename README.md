# A Measurement Audit of CTI Root-Cause Mapping — artifact

Frozen corpora, per-item model outputs, and the CWE hierarchy used in the
paper. Every number reported in the paper regenerates from these files
**without re-querying any model API or the NVD**.

## Contents

```
data/
  derived/
    arms_N999_2026-06-01.json           the frozen sample: exact CVE ids per corpus
    cti-rcm-postcutoff-evaluated.tsv    the 997 evaluated post-cutoff items
    cwec_relations.json                 CWE ChildOf graph used for hierarchy scoring
    manifest-2026-09-05.json            corpus construction record
    release_build.json                  what was removed when staging this release
  results/
    <model>__rcm__<corpus>.jsonl        per-item responses, gold labels, token usage
CHECKSUMS.txt                           sha256 and size for every file
```

Ten result files: five models (`gpt-4o`, `gpt-4.1`, `gpt-5.5`, `llama-4`,
`claude`) × two corpora (`bench`, `post`).

## Reproducing the reported accuracies

```python
import json, re
from pathlib import Path

D = Path('data')
arms = json.loads((D/'derived/arms_N999_2026-06-01.json').read_text())
CWE = re.compile(r'CWE-\d+')

def parse(t):                      # scoring rule used throughout the paper
    if not t: return None
    ls = [l.strip() for l in t.strip().split('\n') if l.strip()]
    if ls:
        m = CWE.fullmatch(ls[-1].strip(' .*`'))
        if m: return m.group(0)
    h = CWE.findall(t)
    return h[-1] if h else None

def load(model, corpus):
    p = D/'results'/f'{model}__rcm__{corpus}.jsonl'
    return {json.loads(l)['cve']: json.loads(l) for l in open(p) if l.strip()}

MODELS = ['gpt-4o','gpt-4.1','gpt-5.5','llama-4','claude']
for corpus in ('bench','post'):
    common = sorted(set(arms[corpus]).intersection(*[set(load(m,corpus)) for m in MODELS]))
    for m in MODELS:
        d = load(m, corpus)
        acc = 100*sum(parse(d[c]['response']) == d[c]['gt'].strip() for c in common)/len(common)
        print(f'{m:10s} {corpus:6s} n={len(common)}  {acc:.1f}%')
```

Expected output (Table 2 of the paper):

| Model | Benchmark | Post-cutoff |
|---|---|---|
| gpt-4o | 75.3 | 75.7 |
| gpt-4.1 | 73.8 | 74.5 |
| gpt-5.5 | 74.9 | 77.2 |
| llama-4 | 74.6 | 74.5 |
| claude | 74.3 | 76.5 |

`n = 997` on the benchmark and `n = 996` on the post-cutoff corpus. One
post-cutoff item never returned a response from one model after repeated
attempts and is excluded from analyses requiring all five.

## Record schema

Each line of a results file is one JSON object:

| Field | Meaning |
|---|---|
| `cve` | CVE identifier |
| `gt` | ground-truth CWE from NVD |
| `response` | verbatim model output |
| `usage` | provider-reported token counts |
| `model`, `task`, `arm` | run identifiers |

## Not included, and why

- **Raw NVD snapshots** (~630 MB) — re-derivable from the CVE API 2.0.
  Note that NVD revises records after publication, so a fresh pull will
  **not** reproduce our snapshot. The frozen arm definitions above recover
  the exact evaluated items.
- **The full 34,959-record post-cutoff pool** — only the 997 evaluated items
  are included; the pool is re-derivable from the documented filters.
- **The CVSS severity-prediction corpus** — not used in this paper.
- **API credentials** — none are stored in any file.
- **CTIBench itself** — available from its own repository under its own
  licence. We reference it rather than redistribute it.

## Provenance

- NVD CVE API 2.0, snapshot pulled 2026-09-05
- Random seed 20261005 throughout (an arbitrary fixed value)
- Corpus boundary 2026-06-01
- CWE catalogue retrieved from MITRE; `ChildOf` relations only

## Staging note

Result files were deduplicated when staging this release: earlier exploratory
runs used a different sample, so records for CVEs outside the frozen arms were
removed, as were entries where the API returned no response after repeated
retries. The counts removed per file are recorded in
`data/release_build.json`. The released accuracies were verified to match the
paper to within 0.1 pp for all ten model-corpus combinations.

## Licence

Code: MIT. NVD data is a US Government work in the public domain; CWE is
subject to MITRE's terms of use. Model outputs are redistributed subject to
each provider's terms.
