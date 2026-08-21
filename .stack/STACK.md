# Shared Composition Stack v2

This directory provides a reusable, repo-local composition bootstrap without changing the repository's normal dependency manifests or installing packages globally.

## Security model

A reviewed install is **offline, wheel-only, and exact-hash locked**. The bootstrap does not resolve package ranges from PyPI or another network index. It requires three operator-supplied inputs:

1. a per-Python/per-platform lock file;
2. the independently authenticated SHA-256 of that exact lock file; and
3. a local wheelhouse containing the exact wheel bytes named by those hashes.

Every lock line must use this canonical form:

```text
NAME==VERSION --hash=sha256:<64 lowercase hex>
```

Every direct and transitive package needed by the selected profile must be present in the lock. Options, URLs, markers, ranges, unhashed packages, duplicate package names, and source distributions are rejected. A different platform or Python version should use a different complete lock rather than conditional entries in one mutable lock.

The bootstrap creates a **fresh private environment for every run** under `.stack/runtime/runs/<profile>/<random-id>`. It never executes or incrementally updates an existing ignored `.stack/.venv`. This also prevents a prior `mirofish` install from contaminating a later `base` environment.

The wheelhouse is snapshotted into private run staging through no-follow regular-file reads before pip starts. Pip runs with an allowlisted environment, isolated configuration, `--no-index`, `--only-binary=:all:`, and `--require-hashes`. The resulting pip report must bind exactly the package/version/artifact hashes in the supplied lock.

Receipts are created with exclusive no-follow output semantics and bind the bootstrap bytes, interpreter bytes, lock bytes, wheel bytes, installed package/artifact identities, and pip report. Receipts are **advisory install evidence only**. They do not authorize merge, promotion, completion, production use, or later runtime execution.

## Profiles

`base` requires locked wheels for the provider-neutral HTTP/config/model-validation and deterministic test roots.

`mirofish` additionally requires the MiroFish composition roots, including Flask, OpenAI-compatible client support, Zep Cloud, CAMEL/OASIS, PyMuPDF, and charset tools. Because `camel-oasis==0.2.5` requires Python `<3.12`, an actual `mirofish` install requires CPython 3.11. A dry-run may be inspected from another Python version.

## Dry-run

Dry-run performs no install and creates no runtime directory:

```bash
python3 .stack/bootstrap.py --profile base --dry-run
python3 .stack/bootstrap.py --profile mirofish --dry-run
```

## Reviewed install shape

Example after an independently reviewed lock and wheelhouse have been prepared:

```bash
LOCK=.stack/locks/base-cp313-linux-x86_64.txt
LOCK_SHA256=<independently-authenticated-64-hex-digest>
WHEELHOUSE=/trusted/local/wheelhouse/base-cp313-linux-x86_64

python3 .stack/bootstrap.py \
  --profile base \
  --lock "$LOCK" \
  --lock-sha256 "$LOCK_SHA256" \
  --wheelhouse "$WHEELHOUSE"
```

The bootstrap intentionally does **not** provide a networked "resolve latest dependencies" mode. Dependency acquisition and lock construction are separate supply-chain steps and need their own provenance/review.

## Runtime boundary

This bootstrap authenticates and reconstructs an install. It is **not an OS sandbox for code that later runs from that environment**. A repository or model task that can execute arbitrary installed code still needs an external filesystem/network/process containment boundary appropriate to that repository's authority level. Do not infer runtime isolation from an install receipt.

## Composition principle

Use mature primitives for ordinary execution and keep authority controls outside candidate code. Exact consumed bytes, deterministic negative tests, independent review, and externally controlled execution/publishing remain the proof boundary. Common code is not automatically trusted merely because identical bytes appear in several repositories.
