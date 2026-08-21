# Shared Composition Stack v4

This directory provides a reusable, repo-local composition bootstrap without changing the repository's normal dependency manifests or installing packages globally.

## Security model

A reviewed install is **offline, wheel-only, exact-hash locked, dependency-traversal disabled, and installer-locked**. The bootstrap does not resolve package ranges from PyPI or another network index. It requires three operator-supplied inputs:

1. a per-Python/per-platform complete lock file;
2. the independently authenticated SHA-256 of that exact lock file; and
3. a local wheelhouse containing the exact wheel bytes named by those hashes.

Every lock line must use this canonical form:

```text
NAME==VERSION --hash=sha256:<64 lowercase hex>
```

Every direct and transitive package needed by the selected profile must be present in the lock. The complete lock also **must include `pip` itself**. Options, URLs, markers, ranges, unhashed packages, duplicate package names, and source distributions are rejected from the lock. A different platform or Python version should use a different complete lock rather than conditional entries in one mutable lock.

The bootstrap creates a **fresh private environment for every run** under `.stack/runtime/runs/<profile>/<random-id>`. It never executes or incrementally updates an existing ignored `.stack/.venv`. This also prevents a prior `mirofish` install from contaminating a later `base` environment.

The venv is created with `--without-pip`, so `venv`/`ensurepip` cannot silently seed an installer that is absent from the authenticated lock. The wheelhouse is snapshotted into private run staging through no-follow regular-file reads. Before any pip code is imported, the selected pip wheel is bound to the `pip` lock entry by SHA-256 plus stdlib-only wheel/METADATA parsing. Only that authenticated pip wheel supplies the vendored PEP 508 parser and the installer executable for the run.

Before any candidate wheel is installed, the verifier parses each locked wheel's `METADATA` using the authenticated pip wheel's vendored PEP 508 parser. It requires wheel name/version/hash identity to match the lock, rejects direct-URL dependencies, requires every active dependency to be present in the complete lock at a compatible locked version, and propagates requested extras while evaluating markers for the actual target interpreter/platform.

Only after that metadata closure passes does the authenticated pip wheel install the explicitly locked wheels. It runs with an allowlisted environment, isolated configuration, `--no-index`, `--only-binary=:all:`, `--require-hashes`, and **`--no-deps`**. Disabling resolver dependency traversal is deliberate: `--no-index` alone does not prevent a wheel's `Requires-Dist` direct URL from being fetched.

After installation, the bootstrap checks both the pip report and a stdlib `importlib.metadata` inventory. The installed distribution name/version set must exactly equal the complete lock, including the authenticated pip distribution. This prevents an unreported `ensurepip`/venv seed or other ambient distribution from being mistaken for a fully locked environment.

Receipts are created with exclusive no-follow output semantics and bind the bootstrap bytes, interpreter bytes, implementation/cache tag/platform identity, lock bytes, wheel bytes, authenticated pip-wheel digest, dependency-metadata closure, exact installed distribution set, installed package/artifact identities, and pip report. Receipts are **advisory install evidence only**. They do not authorize merge, promotion, completion, production use, or later runtime execution.

## Profiles

`base` requires locked wheels for `pip` plus the provider-neutral HTTP/config/model-validation and deterministic test roots.

`mirofish` additionally requires the MiroFish composition roots, including Flask, OpenAI-compatible client support, Zep Cloud, CAMEL/OASIS, PyMuPDF, and charset tools. Because `camel-oasis==0.2.5` requires Python `<3.12`, an actual `mirofish` install requires **CPython 3.11**. PyPy 3.11 and other Python implementations are rejected. A dry-run may be inspected from another Python version or implementation.

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

The wheelhouse must include the exact pip wheel named by the lock. The bootstrap intentionally does **not** trust the interpreter's bundled/system `ensurepip` wheel and does not provide a networked "resolve latest dependencies" mode. Dependency acquisition and lock construction are separate supply-chain steps and need their own provenance/review.

## Runtime boundary

This bootstrap authenticates and reconstructs an install. It is **not an OS sandbox for code that later runs from that environment**. A repository or model task that can execute arbitrary installed code still needs an external filesystem/network/process containment boundary appropriate to that repository's authority level. Do not infer runtime isolation from an install receipt.

This contract also does not claim protection against a hostile same-UID process mutating the private staging tree during a run. If that threat model matters, execute the bootstrap inside a separately controlled sandbox or immutable build environment rather than extending receipt metadata and calling it isolation.

## Composition principle

Use mature primitives for ordinary execution and keep authority controls outside candidate code. Exact consumed bytes, deterministic negative tests, independent review, and externally controlled execution/publishing remain the proof boundary. Common code is not automatically trusted merely because identical bytes appear in several repositories.
