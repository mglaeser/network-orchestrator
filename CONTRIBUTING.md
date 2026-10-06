# Contributing

Start with an issue describing the behavior, affected owner boundary and a
synthetic reproduction. Small changes with explicit evidence are easier to
review than a platform rewrite. Treat a new provider as trusted executable code;
configuration must remain data.

## Local checks

Use a managed Python 3.12 or newer in a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements-dev-lock.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m pytest --cov=netorch --cov-branch --cov-report=term-missing
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
.venv/bin/python -m netorch.privacy_check --root . --exceptions schemas/privacy-exceptions.json
.venv/bin/python -m build --no-isolation
```

The `netorch.privacy_check` line is the public host-data guard that CI runs. It
scans tracked and not yet committed files, new tests included, and reports a
finding by path, line, kind and value hash without echoing the value. Prefer
rewriting the line; an exception in `schemas/privacy-exceptions.json` must name
the exact path, kind, value SHA-256 and a written reason. See
[runnable CI checks](docs/legacy-import.md#runnable-ci-checks).

Tests should prove behavior across a boundary or a failure mode. Avoid tests that
only repeat implementation details. When changing a reader, include complete,
empty, malformed, truncated, denied, busy, timed-out and stale input cases. When
changing coordination, include failures at every write/readback phase and a
property test when operation order can affect safety.

## Required invariants

- A changed resolved profile cannot reuse an old admission digest.
- The user executor cannot invoke a root owner.
- Only the operator can clear operator pause; only a suspension holder can
  release its suspension.
- Unknown state does not authorize recovery or imply absence.
- A historical receipt cannot imply current applied state.
- Stale instance or network generations cannot be treated as current ownership.
- Public examples and fixtures contain synthetic installation data only.

Schema changes require an explicit version/migration decision. Reject unknown
fields and duplicate JSON keys. Keep emitted JSON deterministic and offline.
Do not accept shell strings, executable configuration, arbitrary schema URLs or
new privilege paths as convenience features.

Changes to transport or discovery semantics require a digest strategy/schema
version bump or an independently enforced versioned owner implementation
contract. A hash of unchanged policy cannot invalidate approval when code changes
its meaning. Include an old-admission rejection test at the enforcing boundary.

## Updating dependencies

Change direct pins in `pyproject.toml`, `requirements.txt` and
`requirements-dev.txt` together. Rebuild complete locks with the pinned pip-tools:

```sh
.venv/bin/pip-compile --index-url https://pypi.org/simple --allow-unsafe --strip-extras \
  --generate-hashes --no-emit-index-url --no-emit-trusted-host \
  --output-file requirements-lock.txt requirements.txt
.venv/bin/pip-compile --index-url https://pypi.org/simple --allow-unsafe --strip-extras \
  --generate-hashes --no-emit-index-url --no-emit-trusted-host \
  --output-file requirements-dev-lock.txt requirements-dev.txt
```

Inspect transitive changes, run `pip-audit`, install from hashes in a fresh
environment, and run the full supported Python/OS matrix. A lock is not a
vulnerability waiver. Retain version comments on SHA-pinned Actions so Dependabot
can propose understandable updates. Do not add a package upload token or a
production credential to ordinary CI.

The pip-tools `--allow-unsafe` flag includes build-tool dependencies such as pip
and setuptools in the fully pinned hash lock; it does not disable TLS, hash
checking or package auditing. The explicit public index also avoids deriving a
public lock from a developer's private registry configuration.

## Hardware tests

Hosted CI must never mutate production networking. Opt-in acceptance needs an
isolated profile, an explicit operator window where needed, recovery material and
a record of OS build/tool versions. Do not add a production self-hosted runner to
this public repository. Report simulated, userspace and hardware evidence as
different tiers.

Pull requests should explain the concrete before/after behavior, evidence tier,
validation and operational risks. By contributing, you agree to license your
contribution under the repository's MIT license.
