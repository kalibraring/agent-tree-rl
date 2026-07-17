# Simple usage guide

Use the one-minute demo to evaluate the core idea. Use the authenticated service
walkthrough when you need receipts, evidence, training, promotion, or backup.

## One-minute demo

From the repository root:

```bash
python3 -m agent_tree_rl.cli demo
```

Success prints a proposal -> question -> answer -> commit path, `hard gates:
pass`, and a reward. This path creates no durable state and invokes no external
agent or tool. Use `--json` for machine-readable output.

Stop here if you only want to understand the project. The rest of this guide
starts the authenticated reference service. It uses the public sample benchmark
to demonstrate mechanics; it does **not** approve that benchmark or this machine
for production traffic.

## Authenticated local service

## What you need

- Python 3.11 or newer
- `curl`
- Two terminal windows

Run every source command from the project root: the directory that contains
`pyproject.toml`.

## 1. Initialize local state

In terminal 1:

```bash
cd /path/to/agent-tree-rl
python3 --version
python3 -m agent_tree_rl.cli init --data-dir "$PWD/var" --tenant demo
```

`init` creates `var/bootstrap-tokens.json` with mode `0600` instead of printing
secrets into terminal or CI logs. The file contains four one-time bearer tokens:

- `agent` runs decisions and trains challengers.
- `operator` runs approved evidence commands and reads audit events.
- `promoter` evaluates, promotes, and rolls back policies.
- `auditor` reads champions and audit events.

Move the tokens to a local secret store, then securely delete
`var/bootstrap-tokens.json`. The generated `api-tokens.json` contains only token
hashes, so the plaintext tokens cannot be recovered from the service files
later. `init` refuses to overwrite an existing setup or token-output file; run
it only once for a data directory. Use `--token-output /secure/path/tokens.json`
when the secret destination should live elsewhere.

## 2. Configure the local service

Still in terminal 1, run:

```bash
export AGENT_TREE_RL_DATA_DIR="$PWD/var"
export AGENT_TREE_RL_ALLOW_SAMPLE_BENCHMARK=true
export AGENT_TREE_RL_ALLOWED_COMMANDS="$PWD/agent_tree_rl/workers/evidence_probe.py"
```

The remaining file and working-root settings default safely beneath
`AGENT_TREE_RL_DATA_DIR`.

The sample-benchmark flag is for this local walkthrough only. Production must
use a private, independently governed benchmark.

Check the complete local configuration, then start the server:

```bash
python3 -m agent_tree_rl.cli doctor
python3 -m agent_tree_rl.cli serve
```

`doctor` should report `"ready": true`. The server listens on
`http://127.0.0.1:8080` by default. Leave it running in terminal 1.

## 3. Check the service

In terminal 2:

```bash
cd /path/to/agent-tree-rl
curl --fail --silent --show-error http://127.0.0.1:8080/healthz
curl --fail --silent --show-error http://127.0.0.1:8080/readyz
```

`/healthz` proves that the process is alive. `/readyz` checks storage and confirms
that evidence and benchmark worker configuration was loaded; it does not execute
either worker. Run `agent-tree-rl verify` for the disposable worker lifecycle proof.

## 4. Run one decision

Read the `agent` token into the shell without adding it to shell history:

```zsh
read -r -s "AGENT_TOKEN?Paste the agent token: "
export AGENT_TOKEN
echo
```

Call the decision endpoint:

```bash
curl --fail-with-body --silent --show-error \
  -X POST http://127.0.0.1:8080/v1/decisions/run \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: local-decision-0001" \
  --data '{"simulations":64,"seed":7}'
```

The response contains:

- `trajectory`: the selected proposal/question/answer/commit moves;
- `feasible`: whether the result passed every hard constraint;
- `abstained`: whether the controller refused to commit;
- `reward`: the bounded scalar score after feasibility;
- `experience_receipt_id`: the durable authenticated experience record.

Repeating the exact request with the same idempotency key within 24 hours returns
the original result instead of spending the budget twice. Persist that response
and reconcile an ambiguous outcome before the retention window closes; after
expiry the same key may execute and spend again. Use a new key when the request
body changes or for a later logical operation.

You now have the smallest useful end-to-end run. Press `Ctrl-C` in terminal 1
when you want to stop.

## Optional: run approved evidence

Start the service as above, then read the `operator` token in terminal 2:

```zsh
read -r -s "OPERATOR_TOKEN?Paste the operator token: "
export OPERATOR_TOKEN
echo
```

From the project root, run the allowlisted health probe:

```bash
curl --fail-with-body --silent --show-error \
  -X POST http://127.0.0.1:8080/v1/evidence/run \
  -H "Authorization: Bearer $OPERATOR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: local-evidence-0001" \
  --data "{\"command_id\":\"cmd0\",\"arguments\":[\"health\"],\"cwd\":\"$PWD/var\"}"
```

`cmd0` means the first server-configured command. The API does not accept shell
text or an arbitrary executable.

## Optional: train and promote a challenger

Use the `agent` token to train:

```bash
curl --fail-with-body --silent --show-error \
  -X POST http://127.0.0.1:8080/v1/challengers/train \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: local-training-0001" \
  --data '{"episodes":12,"simulations":128}'
```

Copy `challenger_id` from the response. Then read the distinct `promoter` token:

```zsh
read -r -s "PROMOTER_TOKEN?Paste the promoter token: "
export PROMOTER_TOKEN
echo
```

Evaluate the challenger. Replace `CHALLENGER_ID` with the copied value:

```bash
curl --fail-with-body --silent --show-error \
  -X POST http://127.0.0.1:8080/v1/benchmarks/evaluate \
  -H "Authorization: Bearer $PROMOTER_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: local-evaluation-0001" \
  --data '{"challenger_id":"CHALLENGER_ID"}'
```

Copy `receipt_id` from that response and promote within five minutes. Replace
both placeholders:

```bash
curl --fail-with-body --silent --show-error \
  -X POST http://127.0.0.1:8080/v1/challengers/CHALLENGER_ID/promote \
  -H "Authorization: Bearer $PROMOTER_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: local-promotion-0001" \
  --data '{"reason":"local walkthrough","hidden_benchmark_receipt_id":"RECEIPT_ID"}'
```

This first promotion has no incumbent champion. Later promotions must evaluate
both the current champion and challenger on the same suite and also pass
`champion_hidden_benchmark_receipt_id`.

Inspect the active champion:

```bash
curl --fail-with-body --silent --show-error \
  http://127.0.0.1:8080/v1/families/agent-decision-routing/champion \
  -H "Authorization: Bearer $PROMOTER_TOKEN"
```

The bootstrap uses distinct agent and promoter subjects so separation of duties
remains active.

## Verify the implementation

Run the narrow end-to-end proof first:

```bash
python3 -m agent_tree_rl.cli verify
```

Run the complete release proof before packaging or deployment:

```bash
.venv/bin/python -m pip install -e ".[dev]"
PYTHON=.venv/bin/python scripts/verify_release.sh
```

The release proof runs the test suite, the controller acceptance proof, wheel and
source builds, clean installations of both paths, and the installed evidence probe.

## Back up local state

With the local environment variables still set:

```bash
python3 -m agent_tree_rl.cli backup --output "$PWD/state.atrlb"
```

The bundle contains the database and referenced policy objects. It deliberately
excludes API tokens, signing keys, backup keys, and the hidden benchmark. Store
those secrets separately. Restore only into a stopped, empty data root; follow
the controlled procedure in [RUNBOOK.md](RUNBOOK.md#restore).

## Before production

Do not convert the local walkthrough into a public deployment by changing the
bind address. Complete every environment-owned gate in
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md), especially the private
benchmark, attested sandboxed workers, secret manager or KMS, TLS and workload
identity, immutable remote audit, off-site encrypted backup, and canary/rollback
drills.

For normal operations and incidents, use [RUNBOOK.md](RUNBOOK.md). For the
system model and trust boundaries, use [ARCHITECTURE.md](ARCHITECTURE.md) and
[THREAT_MODEL.md](THREAT_MODEL.md).
