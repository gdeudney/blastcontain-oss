# Bounded PyRIT Crescendo (phase 4B)

This separate optional image runs PyRIT **1.1.0 `CrescendoAttack`** against the
controlled Agent fixture using API 2 conversation grants. It adds no host package,
runner, configuration class or CLI special case. The adjacent [static image](README.md)
continues to provide `PromptSendingAttack` with its existing target-only grant.

## Supported behavior

The fixed profile allows three accepted target turns and one refusal backtrack.
PyRIT generates the first prompt from the reviewed objective; `entry_prompt` is
only a required scenario label and is **not** sent as the first target turn.
Original Apache-2.0 attacker and scorer templates live in `crescendo_templates.py`.
They are part of the immutable reviewed image. Upstream datasets remain removed.
This is an integration of the native algorithm with original templates, **not a
reproduction of the paper's or PyRIT's default attack templates**.

The image uses native PyRIT refusal/objective scorers over the host's evaluator
model channel. JSON schema instructions are supplied through upstream's text
fallback; the adapter does not claim provider-enforced structured output. Native
malformed-JSON retries are retained and charged. A scorer's success only directs
search. Drill's independent observed actions and reducer determine security results.
For example, a forbidden action in a refused branch still fails the suite even
when PyRIT backtracks and the final text appears harmless.

Each generated message becomes one send from an opaque host checkpoint. Previously
observed prefixes can be revisited; arbitrary imported/edited history is rejected.
The controlled Agent retains its policy, canary, messages and simulated tool logs.
Backtracking restores a checkpoint without repeating earlier tool calls, deleting
evidence, or refunding the shared budget. Reset replaces PyRIT's SQLite state and
the case's host state. The worker never receives model endpoints or credentials.
An abliterated attacker is supported by selecting it in the host attacker binding;
there is no download or automatic model selection.

The preparation example caps each case at 40 model calls across all three roles,
four attempted Agent turns, 120 seconds and 4 MiB of artifacts. The three accepted
turns plus one possible refusal produce at most four target attempts. Agent tool
steps and JSON retries may consume the shared model budget before the algorithm
finishes; that is an incomplete run, not a pass. The standard 256 MiB, 64 PID,
read-only, unprivileged, network-disabled container profile is unchanged.

Unsupported: arbitrary MCP/environment state, injected documents/tool responses,
preloaded scenario turns, task checks, multimodal messages, TAP, converters and
unobserved edits to history. Real external side effects cannot be rolled back by
this synthetic checkpoint feature. Benign utility checks must remain separately
selected cases; the Crescendo profile does not measure task utility itself.

## Build and prepare

Use the same reviewed dependency lock and licenses as the static adapter. From
the repository root:

```sh
podman build --iidfile pyrit-image-id -f drill/plugins/pyrit/Containerfile .
podman build --build-arg BASE_IMAGE="$(cat pyrit-image-id)" \
  --iidfile crescendo-image-id -f drill/plugins/pyrit/Containerfile.crescendo .
python drill/plugins/pyrit/prepare_crescendo.py \
  --image-id sha256:<full-id-from-crescendo-image-id> --output crescendo-review \
  --endpoint http://127.0.0.1:1234/v1 \
  --target your-target-model --attacker your-abliterated-model --evaluator your-evaluator-model
```

The helper only probes the chosen local image and writes reviewable JSON. Inspect
`source.json` (including the objective), `suite.json`, the image, templates,
capabilities, license notices and `review.json`. Provider model IDs may include organization/name, colon tags and @version
suffixes (at most 256 characters; no whitespace or control characters). Distinct per-channel endpoints, credentials or
pinned model identities can be configured by editing `suite.json` before review;
put credential references there and resolve secrets in the host environment.

Use the [static review/plan/lock/run sequence](README.md#build-review-and-run) with
`crescendo-review/suite.json` instead of `resistant.json` and the following six
explicit plugin grants:

```text
--grant-access broker.target.conversation --grant-access broker.target.branch
--grant-access broker.attacker.conversation --grant-access broker.attacker.branch
--grant-access broker.evaluator.conversation --grant-access broker.evaluator.branch
```

Plugin, attack content and suite decisions remain separate. Image/template,
objective, model settings or scope changes invalidate the corresponding reviewed
digest. Three live repetitions can be selected with `"seeds": [0, 1, 2]` before
planning; seeds identify cases and do not promise deterministic model responses.
No acceptance or execution occurs during preparation.

Opt into raw retention if offline replay is needed. Signed evidence includes all
attempts, conversation graphs and model-call hashes. Replaying Agent branches needs
the retained original fixture states (or explicitly supplied matching `--states`),
not just the final branch. See [Agent checkpoints](../../docs/agent-checkpoints.md)
and [suite runs](../../docs/suite-runs.md) for signing, replay and expiry.

## Validation and limitations

`validate_crescendo.py` runs the real pinned upstream directly and through the
checkpoint adapter with identical controlled responses. It compares exact channel
histories, refusal backtracking, JSON retry calls, outcomes and reset isolation.
The script runs inside the restricted image with no bundled upstream datasets.

The container suite also runs real API 2 workers, the native Agent child process,
all three host model channels, signed graphs and offline replay. It checks that
abandoned forbidden actions survive aggregation, reset isolates canaries, budgets
are shared, unsupported shapes fail before dispatch, and cancellation during any
model role stops the worker. Controlled model responses do not establish live
attack effectiveness or a vulnerability rate.

```sh
DRILL_PYRIT_IMAGE="$(cat pyrit-image-id)" \
DRILL_PYRIT_CRESCENDO_IMAGE="$(cat crescendo-image-id)" \
python -m pytest drill/plugins/pyrit/tests -q
```

Both image variables are required; a missing image is a failed validation, not a
skip. CI builds both pinned images and runs both adapters. Phase 4C remains open:
three bounded live runs with recorded target, attacker and evaluator identities,
settings, budgets and security/utility limitations need an available local endpoint.
