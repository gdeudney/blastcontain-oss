# Reference container plugin

This original, model-free example demonstrates two adaptive calls through Drill's
broker. It is not PyRIT, a paper reproduction or a live-model security result.
An external plugin can package the same lifecycle without editing Drill's runner.

From the repository root, with Core and Drill installed (or `PYTHONPATH=core:drill`):

```sh
podman build -t localhost/drill-reference:dev -f drill/plugins/reference/Containerfile .
podman image inspect --format '{{.Id}}' localhost/drill-reference:dev
```

The build step is explicit. The worker itself never builds, installs or pulls an
image. For reproducible builds pass a pinned base image using `--build-arg BASE_IMAGE=...`;
the default base tag is only a development convenience. Review the resulting image
and copy its full `sha256:...` ID into the demo command:

```sh
PYTHONPATH=core:drill python drill/plugins/reference/run_demo.py \
  --image-id sha256:YOUR_LOCAL_IMAGE_ID \
  --output-dir /tmp/drill-reference-demo
PYTHONPATH=core:drill python -m blastcontain_drill.plugins.cli \
  --directory /tmp/drill-reference-demo \
  --acceptances /tmp/drill-reference-demo/acceptances.json --probe-runtime
```

Running this reference demo explicitly creates a **temporary fixture acceptance**
for the supplied image and metadata in the new output directory. It does not change
any production registry. `result.json` separates the plugin's claims from the two
host-observed calls and records completed cleanup. The fake target uses no model,
credentials or external network service.

For a real plugin, implement `prepare(config)`, `reset(scenario)`, `execute(broker)`
and `close()`, then call `blastcontain_drill.plugins.sdk.serve(plugin)` inside your
container entry point. Use `broker.call(channel, Injection(...))` instead of opening
network connections. The available channel must be declared, accepted and bound to
a trusted async handler by the host. Standard output carries protocol frames only;
use standard error for small diagnostics. Images run as UID 65532 with a read-only
root filesystem, so keep temporary state under the private `/tmp` mount.

The example Containerfile copies only Drill's stdlib-only contracts and worker SDK,
plus their license/notice files. Pin the SDK and all additional framework/model/data
artifacts in your own image build. Installation does not imply technical acceptance.
See [the worker contract](../../docs/plugin-workers.md) for restrictions, protocol,
budgets, conformance tests and the required trust boundaries.
