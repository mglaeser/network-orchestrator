# Native Bonjour owner

The complete implementation is packaged as `netorch.bonjour_owner` and
`netorch.bonjour_process`. This directory contains only portable settings data;
the provisioning bundle generates the launchd job and Monit check from the
private deployment manifest. There is one user discovery owner for both
directions, with independent leases for each configured policy.

Install and bind these commands using the provisioned Python interpreter:

```text
python -m netorch.bonjour_owner --settings /absolute/private/bonjour.json serve
python -m netorch.bonjour_owner --settings /absolute/private/bonjour.json endpoint
python -m netorch.bonjour_owner --settings /absolute/private/bonjour.json health
```

`serve` is the launchd-managed process. `endpoint` is the fixed stdin/stdout
owner protocol executable. `health` returns zero for fresh scanner and publisher
heartbeats; failures never authorize a container restart. The internal
`publisher` subcommand requires the actual scanner parent PID and a separate
non-stealable publisher lock.

See [the operational contract](../../../docs/bonjour-owner.md) for interface,
Local Network consent, provenance, fail-closed cleanup and native acceptance.
