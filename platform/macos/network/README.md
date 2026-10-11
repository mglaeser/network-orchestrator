# Shared wired interface selector

`wired-interface.pl` is a native read-only helper extracted from the existing
owner implementation, rather than a new networking controller. Its extraction
baseline SHA256 is
`a0869a13a18cb03360cd4bcb907e398d46358dd6e35e20a0e539497b7e60db12`.
The baseline is source provenance, not a declaration that this candidate is
installed on any host.

The candidate deliberately hardens three demonstrated failure boundaries:

- Reject invalid or noncontiguous IPv4 netmasks in inventory evidence.
- Require supported negotiated cable media grammar instead of finding a copper
  media substring inside otherwise invalid text.
- Reap the owned child synchronously after terminating a failed bounded read.

Native command paths, physical selection, address ownership, MAC-redaction
handling and refusal behavior are otherwise retained. There is no network write,
LAN probe, route selection, privileged request or background service. Perl is
the existing native runtime; the public Python workflow invokes this fixed
packaged resource through its bounded process runner. Instance data selects
neither executable paths nor code. Older installed copies are not modified by
installing the framework wheel.

`tests/test_wired_recorded_evidence.py` replays the pure resolver against paired,
sanitized native hardware/link inventories. Negative and adapter-change cases
are explicitly synthetic mutations. Process-failure tests run disposable local
children and verify reaping. CI also checks the helper from the installed wheel
outside the source checkout. Python coverage does not measure Perl branches;
replay assertions and subprocess outcomes are separate evidence, not a Perl
coverage percentage or native acceptance.

See [the full selection and migration contract](../../../docs/wired-interface-selection.md).
