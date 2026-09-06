# Syscoin Core 5.1.1 “Liberty” Release Notes

Syscoin Core version 5.1.1, codename **Liberty**, is available from:

- <https://github.com/syscoin/syscoin/releases/tag/v5.1.1>

This patch release improves node reliability and network-message validation
after Syscoin Core 5.1.0. It does not change the Liberty activation heights,
consensus rules, network wire formats, or Bridge V2 parameters. The bundled
managed client remains **sysgeth 5.1.0**.

## Upgrade instructions

If you are running an older version, shut it down and wait until it has
completely exited before replacing the binaries:

- On Windows, run the new installer.
- On macOS, replace `/Applications/Syscoin-Qt`.
- On Linux, replace `syscoind`, `syscoin-cli`, and any other installed Syscoin
  Core binaries.

Back up wallets and configuration before upgrading. Existing data directories
remain supported.

## Notable changes

### Managed sysgeth startup and recovery

- Keeps the extended startup allowance active throughout a state-bootstrap
  import, then starts a fresh normal readiness window after import completes.
- Ensures a persisted deep-lag recovery marker starts a full block-file and
  NEVM reindex before stale chainstate is loaded.
- Reports startup timeout progress relative to the active startup phase.

### LLMQ and governance network-message hardening

- Rejects invalid DKG member signatures before batch processing.
- Bounds LLMQ bitset and signature-share inventory decoding before allocation.
- Uses overflow-safe sparse bitset offset handling and validates test quorum
  parameter limits.
- Validates legacy governance-sync Bloom filters at the deserialization
  boundary and discourages peers that exceed protocol limits.

These changes preserve valid message serialization, hashes, consensus
behavior, and compatibility with all shipped quorum profiles.

## Compatibility

Syscoin Core is supported and tested on current Linux, macOS, and Windows
systems. It should also work on other Unix-like systems, although those
environments receive less testing.

Syscoin Core 5.1.1 is a drop-in replacement for 5.1.0. Operators do not need a
new sysgeth binary for this update; the matching managed client remains
sysgeth 5.1.0.

## Reporting issues

Please report issues at:

- <https://github.com/syscoin/syscoin/issues>

## Credits

Thanks to the Syscoin community and to all contributors who tested, reported,
reviewed, and fixed these issues, as well as the upstream Bitcoin Core,
Dash Core, and go-ethereum developers.
