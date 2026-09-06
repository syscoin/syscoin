# Syscoin Core 5.1.2 “Liberty” Release Notes

Syscoin Core version 5.1.2, codename **Liberty**, is available from:

- <https://github.com/syscoin/syscoin/releases/tag/v5.1.2>

This recommended patch release improves network-message validation and managed
sysgeth startup reliability after Syscoin Core 5.1.1. The upgrade is
**non-mandatory**: it does not change consensus rules, activation heights,
network wire formats, or Bridge V2 parameters. The bundled managed client
remains **sysgeth 5.1.0**.

## Upgrade recommendation

Upgrading is recommended for all node operators, particularly operators using
the managed sysgeth state bootstrap. Nodes running Syscoin Core 5.1.1 remain
network-compatible, and no coordinated upgrade or restart height is required.

If you upgrade, shut down the existing version and wait until it has completely
exited before replacing the binaries:

- On Windows, run the new installer.
- On macOS, replace `/Applications/Syscoin-Qt`.
- On Linux, replace `syscoind`, `syscoin-cli`, and any other installed Syscoin
  Core binaries.

Back up wallets and configuration before upgrading. Existing data directories
remain supported.

## Notable changes

### Network-message validation

- Enforces resource limits while decoding Bloom-filter and batched quorum
  signature-share messages, before allocating their declared contents.
- Validates DKG justification contribution indices at the protocol boundary.
- Preserves valid message serialization and compatibility with the existing
  network and shipped quorum profiles.

### Managed sysgeth startup

- Handles a transient disappearance and reappearance of the state-bootstrap
  status without prematurely consuming the normal startup grace period.
- Starts the normal readiness window only after bootstrap completion is
  consistently observed.
- Preserves existing dead-process and explicit zero-timeout behavior.

## Compatibility

Syscoin Core is supported and tested on current Linux, macOS, and Windows
systems. It should also work on other Unix-like systems, although those
environments receive less testing.

Syscoin Core 5.1.2 is a drop-in replacement for 5.1.1 and 5.1.0. Operators do
not need a new sysgeth binary for this update; the matching managed client
remains sysgeth 5.1.0.

## Reporting issues

Please report issues at:

- <https://github.com/syscoin/syscoin/issues>

## Credits

Thanks to the Syscoin community and to all contributors who tested, reported,
reviewed, and fixed these issues, as well as the upstream Bitcoin Core,
Dash Core, and go-ethereum developers.
