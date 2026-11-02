# Syscoin Core 5.1.3 “Liberty” Release Notes

Syscoin Core version 5.1.3, codename **Liberty**, is available from:

- <https://github.com/syscoin/syscoin/releases/tag/v5.1.3>

This release fixes masternode transaction conflicts that can prevent miners
from creating block templates, and includes network, validation, storage,
and governance reliability improvements.

**Mining-pool operators should upgrade promptly.** Upgrading is also
recommended for node, Sentry, and wallet operators. No coordinated activation
height is required. The bundled managed client remains **sysgeth 5.1.0**.

## Upgrade instructions

Shut down the existing version and wait until it has completely exited
before replacing the binaries:

- On Windows, run the new installer.
- On macOS, replace `/Applications/Syscoin-Qt`.
- On Linux, replace `syscoind`, `syscoin-cli`, and the other installed
  Syscoin Core binaries.

Back up wallets and configuration before upgrading. Existing data directories
remain supported.

## Notable changes

### Reliable block-template creation

- Prevents conflicting masternode replacements and updates from being admitted
  together, including through RPC package submission.
- Checks provider transactions against both the parent chain state and their
  order in the candidate block, preventing invalid templates such as
  `bad-protx-hash`.
- Removes stale provider transactions and their dependants after collateral
  spends, replacement, and chain reorganizations.
- Reuses verified BLS authentication only for an exact matching verification
  context, reducing repeated work while retaining state validation.

### Network and validation hardening

- Closes obsolete-peer and receive-backpressure paths that could retain
  excessive network data.
- Bounds repeated invalid-script verification work and rate-limits repetitive
  disk logging.
- Widens address-manager identifiers and block/undo-file offsets to avoid
  overflow at their previous limits.
- On 32-bit builds, rejects `-maxmempool` values above 500 MB. The default
  remains 300 MB; 64-bit settings are unchanged.

### NEVM and governance reliability

- Improves recovery from invalid or incomplete NEVM auxiliary data without
  retaining invalid validation state.
- Corrects NEVM cache ownership and writeback behavior.
- Makes accepted orphan governance votes retrievable for relay and
  synchronization.

### RPC and Windows improvements

- Adds `protx_capabilities`, exposing public Sentry signing rules and the
  current chain context without accessing private keys.
- Fixes flat-file persistence with Windows paths and reports write failures
  correctly.

## Compatibility

Syscoin Core 5.1.3 remains compatible with the 5.1.x network. Connections now
require peer protocol **70017**; obsolete protocol versions are disconnected.

The matching managed client remains **sysgeth 5.1.0**. A new sysgeth binary
is not required for this Core update.

## Reporting issues

Please report issues at:

- <https://github.com/syscoin/syscoin/issues>

## Credits

Thanks to the Syscoin community and contributors who reported, reviewed,
tested, and fixed these issues, and to the upstream Bitcoin Core, Dash Core,
and go-ethereum developers.
