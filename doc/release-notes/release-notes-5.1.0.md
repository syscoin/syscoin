# Syscoin Core 5.1.0 “Liberty” Release Notes

Syscoin Core version 5.1.0, codename **Liberty**, is available from:

- <https://github.com/syscoin/syscoin/releases/tag/v5.1.0>

Liberty is the cumulative consensus, bridge, ChainLock, and node-reliability
upgrade from the 5.0.x release line. It also includes the matching Syscoin
geth 5.1.0 client used by managed NEVM nodes.

## Network activation scope

### Mainnet — mandatory coordinated upgrade

Liberty schedules the following consensus activation on mainnet:

- Syscoin Core canonical-receipt and Bridge V2 manager cutover height:
  **2,292,816**
- Paired sysgeth Liberty and vault-migration block: **975,316**
- Bridge V2 vault-manager proxy:
  `0x28bD37C0926575f2568ea8f297c0745EF16174Ab`

Mainnet Core operators must upgrade before Core height **2,292,816**. NEVM
sequencers and operators of independently managed sysgeth instances must
upgrade before NEVM block **975,316**. Activation is controlled by block
height, not an estimated wall-clock time.

The NEVM migration runs one Core block before the Core manager switch, making
the migrated root available when Core height 2,292,816 is validated. The
replacement vault is deployed paused and may remain paused for additional
blocks after activation, but the pause does not remove the requirement to
upgrade both consensus clients before their respective heights.

### Tanenbaum testnet

Liberty also schedules Bridge V2 on Tanenbaum:

- Syscoin Core cutover height: **1,786,999**
- Paired Tanenbaum NEVM migration block: **947,000**
- Bridge V2 vault-manager proxy:
  `0x28bD37C0926575f2568ea8f297c0745EF16174Ab`

Tanenbaum operators must use matching Core and sysgeth versions at and after
these activation heights.

**No Bitcoin checkpoint (BTCC) activation height is assigned for mainnet or
Tanenbaum in this release.** BTCC remains inactive until a future coordinated
release assigns its independent activation parameters.

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

### Bridge V2 and NEVM proof validation

- Selects the expected vault manager at the exact Core cutover height.
- Keeps canonical receipt validation independent from the vault-manager
  switch.
- Tightens receipt, trie, log, amount, destination, and asset validation.
- Improves NEVM mint replay-marker durability across connects, disconnects,
  startup recovery, reindexing, and database flushes.
- Defers NEVM side effects until the corresponding Core consensus checks have
  succeeded.
- Adds focused fuzz and regression coverage for bridge proofs and Syscoin
  transaction payloads.

### ChainLocks, quorums, and governance

- Strengthens ChainLock signing, publication, alternative-tip selection, and
  quorum-context validation.
- Hardens aggregate-signature and signature-share cache handling.
- Makes ChainLock and governance validation state transitions more consistent
  across synchronization, restart, and short reorganization paths.
- Requires distinct coinbase outputs for independently required governance and
  Sentry-node payments.

### Managed sysgeth

- Updates the bundled Linux x86-64 client to **sysgeth 5.1.0**.
- Activates the Liberty EVM instruction set and Bridge V2 vault migration on
  mainnet at NEVM block 975,316.
- Improves managed-client startup, bootstrap, shutdown, and ZMQ request
  handling.
- Keeps optional NEVM configurations available to nodes that do not require a
  managed client.
- Reduces startup and shutdown stalls and improves failure reporting when NEVM
  is required.

### Bitcoin data availability and checkpoint groundwork

- Adds Bitcoin header-backend and checkpoint infrastructure for future
  activation.
- Extends AuxPoW mining RPC behavior and validation for Bitcoin-header-backed
  templates.
- Adds Blake2s-based Bitcoin data-availability support.
- Keeps BTCC activation independently disabled on public networks in this
  release.

### PoDA, chainstate, and persistence

- Tightens PoDA sidecar ownership, size, content, and duplicate-metadata
  validation.
- Improves deterministic Sentry-node snapshot persistence and EvoDB pruning.
- Hardens database rewrite, backup, rollback, and flush failure handling.
- Improves shutdown safety and validation check-queue draining.

### Wallet, RPC, build, and test improvements

- Fixes wallet fee-bump handling when UTXO cluster information is incomplete.
- Improves Qt wallet-controller lifetime handling.
- Expands functional, unit, sanitizer, and fuzz coverage.
- Restores and hardens native Windows, sanitizer, and Guix CI paths.
- Verifies the macOS SDK archive used by reproducible builds.

## Compatibility

Syscoin Core is supported and tested on current Linux, macOS, and Windows
systems. It should also work on other Unix-like systems, although those
environments receive less testing.

This release includes consensus and bridge hardening. Core and sysgeth must be
upgraded as a matched pair; operators must not combine an activation-enabled
Core binary with an older sysgeth artifact.

## Reporting issues

Please report issues at:

- <https://github.com/syscoin/syscoin/issues>

## Credits

Thanks to the Syscoin community and to all contributors who reviewed, tested,
reported, and fixed issues for Liberty, as well as the upstream Bitcoin Core
and go-ethereum developers.
