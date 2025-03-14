# Syscoin 5.0.0 Release Notes

Syscoin Core version 5.0.0 (codename Nexus) is now available from:

- [Syscoin GitHub Releases](https://github.com/syscoin/syscoin/releases/tag/v5.0.0)

This major release includes new features, enhancements to both Syscoin Core and the NEVM (Geth) implementation, and numerous security/stability fixes since **Syscoin Core 4.4.2**. **All users, especially Masternode operators and NEVM node operators, must upgrade.**

You can review the community proposal for this release here https://syscoin.org/news/codename-nexus. Which passed yes - no by 888 votes. You can review the proposal here: 

Nexus sets the stage for the proceeding [roadmap](https://syscoin.org/news/roadmap-preview)

A more technical blog can be found on [medium](https://medium.com/@sidhujag/tying-it-all-together-scaling-bitcoin-with-syscoins-modular-ecosystem-d68e0fbe28fa)

Note: Syscoin Platform Tokens (SPTs) will be reindexed and existing SPTs (including SYSX) will lose state until the Nexus block is reached. If you have any assets in SPTs, please move them (for example SYSX burn to SYS or to NEVM) prior to the Nexus activation height. You will lose your SPT if you do not.

Please report any issues using the issue tracker on GitHub:

- [Syscoin Core Issues](https://github.com/syscoin/syscoin/issues)


## Table of Contents

1. [Upgrade Instructions](#upgrade-instructions)  
2. [Compatibility](#compatibility)  
3. [Major Changes from 4.4.2 to 5.0.0](#major-changes-from-442-to-500)  
    1. [Bitcoin Core Upstream Merges](#1-bitcoin-core-upstream-merges)  
    2. [NEVM (Syscoin Geth) Upgrades](#2-nevm-syscoin-geth-upgrades)  
    3. [Dynamic Governance](#3-dynamic-governance)  
    4. [AuxPoW Tags](#4-auxpow-tags)  
    5. [Enhanced NFT/Token Bridge (ERC721/1155/ERC20)](#5-enhanced-nfttoken-bridge-erc7211155erc20)  
    6. [NEVM Registry & PoDA Enhancements](#6-nevm-registry--poda-enhancements)  
    7. [BLS/LLMQ & Masternode Protocol Improvements](#7-blsllmq--masternode-protocol-improvements)  
    8. [Wallet & Descriptor Improvements](#8-wallet--descriptor-improvements)  
    9. [Removal of Deprecated Syscoin 4.x Asset RPCs](#9-removal-of-deprecated-syscoin-4x-asset-rpcs)  
    10. [Additional Miscellaneous Changes](#10-additional-miscellaneous-changes)  
4. [New/Updated RPCs](#newupdated-rpcs)  
5. [Known Issues](#known-issues)  
6. [Testing](#testing)  
7. [Credits](#credits)  


## Upgrade Instructions

Upgrade Instructions: <https://syscoin.readme.io/v5.0.0/docs/syscoin-50-upgrade-guide>

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then install
the new release:

- On **Windows**, run the installer.
- On **macOS**, copy over `/Applications/Syscoin-Qt`.
- On **Linux**, copy over the `syscoind`/`syscoin-qt` binaries.

If you are upgrading from a version older than 4.2.x, **please read**:  
[Syscoin 4.2 Upgrade Guide](https://syscoin.readme.io/v4.2.0/docs/syscoin-42-upgrade-guide)

We have an automated upgrade mechanism to force a reindex to the node upon detection of your first time running Syscoin 5. This is needed so the node remains consistent with the new network. The node should only reindex the first time you start Syscoin 5.

---

## Compatibility

- Supported & tested on **Linux** (kernel 3+), **macOS 10.15+**, and **Windows 7+**.
- Older OS versions are no longer supported.
- Should also run on most Unix-like systems, though less tested there.
- Legacy SPTs are removed, a new form of SPT will exist that is more efficient. Thus the old and new are not compatible, we skip indexing SPTs until Nexus is activated.
---

## Major Changes from 4.4.2 to 5.0.0

### 1. Bitcoin Core Upstream Merges
- Merged changes from **Bitcoin Core 24.x through ~25.x/26.x**, bringing security, performance, and mempool/policy improvements.
- **Descriptor wallets** remain the default wallet creation model introduced in Bitcoin 23.0.

### 2. NEVM (Syscoin Geth) Upgrades
- Incorporates upstream **go-ethereum** (Geth) changes from ~v1.10.x to v1.11.x, including performance fixes, EVM improvements.
- **NEVM chain rule updates** include EIP-3651, EIP-3855, and EIP-3860 (carried over from 4.4.0). NEVM registry is enabled on the NEVM in this release.

### 3. Dynamic Governance
- **Dynamic Governance**: On-chain mechanism that allows key chain parameters to be updated via masternode/community voting without a full hard fork.

### 4. AuxPoW Tags
- **AuxPoW Tags**: New block header metadata to improve coordination with merged-mining pools and external chain monitoring tools as well as new interesting BTC bridging designs using BitVM2. The blockhash + height is put into the Bitcoin coinbase. This is essential for a fork-aware bridge using BitVM2 for a fully trust-minimized sidechain two-way bridge between Bitcoin and Syscoin.
- **Wrapper**: The [getwork-wrapper.py](https://github.com/syscoin/syscoin/tree/master/contrib/auxpow/getwork-wrapper.py) ./contrib/auxpow/getwork-wrapper.py was updated to include the coinbasescript from the updated RPC. Miners that use external tools are recommended to update their script to include this into an OP_RETURN output, much like other projects are already doing.

### 5. Enhanced NFT/Token Bridge (ERC721/1155/ERC20)
- **Extended bridging support** for ERC721 (NFT), ERC1155 (multi-token), and standard ERC20 tokens between NEVM and Syscoin’s UTXO-based chain.
- Updated [NEVM bridge contracts](https://github.com/syscoin/sysethereum-contracts/) and logic in Syscoin Core for robust freeze/mint flows and event-based validations. A new SyscoinVaultManager contract deployed and SYS balances are moved over from the old ERC20Manager contract to the new one at the Nexus block in NEVM.

### 6. NEVM Registry & PoDA Enhancements
- **NEVM Registry**: A decentralized reference for registered Syscoin NEVM tokens/contracts. Supports easy lookup of token metadata, owners, etc. Precompile address (0x62) enables the registry on the NEVM. Every Sentry node must register their address via protx_update_service to add to registry. If you are using a hosting provider (allnodes, nodehub) they may also help manage your nodes using the registry. Future usage of the registry will include decentralized sequencing, social airdropping, AI node registration to AVS services and other services which want to economically align with Syscoin L1.
- **PoDA (Proof-of-Data Availability)**:  
  - Refined data blob creation and retrieval, with improved consensus checks.  
  - New RPCs to manage PoDA blobs for bridging or other on-chain references.

### 7. BLS/LLMQ & Masternode Protocol Improvements
- Finalizes the transition to the **Basic BLS IETF** standard scheme (v19 BLS upgrade):
  - **Masternode P2P messages** (e.g., `mnauth`, `qsigshare`, `qfcommit`) and `protx` transactions now use the new scheme after activation height.
- **MNLISTDIFF** improvements for more reliable masternode list sync. Because the MN lists are now stored in cache/db as a FIFO queue (up to the last 1728) instead the diff's which cleans up the implementation, we need to reindex the node upon upgrade to ensure the Sentry node list/state remains consistent with the network. We detect asset/assetnft directories which exist prior to Syscoin 5 as a form to upgrade detectabilty and thus force a reindex if those directories are found, subsequently deleting them as they are not needed in Syscoin 5 and further restarts do not reindex.

### 8. Wallet & Descriptor Improvements
- Descriptor wallets are default; legacy wallets remain possible by passing `"descriptor": false` in `createwallet`.
- Various upstream Bitcoin changes improve descriptor-based watch-only, multisig, and coin-selection behaviors.

### 9. Removal of Deprecated Syscoin 4.x Asset RPCs
- The following legacy asset RPC calls have been **removed**:
  ```
  assetnew, assettransfer, assetupdate, assetsend, assetsendmany,
  assetallocationbalance, assetallocationburn, assetallocationmint,
  assetallocationsend, assetallocationsendmany, etc.
  ```
- SysAssets now managed via NEVM bridging or external libraries such as [syscoinjs-lib](https://github.com/syscoin/syscoinjs-lib).

### 10. Additional Miscellaneous Changes
- **Performance**: Faster chain sync thanks to updated indexing and UTXO/NEVM improvements.
- **Security**: Enhanced bridging proof validation, spork logic, and PoDA referencing.
- **Logging**: More detailed logs for bridging events, NEVM calls, and masternode states.
- **SPT changes**: We simplified the SPT design and thus removed SPT management (updates, creation) and delegate that to the NEVM layer. Assets are expected to move from the NEVM bridge to exist in the SPT layer of Syscoin UTXO chain. The SPT design is more efficient and changes from the older one so therefor we re-start indexing SPTs starting from Syscoin 5 activation.
- Numerous other code refactors and bug fixes.

---

## New/Updated RPCs

1. **PoDA/Blob RPCs**  
   - `getnevmblobdata`: Retrieve PoDA/NEVM blob data by version hash.  
   - `listnevmblobdata`: Enumerate local PoDA blobs.  
   - `syscoincreatenevmblob`: Create PoDA blobs to store data references.

2. **Governance/Parameter Update RPCs** (Dynamic Governance)  
   - Potential new or updated commands for on-chain proposals and dynamic governance states (naming subject to final merges).

2. **AuxPoW Update RPCs** (AuxPoW tags)  
   - createauxblock/getauxblock returns "coinbasescript" field to be added a the Bitcoin coinbase output (it is an OP_RETURN commitment to mod 10th block back from the 5th block from the tip and its block height). The 5th block was used specifically because that is when a chainlock will likely prevent reorganizations of the chain and prevents false positive AuxPoW tags even in under adverserial conditions.
   The [RPC code](https://github.com/syscoin/syscoin/blob/master/src/rpc/auxpow_miner.cpp#L168) is as below:

    ```cpp
      int nActiveHeight = pindexTip->nHeight - 5;
      nActiveHeight -= nActiveHeight % 10;
      const CBlockIndex* refIndex = pindexTip->GetAncestor(nActiveHeight);
      result.pushKV ("coinbasescript", HexStr(createScriptPubKey(refIndex->GetBlockHash(), refIndex->nHeight)));
    ```
    The tag is enforced in consensus by [ContextualCheckBlockHeader](https://github.com/syscoin/syscoin/blob/master/src/validation.cpp#L4626).

---

## Known Issues

1. **Descriptor Wallet**: Some external tools may not fully support Syscoin’s descriptor model. You can revert to legacy mode if necessary.
2. **Dynamic Governance**: Stronger assumptions on community governance for public goods funding. Sentry node operators should remain vigilant about voting.

---

Continuous integration includes:
- [Unit tests](https://github.com/syscoin/syscoin/tree/master/src/test)
- [Functional tests](https://github.com/syscoin/syscoin/tree/master/test/functional)

---

## Credits

Thanks to the entire Syscoin community, as well as upstream [Bitcoin Core](https://bitcoincore.org/) and [go-ethereum](https://github.com/ethereum/go-ethereum/) developers. Special acknowledgment to all contributors who tested, reported issues, and proposed patches for Syscoin 5.0.0 features like bridging, PoDA expansions, BLS transitions, and dynamic governance.