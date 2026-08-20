// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_CONSENSUS_PARAMS_H
#define SYSCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>

#include <limits>
// SYSCOIN
#include <cmath>
#include <map>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

// SYSCOIN: Structural parameters for replaying historical tx85 commitments.
// An unassigned migration profile uses them for compatibility replay; a
// configured profile retires that replay after H. They are not a live BLS
// quorum configuration.
struct LegacyQuorumReplayParams {
    int size;
    // Structural replay preserves final-commitment minSize, not the smaller
    // recovered-signature threshold used by the removed BLS machinery.
    int minimum_size;
    int session_interval;
};
/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    // SYSCOIN
    uint64_t nSYSXAsset;
    uint32_t nNEVMChainID;
    // Pre-H vault (NEVM→UTXO mints below nBridgeV2StartBlock).
    std::vector<unsigned char> vchSyscoinVaultManagerLegacy;
    // Post-H vault (at/above nBridgeV2StartBlock). Stub until cutover deploy.
    std::vector<unsigned char> vchSyscoinVaultManager;
    std::vector<unsigned char> vchTokenFreezeMethod;
    unsigned int nSeniorityHeight1;
    double nSeniorityLevel1;
    unsigned int nSeniorityHeight2;
    double nSeniorityLevel2;
    bool bTestnet{false};
    int nBridgeStartBlock;
    int nNEVMStartBlock;
    int nCLReceiptStartBlock;
    // SYSCOIN: begin post-quantum migration and receipt policy.
    // Mandatory BLS-free activation boundary. The all-sentinel profile is a
    // compatibility-replay state only; activation pins this exact block and
    // the reconstructed state used to bootstrap post-quantum quorums.
    int nPQLegacyAnchorHeight{std::numeric_limits<int>::max()};
    uint256 hashPQLegacyAnchorBlock;
    uint256 hashPQLegacyMNState;
    uint256 hashPQLegacyPQRegistryState;
    // Immutable predecessor of the first PQ ChainLock. This is distinct from
    // the migration-state anchor so preparation history can be built before
    // finality is enabled without leaving bootstrap rosters branch-derived.
    int nPQChainLockAnchorHeight{std::numeric_limits<int>::max()};
    uint256 hashPQChainLockAnchorBlock;
    // PQ ChainLock deployment remains fail-closed until a release pins all
    // values. Preparation is the first height accepting key-registry
    // transactions; it must be no later than the migration anchor and must
    // precede epoch zero's registration cutoff so the anchor commits the
    // reconstructed registry.
    // The epoch and BTCC origins are schedule anchors.
    int nPQPreparationHeight{std::numeric_limits<int>::max()};
    int nPQChainLockEpochOrigin{std::numeric_limits<int>::max()};
    uint32_t nPQRegistrationCutoffBlocks{0};
    int nPQRosterSnapshotLag{288}; // SYSCOIN: Freeze PQ rosters on an earlier branch-bound snapshot.
    uint32_t nPQFutureHorizonEpochs{0};
    int nPQBTCCCandidateOrigin{std::numeric_limits<int>::max()};
    // Candidate H is signed by the H+5 ChainLock round and may first be
    // receipted after the fixed five-block propagation buffer at H+10.
    int nPQBTCCNEVMInjectionLag{10};
    // SYSCOIN: Release-updatable historical BTCC receipt assumption boundary.
    // This is intentionally independent from both immutable anchors: only the
    // pre-boundary receipt-certificate crypto is assumed here.
    int nPQBTCCReceiptAnchorHeight{std::numeric_limits<int>::max()};
    uint256 hashPQBTCCReceiptAnchorBlock;
    int nPQBTCCReceiptAnchorCursorHeight{-1};
    uint256 hashPQBTCCReceiptAnchorCursorSysBlock;
    uint256 hashPQBTCCReceiptAnchorCursorBTCBlock;
    uint256 hashPQBTCCReceiptAnchorState;
    // SYSCOIN: end post-quantum migration and receipt policy.
    // Bridge V2 vault-manager cutover (independent of nCLReceiptStartBlock).
    int nBridgeV2StartBlock{std::numeric_limits<int>::max()};
    int64_t nNEVMStartTime;
    int nPODAStartBlock;
    int nNexusStartBlock;
    int nV19StartBlock;
    int nNEVMBootstrapBypassHeight{0};
    uint64_t nMinMNSubsidySats;
        
    int nSuperblockStartBlock;
    int nSuperblockCycle; // in blocks
    int nSuperblockMaturityWindow; // in blocks
    int nGovernanceMinQuorum; // Min absolute vote count to trigger an action
    int nGovernanceFilterElements;
    int nMasternodeMinimumConfirmations;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int SuperBlockCycle(int nHeight) const { 
        if (nHeight >= nNEVMStartBlock) {
            return nSuperblockCycle;
        } else {
            return nSuperblockCycle*2.5;
        }
    }
    double Seniority(int nHeight, int nStartHeight) const {
        unsigned int nSeniorityAge = 0;
        if (nHeight > nNEVMStartBlock) {
            const unsigned int nDifferenceInBlocksPreNEVM = std::max(nNEVMStartBlock - nStartHeight, 0);
            const unsigned int nDifferenceInBlocksPostNEVM = nHeight - std::max(nStartHeight, nNEVMStartBlock);
            nSeniorityAge = nDifferenceInBlocksPreNEVM + nDifferenceInBlocksPostNEVM*2.5;
        } else {
            nSeniorityAge = nHeight - nStartHeight;
        } 
        if(nSeniorityAge >= nSeniorityHeight2)
            return nSeniorityLevel2;
        else if(nSeniorityAge >= nSeniorityHeight1)
            return nSeniorityLevel1;
        return 0;
    }
    int SubsidyHalvingIntervals(int nHeight) const { 
        if(bTestnet) {
            if (nHeight >= nNEVMStartBlock) {
                return nHeight/nSubsidyHalvingInterval;
            } else {
                return nHeight/(nSubsidyHalvingInterval*2.5);
            }
        }
        if (nHeight >= nNEVMStartBlock) {
            static double forkIntervals = nNEVMStartBlock/(nSubsidyHalvingInterval*2.5);
            return floor(forkIntervals + (((double)(nHeight-nNEVMStartBlock))/((double)nSubsidyHalvingInterval)));
        } else {
            return nHeight/(nSubsidyHalvingInterval*2.5);
        }
    }
    int64_t PowTargetSpacing(int nHeight) const {
        if(nHeight >= nNEVMStartBlock) {
            return nPowTargetSpacing; 
        } else {
            return (nPowTargetSpacing/2.5); 
        }
    }
    int64_t DifficultyAdjustmentInterval(int nHeight) const {
        return nPowTargetTimespan / PowTargetSpacing(nHeight);
    }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;
    // SYSCOIN: The release-pinned BTCC receipt anchor must cover every block
    // whose scripts can be skipped by the compiled assume-valid default.
    int nDefaultAssumeValidHeight{-1};
    /** Auxpow parameters */
    int32_t nAuxpowChainId;
    int32_t nAuxpowOldChainId;
    int nAuxpowStartHeight;
    bool fStrictChainId;
    int nLegacyBlocksBefore; // -1 for "always allow"

     /**
     * Check whether or not to allow legacy blocks at the given height.
     * @param nHeight Height of the block to check.
     * @return True if it is allowed to have a legacy version.
     */
    bool AllowLegacyBlocks(unsigned nHeight) const
    {
        if (nLegacyBlocksBefore < 0)
            return true;
        return static_cast<int> (nHeight) < nLegacyBlocksBefore;
    }
    // SYSCOIN
    /** Block height at which DIP0003 becomes active */
    int DIP0003Height;
    /** Block height at which DIP0003 becomes enforced */
    int DIP0003EnforcementHeight;
    LegacyQuorumReplayParams legacyQuorumReplay;
        /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

} // namespace Consensus
#endif // SYSCOIN_CONSENSUS_PARAMS_H
