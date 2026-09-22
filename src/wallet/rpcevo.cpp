// Copyright (c) 2018-2020 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/validation.h>
// SYSCOIN: post-quantum operator/root lifecycle dependencies.
#include <consensus/pq_migration_config.h>
#include <crypto/slhdsa/slhdsa.h>
#include <core_io.h>
#include <hash.h>
#include <init.h>
#include <messagesigner.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <util/moneystr.h>
#include <validation.h>

#include <wallet/coincontrol.h>
#include <wallet/pq_key_schedule.h>
#include <wallet/spend.h>
#include <wallet/rpc/util.h>

#include <netbase.h>

#include <evo/specialtx.h>
#include <evo/providertx.h>
#include <evo/deterministicmns.h>
#include <evo/pq_providertx.h>
#include <evo/pq_owner_key.h>
#include <evo/pq_registry.h>
#include <governance/governancevote.h>

#include <llmq/pq_global_auth.h>

#include <masternode/masternodemeta.h>
#include <masternode/pq_operatorkeys.h>
#include <rpc/util.h>
#include <rpc/blockchain.h>
#include <util/message.h>
#include <util/translation.h>
#include <node/context.h>
#include <node/transaction.h>
#include <wallet/rpc/spend.h>
#include <wallet/rpc/wallet.h>
#include <llmq/quorums_utils.h>
#include <common/args.h>
#include <index/txindex.h>
#include <support/cleanse.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <functional>
#include <limits>
#include <optional>
#include <span>
#include <utility>
#include <vector>
using namespace wallet;

// SYSCOIN: cleanse transient PQ operator and child-root secrets.
namespace {

class SensitiveBytesGuard final
{
public:
    explicit SensitiveBytesGuard(std::vector<unsigned char>& bytes) noexcept
        : m_bytes{bytes}
    {
    }

    ~SensitiveBytesGuard()
    {
        memory_cleanse(m_bytes.data(), m_bytes.size());
    }

    SensitiveBytesGuard(const SensitiveBytesGuard&) = delete;
    SensitiveBytesGuard& operator=(const SensitiveBytesGuard&) = delete;

private:
    std::vector<unsigned char>& m_bytes;
};

class SensitiveChainLockSeedGuard final
{
public:
    explicit SensitiveChainLockSeedGuard(
        llmq::pq::ChainLockMasterSeed& seed) noexcept
        : m_seed{seed}
    {
    }
    ~SensitiveChainLockSeedGuard()
    {
        memory_cleanse(m_seed.data(), m_seed.size());
    }

    SensitiveChainLockSeedGuard(const SensitiveChainLockSeedGuard&) = delete;
    SensitiveChainLockSeedGuard& operator=(
        const SensitiveChainLockSeedGuard&) = delete;

private:
    llmq::pq::ChainLockMasterSeed& m_seed;
};

// SYSCOIN: wallet RPCs carry WalletContext, so reach the owning node through
// the wallet chain interface instead of interpreting the RPC context as one.
static node::NodeContext& GetWalletNodeContext(const CWallet& wallet)
{
    node::NodeContext* const node{wallet.chain().context()};
    if (node == nullptr || node->chainman == nullptr) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Wallet node context is unavailable");
    }
    return *node;
}

} // namespace

static CKeyID ParsePubKeyIDFromAddress(const std::string& strAddress, const std::string& paramName)
{
    CTxDestination dest = DecodeDestination(strAddress);
    const WitnessV0KeyHash *keyID = std::get_if<WitnessV0KeyHash>(&dest);
    if (!keyID) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s must be a valid P2PWKH address, not %s", paramName, strAddress));
    }
    return ToKeyID(*keyID);
}

// SYSCOIN: PQ operator/root parsing and fixed-depth commitment construction.
static slhdsa::SecretKey ParseSLHSecretKey(const std::string& hex_key,
                                           const std::string& param_name)
{
    if (!IsHex(hex_key) || hex_key.size() != slhdsa::SECRET_KEY_SIZE * 2) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("%s must be an exactly %u-byte SLH-DSA-SHAKE-128s secret key",
                      param_name, slhdsa::SECRET_KEY_SIZE));
    }
    auto bytes = ParseHex(hex_key);
    const SensitiveBytesGuard cleanse_bytes{bytes};
    auto key = slhdsa::ImportSecretKey(bytes);
    if (!key) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           strprintf("%s is not a valid SLH-DSA secret key",
                                     param_name));
    }
    return std::move(*key);
}

static void ParseChainLockMasterSeed(
    const std::string& hex_seed,
    llmq::pq::ChainLockMasterSeed& output)
{
    if (!IsHex(hex_seed) ||
        hex_seed.size() != llmq::pq::CHAINLOCK_MASTER_SEED_SIZE * 2) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("chainlockSeed must be an exactly %u-byte independent ChainLock seed",
                      llmq::pq::CHAINLOCK_MASTER_SEED_SIZE));
    }
    auto bytes = ParseHex(hex_seed);
    const bool valid = llmq::pq::ImportChainLockMasterSeed(bytes, output);
    memory_cleanse(bytes.data(), bytes.size());
    if (!valid) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "chainlockSeed must not be all zero");
    }
}

static llmq::pq::ChildKeyTreeCommitment BuildChildKeyTreeCommitment(
    const llmq::pq::ChainLockMasterSeed& chainlock_seed,
    const uint256& pro_tx_hash,
    uint32_t generation,
    uint32_t first_epoch)
{
    if (!llmq::pq::IsValidChildKeyTreeGeneration(generation)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Child-key tree generation is outside the consensus range");
    }
    const auto tree_id{llmq::pq::GetChildKeyTreeId(
        Params().GetConsensus().hashGenesisBlock, pro_tx_hash, generation,
        first_epoch)};
    if (!tree_id) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Unable to derive the child-key tree ID");
    }
    uint256 fixture_root;
    const bool use_test_stub{
        gArgs.GetBoolArg("-pqoperatorcommitmentteststub", false)};
    const std::string fixture{
        gArgs.GetArg("-pqoperatorcommitmenttestfixture", "")};
    const bool verify_fixture{
        gArgs.GetBoolArg("-pqoperatorcommitmenttestfixtureverify", false)};
    if (fixture.empty() && verify_fixture) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "-pqoperatorcommitmenttestfixtureverify requires a fixture");
    }
    if (use_test_stub && (!fixture.empty() || verify_fixture ||
                          Params().GetChainType() != ChainType::REGTEST ||
                          !Params().MineBlocksOnDemand() ||
                          !gArgs.GetBoolArg("-pqfinalitypreparation", false))) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "PQ operator commitment test stubs require preparation-only "
            "mine-on-demand regtest and no exact fixture");
    }
    if (!fixture.empty()) {
        // SYSCOIN: Low-core CI exercises the real registration signatures and
        // state transition with a production-generated commitment. Only the
        // 65,536-leaf expansion is substituted, and only on isolated regtest.
        if (Params().GetChainType() != ChainType::REGTEST ||
            !Params().MineBlocksOnDemand()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "-pqoperatorcommitmenttestfixture is restricted to "
                "mine-on-demand regtest");
        }
        const auto fields{SplitString(fixture, ':')};
        if (fields.size() != 6 ||
            !IsHex(fields[0]) || fields[0].size() != 64 ||
            !IsHex(fields[1]) || fields[1].size() != 64 ||
            !IsHex(fields[2]) || fields[2].size() != 64 ||
            !IsHex(fields[5]) || fields[5].size() != 64) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Malformed PQ operator commitment test fixture");
        }
        uint32_t fixture_generation;
        uint32_t fixture_first_epoch;
        if (!ParseUInt32(fields[3], &fixture_generation) ||
            !ParseUInt32(fields[4], &fixture_first_epoch)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "Malformed PQ operator commitment test fixture schedule");
        }
        if (uint256S(fields[1]) != Hash(chainlock_seed) ||
            fixture_generation != generation ||
            fixture_first_epoch != first_epoch ||
            uint256S(fields[0]) != Params().GetConsensus().hashGenesisBlock) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "PQ operator commitment test fixture does not match the "
                "requested seed or schedule");
        }
        fixture_root = uint256S(fields[5]);
        if (uint256S(fields[2]) != *tree_id || fixture_root.IsNull()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "PQ operator commitment test fixture has the wrong tree ID "
                "or a null root");
        }
    }

    const llmq::pq::ChildKeyTreeConfig config{
        Params().GetConsensus().hashGenesisBlock,
        *tree_id,
        generation,
        first_epoch,
        llmq::pq::CHILD_KEY_TREE_DEPTH,
    };
    if (use_test_stub) {
        // The broad governance/MN suite exercises global-key authorization and
        // registry transitions, not child signing. A domain-separated fake
        // root keeps those tests from multiplying the production 65,536-leaf
        // build across every parallel test process.
        CHashWriter writer{SER_GETHASH, 0};
        writer << std::string{"SYS_PQ_OPERATOR_TEST_STUB_V1"}
               << config.genesis_hash << config.tree_id << config.generation
               << config.first_epoch << config.depth;
        fixture_root = writer.GetHash();
        if (fixture_root.IsNull()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR,
                               "Generated PQ operator test root is null");
        }
    }
    std::optional<llmq::pq::ChildKeyTree> tree;
    if (fixture_root.IsNull() || verify_fixture) {
        tree = llmq::pq::ChildKeyTree::Build(
            chainlock_seed, config,
            llmq::pq::DefaultChildKeyTreeWorkerCount());
        if (!tree) {
            throw JSONRPCError(
                RPC_INTERNAL_ERROR,
                "Failed to build the fixed-depth scheduled-WOTS public-key tree");
        }
        if (verify_fixture && tree->GetRoot() != fixture_root) {
            throw JSONRPCError(
                RPC_INTERNAL_ERROR,
                strprintf("PQ operator commitment test fixture root %s does "
                          "not match production builder root %s",
                          fixture_root.ToString(),
                          tree->GetRoot().ToString()));
        }
    }

    llmq::pq::ChildKeyTreeCommitment commitment;
    commitment.generation = generation;
    commitment.first_epoch = first_epoch;
    commitment.tree_id = *tree_id;
    commitment.root = fixture_root.IsNull() ? tree->GetRoot() : fixture_root;
    if (!commitment.IsStructurallyValid()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Generated scheduled-WOTS child-key commitment is invalid");
    }
    return commitment;
}

// SYSCOIN: post-quantum operator/root lifecycle.
static UniValue protx_generate_operator_keys()
{
    slhdsa::KeyGenerationSeed global_seed{};
    llmq::pq::ChainLockMasterSeed chainlock_seed{};
    GetStrongRandBytesChunked(global_seed);
    GetStrongRandBytes(chainlock_seed);
    auto global_key = slhdsa::GenerateSecretKey(global_seed);
    memory_cleanse(global_seed.data(), global_seed.size());
    if (!global_key) {
        memory_cleanse(chainlock_seed.data(), chainlock_seed.size());
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Failed to generate SLH-DSA operator key");
    }
    std::array<uint8_t, slhdsa::SECRET_KEY_SIZE> encoded_global{};
    if (!global_key->Export(encoded_global)) {
        memory_cleanse(encoded_global.data(), encoded_global.size());
        memory_cleanse(chainlock_seed.data(), chainlock_seed.size());
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Failed to export SLH-DSA operator key");
    }
    UniValue result{UniValue::VOBJ};
    result.pushKV("operatorKey", HexStr(encoded_global));
    result.pushKV("chainlockSeed", HexStr(chainlock_seed));
    memory_cleanse(encoded_global.data(), encoded_global.size());
    memory_cleanse(chainlock_seed.data(), chainlock_seed.size());
    return result;
}

// SYSCOIN: gate PQ-only provider RPCs at their consensus boundaries.
static void EnsurePQProviderRPCActive(int current_height)
{
    const auto& consensus = Params().GetConsensus();
    if (Consensus::CheckPQActivationConfiguration(consensus) !=
            Consensus::PQActivationResult::VALID ||
        current_height + 1 < consensus.nPQActivationHeight) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "Post-quantum provider RPCs require PQ activation at the next block height");
    }
}

// SYSCOIN: Provider registration follows the next block's consensus era.
// Public pre-activation callers must still supply their legacy operator key;
// preparation-only regtest may synthesize opaque bytes because no legacy BLS
// operation is performed and the key exists only to build migration history.
static void ConfigureProviderRegistrationForNextBlock(
    CProRegTx& payload,
    int current_height,
    const std::string& legacy_operator_public_key)
{
    const auto replay{Consensus::CheckPQLegacyReplay(
        Params().GetConsensus(), current_height + 1)};
    if (replay == Consensus::PQLegacyReplayResult::INVALID_CONFIGURATION) {
        throw JSONRPCError(RPC_MISC_ERROR,
                           "Invalid post-quantum activation configuration");
    }
    if (replay == Consensus::PQLegacyReplayResult::RETIRED) {
        EnsurePQProviderRPCActive(current_height);
        if (!legacy_operator_public_key.empty()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "legacyOperatorPubKey must be empty after PQ activation");
        }
        payload.nVersion = CProRegTx::PQ_VERSION;
        return;
    }

    payload.nVersion = CProRegTx::GetVersion(
        llmq::CLLMQUtils::IsV19Active(current_height));
    std::vector<unsigned char> encoded;
    if (!legacy_operator_public_key.empty()) {
        if (!IsHex(legacy_operator_public_key)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                               "legacyOperatorPubKey must be hexadecimal");
        }
        encoded = ParseHex(legacy_operator_public_key);
    } else {
        if (Params().GetChainType() != ChainType::REGTEST ||
            !Params().MineBlocksOnDemand() ||
            !gArgs.GetBoolArg("-pqfinalitypreparation", false)) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "legacyOperatorPubKey is required before PQ activation");
        }
        encoded.resize(CLegacyBLSPublicKey::SERIALIZED_SIZE);
        GetStrongRandBytesChunked(encoded);
        encoded.front() |= 1U;
    }
    if (!payload.pubKeyOperator.SetBytes(encoded) ||
        !payload.pubKeyOperator.IsValid()) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            strprintf("legacyOperatorPubKey must encode exactly %u nonzero bytes",
                      static_cast<unsigned>(
                          CLegacyBLSPublicKey::SERIALIZED_SIZE)));
    }
}

static llmq::pq::GlobalPublicKey ParseVotingPublicKey(const std::string& encoded,
                                                     bool allow_revocation = false)
{
    llmq::pq::GlobalPublicKey public_key{};
    if (encoded.size() != public_key.size() * 2 || !IsHex(encoded)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Voting key must be an exactly 32-byte SLH-DSA public key in hex");
    }
    const auto bytes{ParseHex(encoded)};
    std::copy(bytes.begin(), bytes.end(), public_key.begin());
    if (!allow_revocation && llmq::pq::IsNullVotingPublicKey(public_key)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Voting public key must not be zero");
    }
    return public_key;
}

static void ConfigureProviderVotingKey(CProRegTx& payload, const std::string& voting_key)
{
    payload.keyIDVoting = payload.keyIDOwner;
    if (payload.nVersion == CProRegTx::PQ_VERSION) {
        payload.pqVotingPublicKey = ParseVotingPublicKey(voting_key);
    } else if (!voting_key.empty()) {
        payload.keyIDVoting = ParsePubKeyIDFromAddress(voting_key, "voting address");
    }
}

// SYSCOIN: new PQ registrations use an independent wallet-held SLH owner.
static void ConfigureProviderOwnerKey(CProRegTx& payload, const std::string& owner)
{
    if (payload.nVersion == CProRegTx::PQ_VERSION) {
        payload.pqOwnerPublicKey = ParseVotingPublicKey(owner);
        payload.keyIDOwner = {};
    } else {
        payload.keyIDOwner = ParsePubKeyIDFromAddress(owner, "owner address");
    }
}

static void SignProviderOwnerProof(CWallet& wallet, CProRegTx& payload)
{
    if (payload.nVersion != CProRegTx::PQ_VERSION) return;
    std::string error;
    if (!wallet.SignOwnerAuthorization(payload.pqOwnerPublicKey,
            GetProRegOwnerAuthorizationHash(Params().GetConsensus().hashGenesisBlock, payload),
            llmq::pq::PQ_OWNER_PROOF_CONTEXT, payload.pqOwnerProof, error)) {
        throw JSONRPCError(RPC_WALLET_ERROR, error);
    }
}

static void SignRegistrarOwner(CWallet& wallet, const CDeterministicMNState& state,
                               CProUpRegTx& payload)
{
    const uint256 digest{GetProUpRegOwnerAuthorizationHash(
        Params().GetConsensus().hashGenesisBlock, payload)};
    payload.vchSig.clear();
    if (state.pqOwnerKey.HasActiveKey()) {
        slhdsa::Signature signature{};
        std::string error;
        if (!wallet.SignOwnerAuthorization(state.pqOwnerKey.public_key, digest,
                llmq::pq::PQ_OWNER_UPDATE_CONTEXT, signature, error)) {
            throw JSONRPCError(RPC_WALLET_ERROR, error);
        }
        payload.vchSig.assign(signature.begin(), signature.end());
    } else {
        CKey key;
        if (!wallet.GetKey(state.keyIDOwner, key)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "The masternode owner key is not in this wallet");
        }
        // Legacy registrar signatures retain their historical hash unless
        // explicitly enrolling a new PQ owner in the domain-separated transcript.
        const uint256 legacy_digest{llmq::pq::IsNullOwnerPublicKey(payload.pqOwnerPublicKey)
            ? ::SerializeHash(payload) : digest};
        if (!CHashSigner::SignHash(legacy_digest, key, payload.vchSig)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign owner authorization");
        }
    }
}

static void EnsurePQPreparationRPCActive(int current_height)
{
    llmq::pq::PQRegistryConfig config;
    if (llmq::pq::GetPQRegistryConfig(Params().GetConsensus(), config) !=
            llmq::pq::PQRegistryDeploymentResult::VALID ||
        current_height + 1 < config.preparation_height) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "PQ operator-key registration is not active at the next block height");
    }
}

static uint32_t NextPQFirstMutableEpoch(node::NodeContext& node)
{
    LOCK(cs_main);
    const CBlockIndex* tip{node.chainman->ActiveTip()};
    if (tip == nullptr) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Active chain tip is unavailable");
    }
    EnsurePQPreparationRPCActive(tip->nHeight);
    llmq::pq::PQRegistryConfig config;
    if (llmq::pq::GetPQRegistryConfig(Params().GetConsensus(), config) !=
        llmq::pq::PQRegistryDeploymentResult::VALID) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "PQ registry configuration is invalid");
    }
    const auto view{llmq::pq::DeriveOperatorKeyScheduleView(
        config.schedule, tip->nHeight + 1,
        config.registration_cutoff_blocks, config.future_horizon_epochs)};
    if (!view) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Unable to derive the next-block PQ key schedule");
    }
    return view->first_mutable_epoch;
}

static llmq::pq::ChildKeyTreeCommitment BuildCurrentChildKeyTreeCommitment(
    node::NodeContext& node,
    const llmq::pq::ChainLockMasterSeed& chainlock_seed,
    const uint256& pro_tx_hash,
    uint32_t generation)
{
    const auto commitment{BuildCurrentPQChildKeyCommitment(
        [&]() { return NextPQFirstMutableEpoch(node); },
        [&](uint32_t first_epoch) {
            return BuildChildKeyTreeCommitment(
                chainlock_seed, pro_tx_hash, generation, first_epoch);
        })};
    if (!commitment) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "PQ registration cutoff changed repeatedly during child-key tree "
            "construction; retry the RPC");
    }
    return *commitment;
}

static void EnsureCurrentChildKeyCommitmentSchedule(
    node::NodeContext& node,
    const llmq::pq::ChildKeyTreeCommitment& commitment)
{
    if (commitment.first_epoch != NextPQFirstMutableEpoch(node)) {
        throw JSONRPCError(
            RPC_MISC_ERROR,
            "PQ registration cutoff changed during transaction preparation; "
            "retry the RPC");
    }
}

template<typename SpecialTxPayload>
static void FundSpecialTx(wallet::CWallet& pwallet, CMutableTransaction& tx, const SpecialTxPayload& payload, const CTxDestination& fundDest)
{

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet.BlockUntilSyncedToCurrentChain();
    {
        LOCK(pwallet.cs_wallet);

        CTxDestination nodest = CNoDestination();
        if (fundDest == nodest) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "No source of funds specified");
        }

        SetTxPayload(tx, payload);
        std::vector<CRecipient> vecSend;
        for (const auto& txOut : tx.vout) {
            CTxDestination dest;
            ExtractDestination(txOut.scriptPubKey, dest);
            CRecipient recipient = {dest, txOut.nValue, false};
            vecSend.push_back(recipient);
        }

        CCoinControl coinControl;
        coinControl.destChange = fundDest;

        std::vector<COutput> vecOutputs;
        vecOutputs = AvailableCoins(pwallet).All();

        for (const auto& out : vecOutputs) {
            CTxDestination txDest;
            if (ExtractDestination(out.txout.scriptPubKey, txDest) && txDest == fundDest) {
                coinControl.Select(COutPoint(out.outpoint.hash, out.outpoint.n));
            }
        }

        if (!coinControl.HasSelected()) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "No funds at specified address");
        }
        constexpr int RANDOM_CHANGE_POSITION = -1;
        CTransactionRef wtx;
        auto res = CreateTransaction(pwallet, vecSend, RANDOM_CHANGE_POSITION, coinControl);
        if (!res) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, util::ErrorString(res).original);
        }
        auto &txr = *res;
        wtx = txr.tx;
        tx.vin = wtx->vin;
        tx.vout = wtx->vout;
    }

}

template<typename SpecialTxPayload>
static void UpdateSpecialTxInputsHash(const CMutableTransaction& tx, SpecialTxPayload& payload)
{
    payload.inputsHash = CalcTxInputsHash(CTransaction(tx));
}

template<typename SpecialTxPayload>
static void SignSpecialTxPayloadByHash(const CMutableTransaction& tx, SpecialTxPayload& payload, const CKey& key)
{
    UpdateSpecialTxInputsHash(tx, payload);
    payload.vchSig.clear();

    uint256 hash = ::SerializeHash(payload);
    if (!CHashSigner::SignHash(hash, key, payload.vchSig)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "failed to sign special tx");
    }
}

// SYSCOIN: canonical global-operator lookup and authorization helpers.
static llmq::pq::OperatorKeyState GetActivePQOperator(
    const CBlockIndex* tip,
    const uint256& pro_tx_hash,
    const llmq::pq::GlobalPublicKey& public_key)
{
    llmq::pq::PQRegistryReadView snapshot;
    std::string error;
    if (tip == nullptr || !deterministicMNManager->GetPQRegistryReadView(
                              tip, snapshot, error)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Unable to read active PQ operator registry: " + error);
    }
    const auto* state = snapshot.FindOperator(pro_tx_hash);
    if (state == nullptr || !state->HasActiveGlobalKey() ||
        public_key != state->global_key.public_key) {
        throw JSONRPCError(
            RPC_INVALID_PARAMETER,
            "The SLH-DSA operator key is not the active registered global key");
    }
    return *state;
}

static llmq::pq::OperatorKeyState GetActivePQOperator(
    const CBlockIndex* tip,
    const uint256& pro_tx_hash,
    const slhdsa::SecretKey& key)
{
    llmq::pq::GlobalPublicKey public_key{};
    if (!key.GetPublicKey(public_key)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Unable to derive the SLH-DSA public key");
    }
    return GetActivePQOperator(tip, pro_tx_hash, public_key);
}

static void SignInitialGlobalKeyPayload(
    llmq::pq::GlobalKeyTxPayload& payload,
    CWallet& wallet,
    const CDeterministicMNState& owner_state,
    const slhdsa::SecretKey& operator_key,
    const llmq::pq::GlobalKeyRecord* previous_key = nullptr,
    bool prepare_only = false)
{
    const uint256 genesis_hash = Params().GetConsensus().hashGenesisBlock;
    const auto owner_hash = llmq::pq::GetGlobalOwnerRegistrationAuthorizationHash(
        genesis_hash, payload);
    const auto operator_hash = previous_key == nullptr
        ? llmq::pq::GetGlobalRegistrationAuthorizationHash(
              genesis_hash, payload.pro_tx_hash, payload.candidate,
              payload.transaction_inputs_hash)
        : llmq::pq::GetGlobalRecoveryAuthorizationHash(
              genesis_hash, payload.pro_tx_hash, *previous_key,
              payload.candidate, payload.transaction_inputs_hash);
    if (!owner_hash || !operator_hash) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid operator registration transcript");
    }
    payload.owner_authorization.fill(0);
    payload.pq_owner_authorization.fill(0);
    if (prepare_only) {
        // Canonical placeholders are transported only in an RPC request.
        // They are replaced and verified before a transaction can be submitted.
        if (owner_state.pqOwnerKey.HasActiveKey()) {
            payload.pq_owner_authorization.front() = 1;
        } else {
            payload.owner_authorization[0] = 27;
            payload.owner_authorization[32] = 1;
            payload.owner_authorization[64] = 1;
        }
    } else if (owner_state.pqOwnerKey.HasActiveKey()) {
        std::string error;
        if (!wallet.SignOwnerAuthorization(owner_state.pqOwnerKey.public_key,
                *owner_hash, llmq::pq::PQ_GLOBAL_OWNER_REGISTER_CONTEXT,
                payload.pq_owner_authorization, error)) {
            throw JSONRPCError(RPC_WALLET_ERROR, error);
        }
    } else {
        CKey key;
        std::vector<unsigned char> signature;
        if (!wallet.GetKey(owner_state.keyIDOwner, key)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "The masternode owner key is not in this wallet");
        }
        if (!CHashSigner::SignHash(*owner_hash, key, signature) ||
            signature.size() != payload.owner_authorization.size()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign operator owner authorization");
        }
        std::copy(signature.begin(), signature.end(), payload.owner_authorization.begin());
    }
    if (!slhdsa::SignDeterministic(
            operator_key,
            std::span<const uint8_t>{operator_hash->begin(), operator_hash->size()},
            llmq::pq::GetGlobalAuthContext(
                llmq::pq::GlobalAuthPurpose::GLOBAL_REGISTRATION),
            payload.authorization)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Failed to sign PQ global-key proof of possession");
    }
}

static void SignGlobalKeyRotationPayload(
    llmq::pq::GlobalKeyTxPayload& payload,
    const llmq::pq::GlobalKeyRecord& current,
    const slhdsa::SecretKey& current_key)
{
    const auto authorization_hash = llmq::pq::GetGlobalRotationAuthorizationHash(
        Params().GetConsensus().hashGenesisBlock, payload.pro_tx_hash,
        current, payload.candidate, payload.transaction_inputs_hash);
    if (!authorization_hash ||
        !slhdsa::SignDeterministic(
            current_key,
            std::span<const uint8_t>{authorization_hash->begin(),
                                     authorization_hash->size()},
            llmq::pq::GetGlobalAuthContext(
                llmq::pq::GlobalAuthPurpose::GLOBAL_ROTATION),
            payload.authorization)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Failed to sign PQ global-key rotation");
    }
}
static UniValue SignAndSendSpecialTx(const node::JSONRPCRequest& request, const wallet::CWallet& pwallet, const CMutableTransaction& tx, bool fSubmit = true,
                                    const std::function<void()>& check_prepared = {}, bool check_fee_cap = false)
{
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << tx;

    node::JSONRPCRequest signRequest;
    signRequest.context = request.context;
    signRequest.URI = request.URI;
    signRequest.params.setArray();
    signRequest.params.push_back(HexStr(ds));
    UniValue signResult = signrawtransactionwithwallet().HandleRequest(signRequest);
    if (!signResult["complete"].get_bool()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to sign all transaction fee inputs");
    }
    CTransactionRef txRef;
    if (fSubmit || check_fee_cap) {
        CMutableTransaction mtx;
        if (!DecodeHexTx(mtx, signResult["hex"].get_str())) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
        }
        txRef = MakeTransactionRef(std::move(mtx));
    }
    CAmount max_raw_tx_fee{0};
    if (txRef) {
        max_raw_tx_fee = node::DEFAULT_MAX_RAW_TX_FEE_RATE.GetFee(GetVirtualTransactionSize(*txRef));
    }
    if (check_fee_cap) {
        // A provider request may be signed by a different operator. Protect the
        // funding wallet even when the caller requests offline transaction hex.
        std::map<COutPoint, Coin> coins;
        for (const auto& input : txRef->vin) {
            if (!coins.emplace(input.prevout, Coin{}).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Operator registration contains duplicate fee inputs");
            }
        }
        pwallet.chain().findCoins(coins);
        CAmount input_value{0};
        for (const auto& [outpoint, coin] : coins) {
            if (coin.IsSpent() || !MoneyRange(coin.out.nValue) || coin.out.nValue > MAX_MONEY - input_value) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Operator registration fee inputs are unavailable or invalid");
            }
            input_value += coin.out.nValue;
        }
        CAmount output_value{0};
        for (const auto& output : txRef->vout) {
            if (!MoneyRange(output.nValue) || output.nValue > MAX_MONEY - output_value) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Operator registration output amounts are invalid");
            }
            output_value += output.nValue;
        }
        if (input_value < output_value || input_value - output_value > max_raw_tx_fee) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Operator registration fee is invalid or exceeds the maximum fee rate");
        }
    }
    // Funding, wallet signing and fee checks can cross a cutoff. Check even
    // the offline result immediately before exposing the signed transaction.
    if (check_prepared) check_prepared();
    if (!fSubmit) {
        return signResult["hex"].get_str();
    }
    std::string err_string;
    if (!pwallet.chain().broadcastTransaction(txRef, max_raw_tx_fee, true, err_string)) {
        throw JSONRPCError(RPC_WALLET_ERROR, err_string);
    }
    return txRef->GetHash().GetHex();
}


// handles register, register_prepare and register_fund
// SYSCOIN: provider registration is serialized for the next block's era.
static RPCHelpMan protx_register()
{
    return RPCHelpMan{"protx_register",
                "\nSame as \"protx_register_fund\", but with an externally referenced collateral.\n"
                "The collateral is specified through \"collateralHash\" and \"collateralIndex\" and must be an unspent\n"
                "transaction output spendable by this wallet. It must also not be used by any other masternode.\n",
                {
                    {"collateralHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The collateral transaction hash."},
                    {"collateralIndex", RPCArg::Type::NUM, RPCArg::Optional::NO, "The collateral transaction output index."},
                    {"ipAndPort", RPCArg::Type::STR, RPCArg::Optional::NO, "IP and port in the form \"IP:PORT\".\n"
                                        "Must be unique on the network. Can be set to 0, which will require a ProUpServTx afterwards."},
                    {"ownerAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "Before activation, an unused ECDSA owner address distinct from collateral. After activation, the 32-byte public key from protx_generate_owner_key; its private key must be in this wallet."},
                    {"legacyOperatorPubKey", RPCArg::Type::STR, RPCArg::Optional::NO, "Legacy 48-byte operator public key before PQ activation; must be empty after activation. The global SLH-DSA key is registered separately."},
                    {"votingAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "After PQ activation, the nonzero 32-byte SLH voting public key (64 hex characters) from protx_generate_voting_key.\n"
                                        "Before activation, a legacy voting address; an empty string uses ownerAddress.\n"},
                    {"operatorReward", RPCArg::Type::NUM, RPCArg::Optional::NO, "The fraction in %% to share with the operator. The value must be\n"
                                        "between 0.00 and 100.00."},
                    {"payoutAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The Syscoin address to use for masternode reward payments."},
                    {"fundAddress", RPCArg::Type::STR, RPCArg::Default{""}, "If specified wallet will only use coins from this address to fund ProTx.\n"
                                        "If not specified, payoutAddress is the one that is going to be used.\n"
                                        "The private key belonging to this address must be known in your wallet."},
                    {"submit", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "If true, the resulting transaction is sent to the network."},
                },
                RPCResult{RPCResult::Type::STR_HEX, "", "The transaction hash in hex"},
                RPCExamples{
                    HelpExampleCli("protx_register", "<collateral-hash> 0 173.249.49.9:18369 <owner-address> \"\" <voting-address> 5 <payout-address>")
                + HelpExampleRpc("protx_register", "\"<collateral-hash>\", 0, \"173.249.49.9:18369\", \"<owner-address>\", \"\", \"<voting-address>\", 5, \"<payout-address>\"")
                },
        [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<wallet::CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();
    EnsureWalletIsUnlocked(*pwallet);
    
    size_t paramIdx = 0;

    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;

    CProRegTx ptx;
    int current_height;
    {
        LOCK(cs_main);
        current_height = *pwallet->chain().getHeight();
    }

    uint256 collateralHash = ParseHashV(request.params[paramIdx], "collateralHash");
    int32_t collateralIndex = request.params[paramIdx + 1].getInt<int>();
    if (collateralHash.IsNull() || collateralIndex < 0) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid hash or index: %s-%d", collateralHash.ToString(), collateralIndex));
    }
   
    ptx.collateralOutpoint = COutPoint(collateralHash, (uint32_t)collateralIndex);
    paramIdx += 2;
    CTxDestination fundDest;
    { 
        // TODO unlock on failure
        LOCK(pwallet->cs_wallet);
        pwallet->LockCoin(ptx.collateralOutpoint);


        if (request.params[paramIdx].get_str() != "") {
            std::optional<CService> addr = Lookup(request.params[paramIdx].get_str().c_str(), Params().GetDefaultPort(), false);
            if (!addr.has_value()) {
                throw std::runtime_error(strprintf("invalid network address %s", request.params[paramIdx].get_str()));
            }
            ptx.addr = addr.value();
        }

        ConfigureProviderRegistrationForNextBlock(
            ptx, current_height,
            request.params[paramIdx + 2].get_str());
        ConfigureProviderOwnerKey(ptx, request.params[paramIdx + 1].get_str());
        ConfigureProviderVotingKey(ptx, request.params[paramIdx + 3].get_str());

        int64_t operatorReward;
        if (!ParseFixedPoint(request.params[paramIdx + 4].getValStr(), 2, &operatorReward)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "operatorReward must be a number");
        }
        if (operatorReward < 0 || operatorReward > 10000) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "operatorReward must be between 0.00 and 100.00");
        }
        ptx.nOperatorReward = operatorReward;

        CTxDestination payoutDest = DecodeDestination(request.params[paramIdx + 5].get_str());
        if (!IsValidDestination(payoutDest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid payout address: %s", request.params[paramIdx + 5].get_str()));
        }

        ptx.scriptPayout = GetScriptForDestination(payoutDest);

        // make sure fee calculation works
        ptx.vchSig.resize(65);


        fundDest = payoutDest;
        if (!request.params[paramIdx + 6].isNull()) {
            fundDest = DecodeDestination(request.params[paramIdx + 6].get_str());
            if (!IsValidDestination(fundDest))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Syscoin address: ") + request.params[paramIdx + 6].get_str());
        }
    }
    bool fSubmit{true};
    if (!request.params[paramIdx + 7].isNull()) {
        fSubmit = request.params[paramIdx + 7].get_bool();
    }
    FundSpecialTx(*pwallet, tx, ptx, fundDest);
    UpdateSpecialTxInputsHash(tx, ptx);


    // referencing external collateral
    std::map<COutPoint, Coin> coins;
    coins[ptx.collateralOutpoint]; 
    pwallet->chain().findCoins(coins);
    const Coin &coin = coins.at(ptx.collateralOutpoint);
    if(coin.IsSpent()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("collateral not found: %s", ptx.collateralOutpoint.ToStringShort()));
    }
    CTxDestination txDest;
    ExtractDestination(coin.out.scriptPubKey, txDest);
    CKeyID keyID;
    if (auto witness_id = std::get_if<WitnessV0KeyHash>(&txDest)) {	
        keyID = ToKeyID(*witness_id);
    }	
    else if (auto key_id = std::get_if<PKHash>(&txDest)) {	
        keyID = ToKeyID(*key_id);
    }	
    if (keyID.IsNull()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("collateral type not supported: %s", ptx.collateralOutpoint.ToStringShort()));
    }

    // lets prove we own the collateral
    UpdateSpecialTxInputsHash(tx, ptx);
    ptx.vchSig.clear();
    SignProviderOwnerProof(*pwallet, ptx);
    std::string signature_b64;
    const SigningResult collateral_sign_result = pwallet->SignMessage(ptx.MakeSignString(), txDest, signature_b64);
    if (collateral_sign_result == SigningResult::PRIVATE_KEY_NOT_AVAILABLE) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("collateral key not in wallet: %s", EncodeDestination(txDest)));
    }
    if (collateral_sign_result != SigningResult::OK) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, strprintf("failed to sign collateral proof: %s", SigningResultString(collateral_sign_result)));
    }
    auto signature_raw = DecodeBase64(signature_b64);
    if (!signature_raw) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "failed to decode collateral signature");
    }
    ptx.vchSig = *signature_raw;
    SetTxPayload(tx, ptx);
    return SignAndSendSpecialTx(request, *pwallet, tx, fSubmit);
},
    };
}
    
// SYSCOIN: funded provider registration is serialized for the next block's era.
static RPCHelpMan protx_register_fund()
{
        return RPCHelpMan{"protx_register_fund",
                "\nCreates, funds and sends a ProTx to the network. The resulting transaction will move 100000 Syscoin\n"
                "to the address specified by collateralAddress and will then function as the collateral of your\n"
                "masternode.\n",
                {
                    {"collateralAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The Syscoin address to send the collateral to."},
                    {"ipAndPort", RPCArg::Type::STR, RPCArg::Optional::NO, "IP and port in the form \"IP:PORT\".\n"
                                        "Must be unique on the network. Can be set to 0, which will require a ProUpServTx afterwards."},
                    {"ownerAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "Before activation, an unused ECDSA owner address distinct from collateral. After activation, the 32-byte public key from protx_generate_owner_key; its private key must be in this wallet."},
                    {"legacyOperatorPubKey", RPCArg::Type::STR, RPCArg::Optional::NO, "Legacy 48-byte operator public key before PQ activation; must be empty after activation. Register the global SLH-DSA key separately."},
                    {"votingAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "After PQ activation, the nonzero 32-byte SLH voting public key (64 hex characters) from protx_generate_voting_key.\n"
                                        "Before activation, a legacy voting address; an empty string uses ownerAddress.\n"},
                    {"operatorReward", RPCArg::Type::NUM, RPCArg::Optional::NO, "The fraction in %% to share with the operator. The value must be\n"
                                        "between 0.00 and 100.00."},
                    {"payoutAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The Syscoin address to use for masternode reward payments."},
                    {"fundAddress", RPCArg::Type::STR, RPCArg::Default{""}, "If specified wallet will only use coins from this address to fund ProTx.\n"
                                        "If not specified, payoutAddress is the one that is going to be used.\n"
                                        "The private key belonging to this address must be known in your wallet."},
                    {"submit", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "If true, the resulting transaction is sent to the network."},
                },
                RPCResult{RPCResult::Type::STR_HEX, "", "The transaction hash in hex"},
                RPCExamples{
                    HelpExampleCli("protx_register_fund", "<collateral-address> 173.249.49.9:18369 <owner-address> \"\" <voting-address> 5 <payout-address>")
            + HelpExampleRpc("protx_register_fund", "\"<collateral-address>\", \"173.249.49.9:18369\", \"<owner-address>\", \"\", \"<voting-address>\", 5, \"<payout-address>\"")
                },
        [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<wallet::CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();
    EnsureWalletIsUnlocked(*pwallet);
    
    size_t paramIdx = 0;


    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;
    int current_height;
    {
        LOCK(cs_main);
        current_height = *pwallet->chain().getHeight();
    }
    CProRegTx ptx;


    CTxDestination collateralDest = DecodeDestination(request.params[paramIdx].get_str());
    if (!IsValidDestination(collateralDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid collaterall address: %s", request.params[paramIdx].get_str()));
    }
    CScript collateralScript = GetScriptForDestination(collateralDest);

    CTxOut collateralTxOut(nMNCollateralRequired, collateralScript);
    tx.vout.emplace_back(collateralTxOut);

    paramIdx++;


    if (request.params[paramIdx].get_str() != "") {
        std::optional<CService> addr = Lookup(request.params[paramIdx].get_str().c_str(), Params().GetDefaultPort(), false);
        if (!addr.has_value()) {
            throw std::runtime_error(strprintf("invalid network address %s", request.params[paramIdx].get_str()));
        }
        ptx.addr = addr.value();
    }

    ConfigureProviderRegistrationForNextBlock(
        ptx, current_height,
        request.params[paramIdx + 2].get_str());
    ConfigureProviderOwnerKey(ptx, request.params[paramIdx + 1].get_str());
    ConfigureProviderVotingKey(ptx, request.params[paramIdx + 3].get_str());

    int64_t operatorReward;
    if (!ParseFixedPoint(request.params[paramIdx + 4].getValStr(), 2, &operatorReward)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "operatorReward must be a number");
    }
    if (operatorReward < 0 || operatorReward > 10000) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "operatorReward must be between 0.00 and 100.00");
    }
    ptx.nOperatorReward = operatorReward;

    CTxDestination payoutDest = DecodeDestination(request.params[paramIdx + 5].get_str());
    if (!IsValidDestination(payoutDest)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid payout address: %s", request.params[paramIdx + 5].get_str()));
    }

    ptx.scriptPayout = GetScriptForDestination(payoutDest);


    CTxDestination fundDest = payoutDest;
    if (!request.params[paramIdx + 6].isNull()) {
        fundDest = DecodeDestination(request.params[paramIdx + 6].get_str());
        if (!IsValidDestination(fundDest))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Syscoin address: ") + request.params[paramIdx + 6].get_str());
    }

    FundSpecialTx(*pwallet, tx, ptx, fundDest);
    UpdateSpecialTxInputsHash(tx, ptx);

    bool fSubmit{true};
    if (!request.params[paramIdx + 7].isNull()) {
        fSubmit = request.params[paramIdx + 7].get_bool();
    }

    uint32_t collateralIndex = (uint32_t) -1;
    for (uint32_t i = 0; i < tx.vout.size(); i++) {
        if (tx.vout[i].nValue == nMNCollateralRequired) {
            collateralIndex = i;
            break;
        }
    }
    CHECK_NONFATAL(collateralIndex != (uint32_t) -1);
    ptx.collateralOutpoint.n = collateralIndex;
    SignProviderOwnerProof(*pwallet, ptx);

    SetTxPayload(tx, ptx);
    UniValue res = SignAndSendSpecialTx(request, *pwallet, tx, fSubmit);
    if(fSubmit) {
        uint256 txid = ParseHashV(res,"txhash");
        LOCK(pwallet->cs_wallet);
        pwallet->LockCoin(COutPoint(txid, ptx.collateralOutpoint.n));
    }
    return res;
},
    };
}
// SYSCOIN: prepared provider registration is serialized for the next block's era.
static RPCHelpMan protx_register_prepare()
{
    return RPCHelpMan{"protx_register_prepare",
            "\nCreates an unsigned ProTx and returns it. The ProTx must be signed externally with the collateral\n"
            "key and then passed to \"protx_register_submit\". The prepared transaction will also contain inputs\n"
            "and outputs to cover fees.\n",
            {
                {"collateralHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The collateral transaction hash."},
                {"collateralIndex", RPCArg::Type::NUM, RPCArg::Optional::NO, "The collateral transaction output index."},
                {"ipAndPort", RPCArg::Type::STR, RPCArg::Optional::NO, "IP and port in the form \"IP:PORT\".\n"
                                    "Must be unique on the network. Can be set to 0, which will require a ProUpServTx afterwards."},
                {"ownerAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "Before activation, an unused ECDSA owner address distinct from collateral. After activation, the 32-byte public key from protx_generate_owner_key; its private key must be in this wallet."},
                {"legacyOperatorPubKey", RPCArg::Type::STR, RPCArg::Optional::NO, "Legacy 48-byte operator public key before PQ activation; must be empty after activation. Register the global SLH-DSA key separately."},
                {"votingAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "After PQ activation, the nonzero 32-byte SLH voting public key (64 hex characters) from protx_generate_voting_key.\n"
                                    "Before activation, a legacy voting address; an empty string uses ownerAddress.\n"},
                {"operatorReward", RPCArg::Type::NUM, RPCArg::Optional::NO, "The fraction in %% to share with the operator. The value must be\n"
                                    "between 0.00 and 100.00."},
                {"payoutAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The Syscoin address to use for masternode reward payments."},
                {"fundAddress", RPCArg::Type::STR, RPCArg::Default{""}, "If specified wallet will only use coins from this address to fund ProTx.\n"
                                    "If not specified, payoutAddress is the one that is going to be used.\n"
                                    "The private key belonging to this address must be known in your wallet."},
            },
            RPCResult{RPCResult::Type::ANY, "", "Unsigned ProTX transaction object"},
            RPCExamples{
                HelpExampleCli("protx_register_prepare", "<collateral-hash> 0 173.249.49.9:18369 <owner-address> \"\" <voting-address> 5 <payout-address>")
            + HelpExampleRpc("protx_register_prepare", "\"<collateral-hash>\", 0, \"173.249.49.9:18369\", \"<owner-address>\", \"\", \"<voting-address>\", 5, \"<payout-address>\"")
            },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<wallet::CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;
    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();

    size_t paramIdx = 0;

    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_MN_REGISTER;
    int current_height;
    {
        LOCK(cs_main);
        current_height = *pwallet->chain().getHeight();
    }
    CProRegTx ptx;

    uint256 collateralHash = ParseHashV(request.params[paramIdx], "collateralHash");
    int32_t collateralIndex = request.params[paramIdx + 1].getInt<int>();
    if (collateralHash.IsNull() || collateralIndex < 0) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid hash or index: %s-%d", collateralHash.ToString(), collateralIndex));
    }

    ptx.collateralOutpoint = COutPoint(collateralHash, (uint32_t)collateralIndex);
    paramIdx += 2;
    CTxDestination fundDest;
    {
        // TODO unlock on failure
        LOCK(pwallet->cs_wallet);
        pwallet->LockCoin(ptx.collateralOutpoint);
        

        if (request.params[paramIdx].get_str() != "") {
            std::optional<CService> addr = Lookup(request.params[paramIdx].get_str().c_str(), Params().GetDefaultPort(), false);
            if (!addr.has_value()) {
                throw std::runtime_error(strprintf("invalid network address %s", request.params[paramIdx].get_str()));
            }
            ptx.addr = addr.value();
        }

        ConfigureProviderRegistrationForNextBlock(
            ptx, current_height,
            request.params[paramIdx + 2].get_str());
        ConfigureProviderOwnerKey(ptx, request.params[paramIdx + 1].get_str());
        ConfigureProviderVotingKey(ptx, request.params[paramIdx + 3].get_str());

        int64_t operatorReward;
        if (!ParseFixedPoint(request.params[paramIdx + 4].getValStr(), 2, &operatorReward)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "operatorReward must be a number");
        }
        if (operatorReward < 0 || operatorReward > 10000) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "operatorReward must be between 0.00 and 100.00");
        }
        ptx.nOperatorReward = operatorReward;

        CTxDestination payoutDest = DecodeDestination(request.params[paramIdx + 5].get_str());
        if (!IsValidDestination(payoutDest)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid payout address: %s", request.params[paramIdx + 5].get_str()));
        }

        ptx.scriptPayout = GetScriptForDestination(payoutDest);


        // make sure fee calculation works
        ptx.vchSig.resize(65);
        

        fundDest = payoutDest;
        if (!request.params[paramIdx + 6].isNull()) {
            fundDest = DecodeDestination(request.params[paramIdx + 6].get_str());
            if (!IsValidDestination(fundDest))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Syscoin address: ") + request.params[paramIdx + 6].get_str());
        }
    }
    FundSpecialTx(*pwallet, tx, ptx, fundDest);
    UpdateSpecialTxInputsHash(tx, ptx);

    // referencing external collateral
    std::map<COutPoint, Coin> coins;
    coins[ptx.collateralOutpoint]; 
    pwallet->chain().findCoins(coins);
    const Coin &coin = coins.at(ptx.collateralOutpoint);
    if(coin.IsSpent()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("collateral not found: %s", ptx.collateralOutpoint.ToStringShort()));
    }
    CTxDestination txDest;
    ExtractDestination(coin.out.scriptPubKey, txDest);
    CKeyID keyID;
    if (auto witness_id = std::get_if<WitnessV0KeyHash>(&txDest)) {	
        keyID = ToKeyID(*witness_id);
    }	
    else if (auto key_id = std::get_if<PKHash>(&txDest)) {	
        keyID = ToKeyID(*key_id);
    }	
    if (keyID.IsNull()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("collateral type not supported: %s", ptx.collateralOutpoint.ToStringShort()));
    }
    // external signing with collateral key
    ptx.vchSig.clear();
    SignProviderOwnerProof(*pwallet, ptx);
    SetTxPayload(tx, ptx);
    

    UniValue ret(UniValue::VOBJ);
    ret.pushKV("tx", EncodeHexTx(CTransaction(tx)));
    ret.pushKV("collateralAddress", EncodeDestination(txDest));
    ret.pushKV("signMessage", ptx.MakeSignString());
    return ret;
},
    };
}

// SYSCOIN: submit only canonical PQ provider registrations.
static RPCHelpMan protx_register_submit()
{
   return RPCHelpMan{"protx_register_submit",
            "\nSubmits the specified ProTx to the network. This command will also sign the inputs of the transaction\n"
            "which were previously added by \"protx_register_prepare\" to cover transaction fees\n"
            "and outputs to cover fees.\n",
            {
                {"tx", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The serialized transaction previously returned by \"protx_register_prepare\"."},
                {"sig", RPCArg::Type::STR, RPCArg::Optional::NO, "The signature signed with the collateral key. Must be in base64 format."},
            },
            RPCResult{RPCResult::Type::STR_HEX, "", "The transaction hash in hex"},
            RPCExamples{
                HelpExampleCli("protx_register_submit", "")
            + HelpExampleRpc("protx_register_submit", "")
            },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<wallet::CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    EnsureWalletIsUnlocked(*pwallet);
    CMutableTransaction tx;
    if (!DecodeHexTx(tx, request.params[0].get_str())) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "transaction not deserializable");
    }
    if (tx.nVersion != SYSCOIN_TX_VERSION_MN_REGISTER) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "transaction not a ProRegTx");
    }
    CProRegTx ptx;
    if (!GetTxPayload(tx, ptx)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "transaction payload not deserializable");
    }
    if (!ptx.vchSig.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "payload signature not empty");
    }

    ptx.vchSig = *DecodeBase64(request.params[1].get_str().c_str());

    SetTxPayload(tx, ptx);
    {
        LOCK(pwallet->cs_wallet);
        pwallet->LockCoin(COutPoint(tx.GetHash(), ptx.collateralOutpoint.n));
    }
    return SignAndSendSpecialTx(request, *pwallet, tx);
},
    };
}

// SYSCOIN: public, network-bound registration requests keep provider secrets
// and owner secrets in their respective wallets. A request is never broadcast.
struct CheckedOperatorRegistration {
    CMutableTransaction tx;
    llmq::pq::GlobalKeyTxPayload payload;
    CDeterministicMNCPtr dmn;
};

static constexpr std::string_view OPERATOR_REQUEST_CONTEXT{"SYS_PQ_OPERATOR_REQUEST_V1"};

static uint256 GetOperatorRegistrationRequestHash(const CMutableTransaction& tx)
{
    return (CHashWriter{SER_GETHASH, PROTOCOL_VERSION}
            << std::string{OPERATOR_REQUEST_CONTEXT}
            << Params().GetConsensus().hashGenesisBlock << tx).GetHash();
}

static std::string MakeOperatorRegistrationRequest(
    const CMutableTransaction& tx, const slhdsa::SecretKey& operator_key)
{
    // Fee funding may have left signatures for an earlier payload. The handoff
    // authenticates an exact unsigned template, including change and fees.
    CMutableTransaction unsigned_tx{tx};
    for (auto& input : unsigned_tx.vin) {
        input.scriptSig.clear();
        input.scriptWitness.SetNull();
    }
    const uint256 digest{GetOperatorRegistrationRequestHash(unsigned_tx)};
    const std::span<const uint8_t> context{
        reinterpret_cast<const uint8_t*>(OPERATOR_REQUEST_CONTEXT.data()), OPERATOR_REQUEST_CONTEXT.size()};
    slhdsa::Signature seal{};
    if (!slhdsa::SignDeterministic(operator_key, std::span{digest.begin(), digest.size()}, context, seal)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Unable to authenticate operator registration request");
    }
    CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
    stream << std::string{OPERATOR_REQUEST_CONTEXT}
           << Params().GetConsensus().hashGenesisBlock << unsigned_tx << seal;
    return HexStr(stream);
}

static CheckedOperatorRegistration CheckOperatorRegistrationRequest(
    node::NodeContext& node, const std::string& request_hex)
{
    CheckedOperatorRegistration result;
    // Bound allocation before decoding externally supplied data.
    if (request_hex.size() > 262144 || !IsHex(request_hex)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid operator registration request encoding");
    }
    try {
        CDataStream stream{ParseHex(request_hex), SER_NETWORK, PROTOCOL_VERSION};
        std::string domain;
        uint256 genesis;
        slhdsa::Signature seal{};
        stream >> domain >> genesis >> result.tx >> seal;
        if (!stream.empty() || domain != OPERATOR_REQUEST_CONTEXT ||
            genesis != Params().GetConsensus().hashGenesisBlock ||
            result.tx.nVersion != llmq::pq::PQ_GLOBAL_KEY_TX_VERSION || result.tx.vin.empty()) {
            throw std::runtime_error("wrong network, version, or transaction");
        }
        std::vector<unsigned char> data;
        int output_index;
        if (!GetSyscoinData(CTransaction{result.tx}, data, output_index) ||
            !llmq::pq::DecodeGlobalKeyTxPayload(data, result.payload) ||
            result.payload.operation != llmq::pq::GlobalKeyOperation::INITIAL ||
            result.payload.transaction_inputs_hash != CalcTxInputsHash(CTransaction{result.tx})) {
            throw std::runtime_error("invalid registration payload or funding inputs");
        }
        CScript canonical_payload;
        canonical_payload << OP_RETURN << data;
        for (size_t i = 0; i < result.tx.vout.size(); ++i) {
            const auto& output{result.tx.vout[i]};
            if (i == static_cast<size_t>(output_index)) {
                if (output.nValue != 0 || output.scriptPubKey != canonical_payload) {
                    throw std::runtime_error("noncanonical registration output");
                }
            } else if (output.scriptPubKey.IsUnspendable()) {
                throw std::runtime_error("unexpected additional data output");
            }
        }
        for (const auto& input : result.tx.vin) {
            if (!input.scriptSig.empty() || !input.scriptWitness.IsNull()) {
                throw std::runtime_error("operator request fee inputs must be unsigned");
            }
        }
        const uint256 digest{GetOperatorRegistrationRequestHash(result.tx)};
        const std::span<const uint8_t> context{
            reinterpret_cast<const uint8_t*>(OPERATOR_REQUEST_CONTEXT.data()), OPERATOR_REQUEST_CONTEXT.size()};
        if (!slhdsa::Verify(result.payload.candidate.public_key,
                std::span{digest.begin(), digest.size()}, context, seal)) {
            throw std::runtime_error("invalid operator request authentication");
        }
    } catch (const std::exception& error) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           std::string{"Invalid operator registration request: "} + error.what());
    }
    auto& payload{result.payload};
    llmq::pq::OperatorKeyState operator_state;
    std::optional<llmq::pq::OperatorKeyScheduleView> schedule;
    {
        LOCK(cs_main);
        const CBlockIndex* tip{node.chainman->ActiveTip()};
        if (!tip) throw JSONRPCError(RPC_INTERNAL_ERROR, "Active chain tip is unavailable");
        EnsurePQPreparationRPCActive(tip->nHeight);
        result.dmn = deterministicMNManager->GetListForBlock(tip).GetMN(payload.pro_tx_hash);
        if (!result.dmn) throw JSONRPCError(RPC_INVALID_PARAMETER, "Masternode not found at active tip");
        const auto& owner{result.dmn->pdmnState->pqOwnerKey};
        if (owner.HasActiveKey()) {
            if (payload.version != llmq::pq::PQ_GLOBAL_KEY_PQ_OWNER_PAYLOAD_VERSION ||
                payload.owner_key_version != owner.key_version) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Operator request has stale owner authority");
            }
        } else if (payload.version != llmq::pq::PQ_GLOBAL_KEY_PAYLOAD_VERSION) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Operator request has stale owner authority");
        }
        llmq::pq::PQRegistryReadView snapshot;
        std::string error;
        if (!deterministicMNManager->GetPQRegistryReadView(tip, snapshot, error)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Unable to read PQ registry snapshot: " + error);
        }
        const auto key_owner{snapshot.FindRetainedGlobalKeyOwner(payload.candidate.public_key)};
        if (key_owner && *key_owner != payload.pro_tx_hash) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Operator key belongs to another masternode");
        }
        if (const auto* current{snapshot.FindOperator(payload.pro_tx_hash)}) {
            operator_state = *current;
        } else {
            operator_state.pro_tx_hash = payload.pro_tx_hash;
        }
        llmq::pq::PQRegistryConfig config;
        if (llmq::pq::GetPQRegistryConfig(Params().GetConsensus(), config) !=
            llmq::pq::PQRegistryDeploymentResult::VALID) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "PQ registry configuration is invalid");
        }
        schedule = llmq::pq::DeriveOperatorKeyScheduleView(config.schedule,
            tip->nHeight + 1, config.registration_cutoff_blocks, config.future_horizon_epochs);
    }
    // Reuse the consensus state machine, including recovery delay and cutoff,
    // on a copy. The owner's signature is deliberately checked separately.
    if (!schedule || operator_state.Advance(*schedule) != llmq::pq::OperatorKeyStateResult::OK ||
        operator_state.ApplyInitialGlobalKey(*schedule, Params().GetConsensus().hashGenesisBlock,
            payload.candidate, payload.transaction_inputs_hash, payload.authorization,
            /*owner_authorization_verified=*/true) != llmq::pq::OperatorKeyStateResult::OK) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Operator registration proof or schedule is invalid; prepare a new request");
    }
    // Only unsigned requests belong in this handoff. Reject signatures carried
    // inside the envelope so each owner signs the same canonical template.
    llmq::pq::CompactECDSAOwnerSignature compact{};
    llmq::pq::GlobalSignature pq{};
    if (result.dmn->pdmnState->pqOwnerKey.HasActiveKey()) {
        pq.front() = 1;
    } else {
        compact[0] = 27;
        compact[32] = 1;
        compact[64] = 1;
    }
    if (payload.owner_authorization != compact || payload.pq_owner_authorization != pq) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Operator request contains a noncanonical owner placeholder");
    }
    return result;
}

static UniValue DescribeOperatorRegistration(const CheckedOperatorRegistration& registration)
{
    const auto& payload{registration.payload};
    const auto& state{*registration.dmn->pdmnState};
    const bool pq{state.pqOwnerKey.HasActiveKey()};
    UniValue result{UniValue::VOBJ};
    result.pushKV("proTxHash", payload.pro_tx_hash.ToString());
    result.pushKV("genesisHash", Params().GetConsensus().hashGenesisBlock.ToString());
    result.pushKV("ownerType", pq ? "slh-dsa" : "ecdsa");
    result.pushKV("ownerKeyVersion", state.pqOwnerKey.key_version);
    if (pq) result.pushKV("ownerPublicKey", HexStr(state.pqOwnerKey.public_key));
    else result.pushKV("ownerAddress", EncodeDestination(WitnessV0KeyHash(state.keyIDOwner)));
    result.pushKV("operatorPublicKey", HexStr(payload.candidate.public_key));
    result.pushKV("operatorKeyVersion", payload.candidate.key_version);
    result.pushKV("chainlockRoot", payload.candidate.child_key_commitment.root.ToString());
    result.pushKV("treeGeneration", payload.candidate.child_key_commitment.generation);
    result.pushKV("firstEpoch", payload.candidate.child_key_commitment.first_epoch);
    result.pushKV("inputsHash", payload.transaction_inputs_hash.ToString());
    return result;
}

static RPCHelpMan protx_decode_operator_request()
{
    return RPCHelpMan{"protx_decode_operator_request",
        "\nValidates a provider request and displays its public registration details without signing.\n",
        {{"request", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Request hex from protx_register_operator_prepare."}},
        RPCResult{RPCResult::Type::ANY, "", "Validated public registration details"},
        RPCExamples{HelpExampleCli("protx_decode_operator_request", "<request>")},
        [](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            auto wallet{GetWalletForJSONRPCRequest(request)};
            if (!wallet) return NullUniValue;
            wallet->BlockUntilSyncedToCurrentChain();
            return DescribeOperatorRegistration(CheckOperatorRegistrationRequest(
                GetWalletNodeContext(*wallet), request.params[0].get_str()));
        }};
}

static RPCHelpMan protx_register_operator_sign()
{
    return RPCHelpMan{"protx_register_operator_sign",
        "\nAuthorizes a provider request with this wallet's current owner key. Does not sign fee inputs or broadcast. Inspect it first with protx_decode_operator_request.\n",
        {{"request", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Request hex from the provider."}},
        RPCResult{RPCResult::Type::STR_HEX, "", "Owner authorization hex to return to the provider"},
        RPCExamples{HelpExampleCli("protx_register_operator_sign", "<request>")},
        [](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            auto wallet{GetWalletForJSONRPCRequest(request)};
            if (!wallet) return NullUniValue;
            EnsureWalletIsUnlocked(*wallet);
            wallet->BlockUntilSyncedToCurrentChain();
            const auto registration{CheckOperatorRegistrationRequest(
                GetWalletNodeContext(*wallet), request.params[0].get_str())};
            const auto digest{llmq::pq::GetGlobalOwnerRegistrationAuthorizationHash(
                Params().GetConsensus().hashGenesisBlock, registration.payload)};
            if (!digest) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid owner authorization transcript");
            const auto& state{*registration.dmn->pdmnState};
            if (state.pqOwnerKey.HasActiveKey()) {
                slhdsa::Signature signature{};
                std::string error;
                if (!wallet->SignOwnerAuthorization(state.pqOwnerKey.public_key, *digest,
                        llmq::pq::PQ_GLOBAL_OWNER_REGISTER_CONTEXT, signature, error)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, error);
                }
                return HexStr(signature);
            }
            CKey key;
            std::vector<unsigned char> signature;
            if (!wallet->GetKey(state.keyIDOwner, key)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "The masternode owner key is not in this wallet");
            }
            if (!CHashSigner::SignHash(*digest, key, signature)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Failed to sign operator owner authorization");
            }
            return HexStr(signature);
        }};
}

static RPCHelpMan protx_register_operator_submit()
{
    return RPCHelpMan{"protx_register_operator_submit",
        "\nChecks the customer's owner authorization, signs provider fee inputs, and submits the prepared operator registration.\n",
        {{"request", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Original prepared request hex."},
         {"signature", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Authorization returned by protx_register_operator_sign."},
         {"submit", RPCArg::Type::BOOL, RPCArg::Default{true}, "Broadcast, or return the completed transaction hex."}},
        RPCResult{RPCResult::Type::STR_HEX, "", "Transaction hash or signed transaction hex"},
        RPCExamples{HelpExampleCli("protx_register_operator_submit", "<request> <signature>")},
        [](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            auto wallet{GetWalletForJSONRPCRequest(request)};
            if (!wallet) return NullUniValue;
            EnsureWalletIsUnlocked(*wallet);
            wallet->BlockUntilSyncedToCurrentChain();
            auto& node{GetWalletNodeContext(*wallet)};
            const auto request_hex{request.params[0].get_str()};
            auto registration{CheckOperatorRegistrationRequest(node, request_hex)};
            {
                LOCK(wallet->cs_wallet);
                for (const auto& output : registration.tx.vout) {
                    if (!output.scriptPubKey.IsUnspendable() &&
                        !(wallet->IsMine(output.scriptPubKey) & ISMINE_SPENDABLE)) {
                        throw JSONRPCError(RPC_WALLET_ERROR,
                            "Operator registration change must belong to the submitting wallet");
                    }
                }
            }
            const auto& encoded{request.params[1].get_str()};
            const bool pq{registration.dmn->pdmnState->pqOwnerKey.HasActiveKey()};
            const size_t expected{pq ? slhdsa::SIGNATURE_SIZE : llmq::pq::COMPACT_ECDSA_SIGNATURE_SIZE};
            if (encoded.size() != expected * 2 || !IsHex(encoded)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Wrong owner authorization size or encoding");
            }
            const auto signature{ParseHex(encoded)};
            if (pq) std::copy(signature.begin(), signature.end(), registration.payload.pq_owner_authorization.begin());
            else std::copy(signature.begin(), signature.end(), registration.payload.owner_authorization.begin());
            const auto& state{*registration.dmn->pdmnState};
            const bool valid{pq
                ? llmq::pq::VerifyGlobalOwnerRegistrationAuthorization(Params().GetConsensus().hashGenesisBlock,
                    registration.payload, state.keyIDOwner, state.pqOwnerKey)
                : llmq::pq::VerifyGlobalOwnerRegistrationAuthorization(Params().GetConsensus().hashGenesisBlock,
                    registration.payload, state.keyIDOwner)};
            if (!valid) throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid owner authorization");
            SetTxPayload(registration.tx, registration.payload);
            const bool submit{request.params[2].isNull() || request.params[2].get_bool()};
            return SignAndSendSpecialTx(request, *wallet, registration.tx, submit, [&]() {
                // Wallet input signing may span an owner rotation or epoch cutoff.
                const auto current{CheckOperatorRegistrationRequest(node, request_hex)};
                if (current.dmn->pdmnState->pqOwnerKey != state.pqOwnerKey ||
                    current.dmn->pdmnState->keyIDOwner != state.keyIDOwner) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Operator request has stale owner authority");
                }
            }, /*check_fee_cap=*/true);
        }};
}

// SYSCOIN: one-time bootstrap/recovery of the global operator key and child root.
static RPCHelpMan MakeRegisterOperatorRPC(bool prepare_only)
{
    std::vector<RPCArg> args{
        {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
         "The deterministic masternode ProRegTx hash."},
        {"operatorKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
         "The exactly 64-byte SLH-DSA-SHAKE-128s secret key. Avoid exposing this argument through shell history."},
        {"chainlockSeed", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
         "The independent nonzero 32-byte ChainLock seed. It deterministically commits 65,536 epoch keys and is never placed on-chain."},
        {"feeSourceAddress", RPCArg::Type::STR, RPCArg::Default{""},
         "Funded address in this wallet; defaults to the masternode payout address. A separate provider wallet normally needs its own fee address here."},
    };
    if (!prepare_only) {
        args.emplace_back("submit", RPCArg::Type::BOOL, RPCArg::Default{true},
                          "Broadcast when true; otherwise return the signed transaction hex.");
    }
    return RPCHelpMan{
        prepare_only ? "protx_register_operator_prepare" : "protx_register_operator_key",
        prepare_only
            ? "\nPrepares and funds a PQ operator registration using only provider secrets. Send the returned request to the owner for protx_register_operator_sign, then use protx_register_operator_submit. No owner private key is needed here.\n"
            : "\nRegisters or recovers the SLH operator key using the current ECDSA or PQ owner authorization. For separate provider/owner wallets use protx_register_operator_prepare/sign/submit.\n",
        std::move(args),
        RPCResult{RPCResult::Type::ANY, "", "Transaction hash, signed transaction hex, or prepared request with public details"},
        RPCExamples{HelpExampleCli(
            prepare_only ? "protx_register_operator_prepare" : "protx_register_operator_key",
            "<proTxHash> <64-byte-secret-key> <32-byte-chainlock-seed> <provider-fee-address>")},
        [prepare_only](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            auto pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return NullUniValue;
            EnsureWalletIsUnlocked(*pwallet);
            pwallet->BlockUntilSyncedToCurrentChain();

            node::NodeContext& node = GetWalletNodeContext(*pwallet);
            const uint256 pro_tx_hash = ParseHashV(request.params[0], "proTxHash");
            auto operator_key = ParseSLHSecretKey(request.params[1].get_str(),
                                                  "operatorKey");
            llmq::pq::ChainLockMasterSeed chainlock_seed{};
            ParseChainLockMasterSeed(request.params[2].get_str(),
                                     chainlock_seed);
            const SensitiveChainLockSeedGuard chainlock_seed_guard{
                chainlock_seed};

            CDeterministicMNCPtr dmn;
            uint32_t key_version{1};
            uint32_t tree_generation{1};
            std::optional<llmq::pq::GlobalKeyRecord> previous_key;
            {
                LOCK(cs_main);
                const CBlockIndex* tip = node.chainman->ActiveTip();
                if (tip == nullptr) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                                       "Active chain tip is unavailable");
                }
                EnsurePQPreparationRPCActive(tip->nHeight);
                dmn = deterministicMNManager->GetListForBlock(tip).GetMN(pro_tx_hash);
                if (!dmn) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       "Masternode not found at active tip");
                }

                llmq::pq::PQRegistryReadView snapshot;
                std::string registry_error;
                if (!deterministicMNManager->GetPQRegistryReadView(
                        tip, snapshot, registry_error)) {
                    throw JSONRPCError(
                        RPC_INTERNAL_ERROR,
                        "Unable to read PQ registry snapshot: " + registry_error);
                }
                if (const auto* state = snapshot.FindOperator(pro_tx_hash)) {
                    if (state->HasActiveGlobalKey()) {
                        throw JSONRPCError(
                            RPC_INVALID_PARAMETER,
                            "An active global key already exists; use the rotation transaction path");
                    }
                    if (state->has_global_key != 0) {
                        if (state->global_key.key_version ==
                            std::numeric_limits<uint32_t>::max()) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER,
                                               "Global key version is exhausted");
                        }
                        key_version = state->global_key.key_version + 1;
                        previous_key = state->global_key;
                        // SYSCOIN: recovery advances to a fresh tree generation.
                        if (!llmq::pq::CanAdvanceChildKeyTreeGeneration(
                                state->global_key.child_key_commitment.generation)) {
                            throw JSONRPCError(
                                RPC_INVALID_PARAMETER,
                                "Child-key tree generation is exhausted");
                        }
                        tree_generation =
                            state->global_key.child_key_commitment.generation + 1;
                    }
                }
            }

            const auto child_commitment = BuildCurrentChildKeyTreeCommitment(
                node, chainlock_seed, pro_tx_hash, tree_generation);

            llmq::pq::GlobalKeyTxPayload payload;
            if (dmn->pdmnState->pqOwnerKey.HasActiveKey()) {
                payload.version = llmq::pq::PQ_GLOBAL_KEY_PQ_OWNER_PAYLOAD_VERSION;
                payload.owner_key_version = dmn->pdmnState->pqOwnerKey.key_version;
            }
            payload.operation = llmq::pq::GlobalKeyOperation::INITIAL;
            payload.pro_tx_hash = pro_tx_hash;
            payload.candidate.key_version = key_version;
            if (!operator_key.GetPublicKey(payload.candidate.public_key)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Unable to derive the SLH-DSA public key");
            }
            payload.candidate.child_key_commitment = child_commitment;
            payload.transaction_inputs_hash = uint256::ONEV;
            SignInitialGlobalKeyPayload(
                payload, *pwallet, *dmn->pdmnState, operator_key,
                previous_key ? &*previous_key : nullptr, prepare_only);

            CMutableTransaction tx;
            tx.nVersion = llmq::pq::PQ_GLOBAL_KEY_TX_VERSION;
            CTxDestination fee_source;
            if (!request.params[3].isNull() &&
                !request.params[3].get_str().empty()) {
                fee_source = DecodeDestination(request.params[3].get_str());
                if (!IsValidDestination(fee_source)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                       "Invalid fee source address");
                }
            } else if (!ExtractDestination(dmn->pdmnState->scriptPayout,
                                           fee_source)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Masternode payout script has no usable fee address");
            }
            FundSpecialTx(*pwallet, tx, payload, fee_source);
            payload.transaction_inputs_hash = CalcTxInputsHash(CTransaction(tx));
            SignInitialGlobalKeyPayload(
                payload, *pwallet, *dmn->pdmnState, operator_key,
                previous_key ? &*previous_key : nullptr, prepare_only);
            SetTxPayload(tx, payload);

            if (prepare_only) {
                const auto prepared{MakeOperatorRegistrationRequest(tx, operator_key)};
                auto checked{CheckOperatorRegistrationRequest(node, prepared)};
                UniValue result{DescribeOperatorRegistration(checked)};
                result.pushKV("request", prepared);
                return result;
            }

            const bool submit = request.params[4].isNull() ||
                                request.params[4].get_bool();
            return SignAndSendSpecialTx(request, *pwallet, tx, submit, [&]() {
                EnsureCurrentChildKeyCommitmentSchedule(node, child_commitment);
            });
        },
    };
}

static RPCHelpMan protx_register_operator_key() { return MakeRegisterOperatorRPC(false); }
static RPCHelpMan protx_register_operator_prepare() { return MakeRegisterOperatorRPC(true); }

static RPCHelpMan protx_generate_owner_key()
{
    return RPCHelpMan{"protx_generate_owner_key",
        "\nGenerates an independent SLH owner key in this wallet and returns only its public key. Back up the wallet after generation.\n",
        {}, RPCResult{RPCResult::Type::STR_HEX, "", "32-byte SLH owner public key"},
        RPCExamples{HelpExampleCli("protx_generate_owner_key", "")},
        [](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            auto wallet{GetWalletForJSONRPCRequest(request)};
            if (!wallet) return NullUniValue;
            EnsureWalletIsUnlocked(*wallet);
            slhdsa::PublicKey public_key{};
            std::string error;
            if (!wallet->GenerateOwnerKey(public_key, error)) {
                throw JSONRPCError(RPC_WALLET_ERROR, error);
            }
            return HexStr(public_key);
        }};
}

static RPCHelpMan protx_update_owner()
{
    return RPCHelpMan{"protx_update_owner",
        "\nMigrates an existing ECDSA owner to SLH, or rotates its SLH owner key. Requires the current owner key and the new owner private key in this wallet. Optionally enrolls the separate PQ voting key in the same transaction. Preserves payout and operator keys. Available from PQ preparation; active PQ owner and voting keys, plus the operator commitment, are required for rewards at activation.\n",
        {{"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Masternode registration hash."},
         {"ownerPublicKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Public key from protx_generate_owner_key. The existing owner key may be retained when enrolling a missing voting key."},
         {"feeSourceAddress", RPCArg::Type::STR, RPCArg::Default{""}, "Fee source, or empty to use the existing payout address."},
         {"votingPublicKey", RPCArg::Type::STR, RPCArg::Default{""}, "Public key from protx_generate_voting_key in the owner's or delegate's wallet. Empty preserves the current voting key. Before activation only initial voting enrollment is allowed."}},
        RPCResult{RPCResult::Type::STR_HEX, "", "Owner update transaction hash"},
        RPCExamples{HelpExampleCli("protx_update_owner", "<proTxHash> <ownerPublicKey> <feeSourceAddress> <votingPublicKey>")},
        [](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            auto wallet{GetWalletForJSONRPCRequest(request)};
            if (!wallet) return NullUniValue;
            EnsureWalletIsUnlocked(*wallet);
            wallet->BlockUntilSyncedToCurrentChain();
            auto& node{GetWalletNodeContext(*wallet)};
            CProUpRegTx payload;
            payload.nVersion = CProUpRegTx::PQ_VERSION;
            payload.proTxHash = ParseHashV(request.params[0], "proTxHash");
            payload.pqOwnerPublicKey = ParseVotingPublicKey(request.params[1].get_str());
            CDeterministicMNCPtr dmn;
            bool preparation{false};
            {
                LOCK(cs_main);
                const CBlockIndex* tip{node.chainman->ActiveTip()};
                if (!tip) throw JSONRPCError(RPC_INTERNAL_ERROR, "Active chain tip is unavailable");
                EnsurePQPreparationRPCActive(tip->nHeight);
                preparation = Consensus::CheckPQLegacyReplay(
                    Params().GetConsensus(), tip->nHeight + 1) != Consensus::PQLegacyReplayResult::RETIRED;
                dmn = deterministicMNManager->GetListForBlock(tip).GetMN(payload.proTxHash);
            }
            if (!dmn) throw JSONRPCError(RPC_INVALID_PARAMETER, "Masternode not found at active tip");
            const auto& state{*dmn->pdmnState};
            if (!wallet->HasOwnerKey(payload.pqOwnerPublicKey)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "New owner private key is not in this wallet");
            }
            payload.ownerKeyVersion = state.pqOwnerKey.key_version;
            payload.keyIDVoting = state.keyIDVoting;
            payload.pqVotingPublicKey = state.pqVotingKey.public_key;
            if (!request.params[3].isNull() && !request.params[3].get_str().empty()) {
                payload.pqVotingPublicKey = ParseVotingPublicKey(request.params[3].get_str());
                if (preparation && state.pqVotingKey.key_version != 0 &&
                    payload.pqVotingPublicKey != state.pqVotingKey.public_key) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Before activation only initial PQ voting enrollment is allowed");
                }
            }
            if (state.pqOwnerKey.public_key == payload.pqOwnerPublicKey &&
                (state.pqVotingKey.key_version != 0 ||
                 llmq::pq::IsNullVotingPublicKey(payload.pqVotingPublicKey))) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Owner key is already active and no initial voting enrollment was requested");
            }
            payload.scriptPayout = state.scriptPayout;
            payload.vchSig.resize(state.pqOwnerKey.HasActiveKey() ? slhdsa::SIGNATURE_SIZE : 65);
            CTxDestination fee_source;
            if (!request.params[2].isNull() && !request.params[2].get_str().empty()) {
                fee_source = DecodeDestination(request.params[2].get_str());
                if (!IsValidDestination(fee_source)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid fee source address");
                }
            } else if (!ExtractDestination(state.scriptPayout, fee_source)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Masternode payout script has no usable fee address");
            }
            CMutableTransaction tx;
            tx.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR;
            FundSpecialTx(*wallet, tx, payload, fee_source);
            UpdateSpecialTxInputsHash(tx, payload);
            std::string error;
            if (!wallet->SignOwnerAuthorization(payload.pqOwnerPublicKey,
                    GetProUpRegOwnerAuthorizationHash(Params().GetConsensus().hashGenesisBlock, payload),
                    llmq::pq::PQ_OWNER_PROOF_CONTEXT, payload.pqOwnerProof, error)) {
                throw JSONRPCError(RPC_WALLET_ERROR, error);
            }
            SignRegistrarOwner(*wallet, state, payload);
            SetTxPayload(tx, payload);
            return SignAndSendSpecialTx(request, *wallet, tx, true, [&]() {
                LOCK(cs_main);
                const auto* tip{node.chainman->ActiveTip()};
                const auto current{tip ? deterministicMNManager->GetListForBlock(tip).GetMN(payload.proTxHash) : nullptr};
                if (!current || current->pdmnState->pqOwnerKey != state.pqOwnerKey ||
                    current->pdmnState->keyIDOwner != state.keyIDOwner ||
                    current->pdmnState->keyIDVoting != state.keyIDVoting ||
                    current->pdmnState->pqVotingKey != state.pqVotingKey ||
                    current->pdmnState->scriptPayout != state.scriptPayout) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Owner or registrar state changed while signing; retry the update");
                }
            });
        }};
}

static RPCHelpMan protx_generate_voting_key()
{
    return RPCHelpMan{
        "protx_generate_voting_key",
        "\nGenerates an independent reusable SLH-DSA proposal-funding voting key in this wallet.\n"
        "Only its public key is returned. Give it to the masternode owner for registration; the private key stays in the owner's or delegate's wallet.\n"
        "Back up the full wallet with backupwallet after generation. Descriptor exports and earlier backups cannot recover this independent key.\n",
        {},
        RPCResult{RPCResult::Type::STR_HEX, "publicKey", "32-byte SLH-DSA-SHAKE-128s voting public key"},
        RPCExamples{HelpExampleCli("protx_generate_voting_key", "")},
        [&](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            auto wallet{GetWalletForJSONRPCRequest(request)};
            if (!wallet) return NullUniValue;
            EnsureWalletIsUnlocked(*wallet);
            slhdsa::PublicKey public_key;
            std::string error;
            if (!wallet->GenerateVotingKey(public_key, error)) {
                throw JSONRPCError(RPC_WALLET_ERROR, error);
            }
            return HexStr(public_key);
        }};
}

static RPCHelpMan protx_generate_operator_keypair()
{
    return RPCHelpMan{
        "protx_generate_operator_keypair",
        "\nGenerates independent local secrets for PQ masternode operation. Store both securely; this RPC does not persist them.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR_HEX, "operatorKey",
             "Canonical 64-byte global SLH-DSA secret key"},
            {RPCResult::Type::STR_HEX, "chainlockSeed",
             "Independent 32-byte ChainLock child-key master seed"},
        }},
        RPCExamples{HelpExampleCli("protx_generate_operator_keypair", "")},
        [&](const RPCHelpMan&, const node::JSONRPCRequest&) -> UniValue {
            return protx_generate_operator_keys();
        },
    };
}

// SYSCOIN: current-PQ-authorized global operator rotation.
static RPCHelpMan protx_rotate_operator_key()
{
    return RPCHelpMan{
        "protx_rotate_operator_key",
        "\nRotates an active global SLH-DSA operator key. The current key authorizes the exact replacement and transaction inputs.\n",
        {
            {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The deterministic masternode ProRegTx hash."},
            {"currentOperatorKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The current 64-byte SLH-DSA secret key."},
            {"newOperatorKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The replacement 64-byte SLH-DSA secret key."},
            {"feeSourceAddress", RPCArg::Type::STR, RPCArg::Default{""},
             "Wallet address used to fund the transaction; defaults to the masternode payout address."},
            {"submit", RPCArg::Type::BOOL, RPCArg::Default{true},
             "Broadcast when true; otherwise return the signed transaction hex."},
            {"newChainlockSeed", RPCArg::Type::STR, RPCArg::Default{""},
             "Optional independent nonzero 32-byte ChainLock seed for an exceptional child-root rotation. Empty preserves the existing 65,536-epoch commitment; consensus permits at most 15 replacements after generation 1."},
        },
        RPCResult{RPCResult::Type::STR_HEX, "", "Transaction hash or signed transaction hex"},
        RPCExamples{HelpExampleCli(
            "protx_rotate_operator_key", "<proTxHash> <current-key> <new-key>")},
        [&](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            auto pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return NullUniValue;
            EnsureWalletIsUnlocked(*pwallet);
            pwallet->BlockUntilSyncedToCurrentChain();

            node::NodeContext& node = GetWalletNodeContext(*pwallet);
            const uint256 pro_tx_hash = ParseHashV(request.params[0], "proTxHash");
            auto current_key = ParseSLHSecretKey(
                request.params[1].get_str(), "currentOperatorKey");
            auto new_key = ParseSLHSecretKey(
                request.params[2].get_str(), "newOperatorKey");
            llmq::pq::ChainLockMasterSeed replacement_chainlock_seed{};
            const SensitiveChainLockSeedGuard replacement_seed_guard{
                replacement_chainlock_seed};
            const bool rotate_child_root{
                !request.params[5].isNull() &&
                !request.params[5].get_str().empty()};
            if (rotate_child_root) {
                ParseChainLockMasterSeed(request.params[5].get_str(),
                                         replacement_chainlock_seed);
            }

            CDeterministicMNCPtr dmn;
            llmq::pq::OperatorKeyState operator_state;
            uint32_t replacement_tree_generation{0};
            {
                LOCK(cs_main);
                const CBlockIndex* tip = node.chainman->ActiveTip();
                if (tip == nullptr) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                                       "Active chain tip is unavailable");
                }
                EnsurePQPreparationRPCActive(tip->nHeight);
                dmn = deterministicMNManager->GetListForBlock(tip).GetMN(pro_tx_hash);
                if (!dmn) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       "Masternode not found at active tip");
                }
                operator_state = GetActivePQOperator(
                    tip, pro_tx_hash, current_key);
                if (rotate_child_root) {
                    const auto& current_commitment{
                        operator_state.global_key.child_key_commitment};
                    if (!llmq::pq::CanAdvanceChildKeyTreeGeneration(
                            current_commitment.generation)) {
                        throw JSONRPCError(
                            RPC_INVALID_PARAMETER,
                            "Child-key tree generation is exhausted");
                    }
                    replacement_tree_generation =
                        current_commitment.generation + 1;
                }
            }
            if (operator_state.global_key.key_version ==
                std::numeric_limits<uint32_t>::max()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Global key version is exhausted");
            }

            llmq::pq::GlobalKeyTxPayload payload;
            payload.operation = llmq::pq::GlobalKeyOperation::ROTATE;
            payload.pro_tx_hash = pro_tx_hash;
            payload.candidate.key_version =
                operator_state.global_key.key_version + 1;
            if (!new_key.GetPublicKey(payload.candidate.public_key) ||
                payload.candidate.public_key ==
                    operator_state.global_key.public_key) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Replacement global key must be different");
            }
            payload.candidate.child_key_commitment =
                operator_state.global_key.child_key_commitment;
            if (rotate_child_root) {
                payload.candidate.child_key_commitment =
                    BuildCurrentChildKeyTreeCommitment(
                        node,
                        replacement_chainlock_seed,
                        pro_tx_hash,
                        replacement_tree_generation);
                if (payload.candidate.child_key_commitment.root ==
                    operator_state.global_key.child_key_commitment.root) {
                    throw JSONRPCError(
                        RPC_INTERNAL_ERROR,
                        "Replacement child-key root unexpectedly matches the current root");
                }
            }
            payload.transaction_inputs_hash = uint256::ONEV;
            SignGlobalKeyRotationPayload(payload, operator_state.global_key,
                                         current_key);

            CMutableTransaction tx;
            tx.nVersion = llmq::pq::PQ_GLOBAL_KEY_TX_VERSION;
            CTxDestination fee_source;
            if (!request.params[3].isNull() &&
                !request.params[3].get_str().empty()) {
                fee_source = DecodeDestination(request.params[3].get_str());
                if (!IsValidDestination(fee_source)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                                       "Invalid fee source address");
                }
            } else if (!ExtractDestination(dmn->pdmnState->scriptPayout,
                                           fee_source)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Masternode payout script has no usable fee address");
            }
            FundSpecialTx(*pwallet, tx, payload, fee_source);
            payload.transaction_inputs_hash = CalcTxInputsHash(CTransaction(tx));
            SignGlobalKeyRotationPayload(payload, operator_state.global_key,
                                         current_key);
            SetTxPayload(tx, payload);

            const bool submit = request.params[4].isNull() ||
                                request.params[4].get_bool();
            return SignAndSendSpecialTx(request, *pwallet, tx, submit, [&]() {
                if (rotate_child_root) {
                    EnsureCurrentChildKeyCommitmentSchedule(
                        node, payload.candidate.child_key_commitment);
                }
            });
        },
    };
}

static RPCHelpMan protx_recovery_ready()
{
    return RPCHelpMan{
        "protx_recovery_ready",
        "\nDeclares PQ recovery readiness for one four-epoch recovery group. The current operator key signs the fixed branch reference and transaction inputs; this does not rotate keys, revive PoSe, or change payments.\n",
        {
            {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The deterministic masternode ProRegTx hash."},
            {"operatorKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The current 64-byte SLH-DSA operator secret key."},
            {"group", RPCArg::Type::NUM, RPCArg::Optional::NO,
             "Recovery group index q, covering epochs 4q through 4q+3."},
            {"feeSourceAddress", RPCArg::Type::STR, RPCArg::Default{""},
             "Wallet fee address; defaults to the masternode payout address."},
            {"submit", RPCArg::Type::BOOL, RPCArg::Default{true},
             "Broadcast when true; otherwise return signed transaction hex."},
        },
        RPCResult{RPCResult::Type::STR_HEX, "", "Transaction hash or signed transaction hex"},
        RPCExamples{HelpExampleCli("protx_recovery_ready", "<proTxHash> <operator-key> <group>")},
        [&](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
            auto pwallet = GetWalletForJSONRPCRequest(request);
            if (!pwallet) return NullUniValue;
            EnsureWalletIsUnlocked(*pwallet);
            pwallet->BlockUntilSyncedToCurrentChain();
            node::NodeContext& node = GetWalletNodeContext(*pwallet);
            const uint256 pro_tx_hash{ParseHashV(request.params[0], "proTxHash")};
            auto operator_key{ParseSLHSecretKey(request.params[1].get_str(), "operatorKey")};
            const int64_t group{request.params[2].getInt<int64_t>()};
            if (group < 0 || group > std::numeric_limits<uint32_t>::max() / 4) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Recovery group is out of range");
            }

            CDeterministicMNCPtr dmn;
            llmq::pq::OperatorKeyState operator_state;
            llmq::pq::RecoveryReadinessTxPayload payload;
            {
                LOCK(cs_main);
                const CBlockIndex* tip{node.chainman->ActiveTip()};
                if (tip == nullptr) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Active chain tip is unavailable");
                }
                EnsurePQProviderRPCActive(tip->nHeight);
                llmq::pq::PQRegistryConfig config;
                if (llmq::pq::GetPQRegistryConfig(Params().GetConsensus(), config) !=
                    llmq::pq::PQRegistryDeploymentResult::VALID) {
                    throw JSONRPCError(RPC_MISC_ERROR, "PQ registry is not configured");
                }
                const auto coordinates{llmq::pq::DeriveRecoveryRefreshCoordinates(
                    config.schedule, config.btcc_schedule, config.recovery_refresh,
                    static_cast<uint32_t>(group))};
                if (!coordinates || tip->nHeight + 1 < config.recovery_refresh.activation_height ||
                    tip->nHeight < coordinates->readiness_reference_height ||
                    tip->nHeight >= coordinates->snapshot_height) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       "The next block is outside this group's readiness window");
                }
                const CBlockIndex* reference{tip->GetAncestor(coordinates->readiness_reference_height)};
                if (reference == nullptr) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR, "Readiness reference block is unavailable");
                }
                dmn = deterministicMNManager->GetListForBlock(tip).GetMN(pro_tx_hash);
                if (!dmn) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Masternode not found at active tip");
                }
                operator_state = GetActivePQOperator(tip, pro_tx_hash, operator_key);
                payload.readiness.pro_tx_hash = pro_tx_hash;
                payload.readiness.global_key_version = operator_state.global_key.key_version;
                payload.readiness.group = static_cast<uint32_t>(group);
                payload.readiness.reference_height = coordinates->readiness_reference_height;
                payload.readiness.reference_hash = reference->GetBlockHash();
            }
            payload.readiness.transaction_inputs_hash = uint256::ONEV;
            payload.signature[0] = 1;
            CMutableTransaction tx;
            tx.nVersion = llmq::pq::PQ_RECOVERY_READINESS_TX_VERSION;
            CTxDestination fee_source;
            if (!request.params[3].isNull() && !request.params[3].get_str().empty()) {
                fee_source = DecodeDestination(request.params[3].get_str());
                if (!IsValidDestination(fee_source)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid fee source address");
                }
            } else if (!ExtractDestination(dmn->pdmnState->scriptPayout, fee_source)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                                   "Masternode payout script has no usable fee address");
            }
            FundSpecialTx(*pwallet, tx, payload, fee_source);
            payload.readiness.transaction_inputs_hash = CalcTxInputsHash(CTransaction(tx));
            const auto digest{llmq::pq::GetRecoveryReadinessAuthorizationHash(
                Params().GetConsensus().hashGenesisBlock, operator_state.global_key,
                payload.readiness)};
            if (!digest || !slhdsa::SignDeterministic(
                    operator_key, std::span<const uint8_t>{digest->begin(), digest->size()},
                    llmq::pq::GetGlobalAuthContext(llmq::pq::GlobalAuthPurpose::RECOVERY_READINESS),
                    payload.signature)) {
                throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to sign PQ recovery readiness");
            }
            SetTxPayload(tx, payload);
            const bool submit{request.params[4].isNull() || request.params[4].get_bool()};
            return SignAndSendSpecialTx(request, *pwallet, tx, submit, [&]() {
                LOCK(cs_main);
                TxValidationState state;
                if (!deterministicMNManager->CheckPQTransaction(
                        CTransaction(tx), node.chainman->ActiveTip(), state,
                        /*fJustCheck=*/false, /*check_sigs=*/true)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER,
                                       "Readiness declaration is no longer valid: " + state.ToString());
                }
            });
        },
    };
}

// SYSCOIN: provider service updates use the registered global SLH key.
static RPCHelpMan protx_update_service()
{
    return RPCHelpMan{"protx_update_service",
        "\nCreates and sends a ProUpServTx to the network. This will update the IP address\n"
        "of a masternode.\n"
        "If this is done for a masternode that got PoSe-banned, the ProUpServTx will also revive this masternode.\n",
        {
            {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the initial ProRegTx."},
            {"ipAndPort", RPCArg::Type::STR, RPCArg::Optional::NO, "IP and port in the form \"IP:PORT\".\n"
                "Must be unique on the network. Can be set to 0, which will require a ProUpServTx afterwards."},
            {"operatorKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 64-byte SLH-DSA-SHAKE-128s global operator secret key."},
            {"nevmAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The NEVM address to associate with NEVM registry.\n"
                    "If set to an empty string, any existing NEVM registry entry will be removed."},
            {"operatorPayoutAddress", RPCArg::Type::STR, RPCArg::Default{""}, "The address used for operator reward payments.\n"
                "Only allowed when the ProRegTx had a non-zero operatorReward value.\n"
                "If set to an empty string, the currently active payout address is reused."},
            {"feeSourceAddress", RPCArg::Type::STR, RPCArg::Default{""}, "If specified, the wallet will only use coins from this address to fund ProTx.\n"
                "If not specified, payoutAddress is the one that is going to be used.\n"
                "The private key belonging to this address must be known in your wallet."},
        },
        RPCResult{RPCResult::Type::STR_HEX, "", "The transaction hash in hex"},
        RPCExamples{
            HelpExampleCli("protx_update_service", "<proTxHash> 173.249.49.9:18369 <64-byte-slh-secret-hex> <nevm-address> <operator-payout-address>")
            + HelpExampleRpc("protx_update_service", "\"<proTxHash>\", \"173.249.49.9:18369\", \"<64-byte-slh-secret-hex>\", \"<nevm-address>\", \"<operator-payout-address>\"")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<wallet::CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    EnsureWalletIsUnlocked(*pwallet);

    pwallet->BlockUntilSyncedToCurrentChain();

    node::NodeContext& node = GetWalletNodeContext(*pwallet);
    CProUpServTx ptx;
    int current_height;
    {
        LOCK(cs_main);
        current_height = *pwallet->chain().getHeight();
    }
    EnsurePQProviderRPCActive(current_height);
    ptx.nVersion = CProUpServTx::PQ_VERSION;
    ptx.proTxHash = ParseHashV(request.params[0], "proTxHash");
    std::optional<CService> addr = Lookup(request.params[1].get_str().c_str(), Params().GetDefaultPort(), false);
    if (!addr.has_value()) {
        throw std::runtime_error(strprintf("Invalid network address %s", request.params[1].get_str()));
    }
    ptx.addr = addr.value();

    auto keyOperator = ParseSLHSecretKey(request.params[2].get_str(), "operatorKey");
    auto mnList = deterministicMNManager->GetListAtChainTip();
    auto dmn = mnList.GetMN(ptx.proTxHash);
    if (!dmn) {
        throw std::runtime_error(strprintf("Masternode with proTxHash %s not found", ptx.proTxHash.ToString()));
    }
    llmq::pq::OperatorKeyState operator_state;
    {
        LOCK(cs_main);
        operator_state = GetActivePQOperator(
            node.chainman->ActiveTip(), ptx.proTxHash, keyOperator);
    }
    ptx.globalKeyVersion = operator_state.global_key.key_version;

    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE;

    if (!request.params[3].isNull()) {
        std::string nevmAddressStr = request.params[3].get_str();
        if(nevmAddressStr.size() > 0) {
            // Check if the string starts with "0x" and remove it
            if (nevmAddressStr.rfind("0x", 0) == 0) {
                nevmAddressStr = nevmAddressStr.substr(2);
            } else {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid NEVM address (should start with 0x): ") + request.params[3].get_str());
            }
        
            // Ethereum address must be exactly 20 bytes (40 hex characters)
            if (nevmAddressStr.length() != 40 || !IsHex(nevmAddressStr)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid NEVM address (must be 20 bytes / 40 hex chars): ") + request.params[3].get_str());
            }
        
            // Parse the hex address into bytes
            ptx.vchNEVMAddress = ParseHex(nevmAddressStr);
        }
    }
    // param operatorPayoutAddress
    if (!request.params[4].isNull()) {
        if (request.params[4].get_str().empty()) {
            ptx.scriptOperatorPayout = dmn->pdmnState->scriptOperatorPayout;
        } else {
            CTxDestination payoutDest = DecodeDestination(request.params[4].get_str());
            if (!IsValidDestination(payoutDest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid operator payout address: %s", request.params[4].get_str()));
            }
            ptx.scriptOperatorPayout = GetScriptForDestination(payoutDest);
        }
    } else {
        ptx.scriptOperatorPayout = dmn->pdmnState->scriptOperatorPayout;
    }

    CTxDestination feeSource;

    // param feeSourceAddress
    if (!request.params[5].isNull()) {
        feeSource = DecodeDestination(request.params[5].get_str());
        if (!IsValidDestination(feeSource))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Syscoin address: ") + request.params[5].get_str());
    } else {
        if (ptx.scriptOperatorPayout != CScript()) {
            // use operator reward address as default source for fees
            ExtractDestination(ptx.scriptOperatorPayout, feeSource);
        } else {
            // use payout address as default source for fees
            ExtractDestination(dmn->pdmnState->scriptPayout, feeSource);
        }
    }

    FundSpecialTx(*pwallet, tx, ptx, feeSource);
    UpdateSpecialTxInputsHash(tx, ptx);
    const auto endpoint = llmq::pq::MakeNetworkEndpoint(ptx.addr);
    if (!endpoint) {
        throw JSONRPCError(RPC_INVALID_PARAMETER,
                           "Service address cannot be encoded in the PQ authorization transcript");
    }
    llmq::pq::ProviderServiceAuthorization authorization;
    authorization.payload_version = ptx.nVersion;
    authorization.pro_tx_hash = ptx.proTxHash;
    authorization.global_key_version = ptx.globalKeyVersion;
    authorization.service = *endpoint;
    authorization.operator_payout_script.assign(
        ptx.scriptOperatorPayout.begin(), ptx.scriptOperatorPayout.end());
    if (!ptx.vchNEVMAddress.empty()) {
        authorization.nevm_address.emplace();
        std::copy(ptx.vchNEVMAddress.begin(), ptx.vchNEVMAddress.end(),
                  authorization.nevm_address->begin());
    }
    authorization.transaction_inputs_hash = ptx.inputsHash;
    const auto authorization_hash = llmq::pq::GetProviderServiceAuthorizationHash(
        Params().GetConsensus().hashGenesisBlock,
        operator_state.global_key, authorization);
    if (!authorization_hash ||
        !slhdsa::SignDeterministic(
            keyOperator,
            std::span<const uint8_t>{authorization_hash->begin(),
                                     authorization_hash->size()},
            llmq::pq::GetGlobalAuthContext(
                llmq::pq::GlobalAuthPurpose::PROVIDER_SERVICE),
            ptx.pqSig)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Failed to sign PQ provider service authorization");
    }
    SetTxPayload(tx, ptx);

    return SignAndSendSpecialTx(request, *pwallet, tx);
},
    };
}

    // SYSCOIN: owner updates cannot replace the active PQ operator root.
    static RPCHelpMan protx_update_registrar()
    {
            return RPCHelpMan{"protx_update_registrar",
                "\nCreates and sends a ProUpRegTx to the network. This will update the operator key, voting key, payout\n"
                "address of the masternode specified by \"proTxHash\".\n"
                "The owner key of the masternode must be known to your wallet.\n",
                {
                    {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the initial ProRegTx."},
                    {"deprecatedOperatorPubKey", RPCArg::Type::STR, RPCArg::Optional::NO, "Must be empty. Global SLH-DSA key rotation uses the separate PQ global-key transaction."},
                    {"votingAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "A 32-byte SLH voting public key (64 hex characters). An empty string preserves the current key; 64 zeroes revoke it. This RPC requires PQ activation at the next block height."},
                    {"payoutAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The Syscoin address to use for masternode reward payments.\n"
                                    "If set to an empty string, the currently active payout address is reused."}, 
                    {"feeSourceAddress", RPCArg::Type::STR, RPCArg::Default{""}, "If specified wallet will only use coins from this address to fund ProTx.\n"
                                        "If not specified, payoutAddress is the one that is going to be used.\n"
                                        "The private key belonging to this address must be known in your wallet."},
                },
                RPCResult{RPCResult::Type::STR_HEX, "", "The transaction hash in hex"},
                RPCExamples{
                        HelpExampleCli("protx_update_registrar", "<proTxHash> \"\" <voting-address> <payout-address>")
                    + HelpExampleRpc("protx_update_registrar", "\"<proTxHash>\", \"\", \"<voting-address>\", \"<payout-address>\"")
                },
        [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
    {
        std::shared_ptr<wallet::CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
        if (!pwallet) return NullUniValue;

        // Make sure the results are valid at least up to the most recent block
        // the user could have gotten from another RPC command prior to now
        pwallet->BlockUntilSyncedToCurrentChain();
        EnsureWalletIsUnlocked(*pwallet);
        CProUpRegTx ptx;
        int current_height;
        {
            LOCK(cs_main);
            current_height = *pwallet->chain().getHeight();
        }
        EnsurePQProviderRPCActive(current_height);
        ptx.nVersion = CProUpRegTx::PQ_VERSION;
        ptx.proTxHash = ParseHashV(request.params[0], "proTxHash");
        auto mnList = deterministicMNManager->GetListAtChainTip();
        auto dmn = mnList.GetMN(ptx.proTxHash);
        if (!dmn) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("masternode %s not found", ptx.proTxHash.ToString()));
        }
        ptx.keyIDVoting = dmn->pdmnState->keyIDVoting;
        ptx.pqVotingPublicKey = dmn->pdmnState->pqVotingKey.public_key;
        ptx.scriptPayout = dmn->pdmnState->scriptPayout;

        if (!request.params[1].get_str().empty()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "deprecatedOperatorPubKey must be empty; use a PQ global-key transaction for key rotation");
        }
        if (request.params[2].get_str() != "") {
            ptx.pqVotingPublicKey = ParseVotingPublicKey(request.params[2].get_str(), /*allow_revocation=*/true);
        }

        CTxDestination payoutDest;
        ExtractDestination(ptx.scriptPayout, payoutDest);
        if (request.params[3].get_str() != "") {
            payoutDest = DecodeDestination(request.params[3].get_str());
            if (!IsValidDestination(payoutDest)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("invalid payout address: %s", request.params[3].get_str()));
            }
            ptx.scriptPayout = GetScriptForDestination(payoutDest);
        }
        
        
        CMutableTransaction tx;
        tx.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR;

        // SYSCOIN: migrated ownership carries a full SLH signature.
        ptx.ownerKeyVersion = dmn->pdmnState->pqOwnerKey.key_version;
        ptx.vchSig.resize(dmn->pdmnState->pqOwnerKey.HasActiveKey()
            ? slhdsa::SIGNATURE_SIZE : 65);

        CTxDestination feeSourceDest = payoutDest;
        if (!request.params[4].isNull()) {
            feeSourceDest = DecodeDestination(request.params[4].get_str());
            if (!IsValidDestination(feeSourceDest))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Syscoin address: ") + request.params[4].get_str());
        }
        FundSpecialTx(*pwallet, tx, ptx, feeSourceDest);
        UpdateSpecialTxInputsHash(tx, ptx);
        SignRegistrarOwner(*pwallet, *dmn->pdmnState, ptx);
        SetTxPayload(tx, ptx);

        return SignAndSendSpecialTx(request, *pwallet, tx);
    },
        };
    }  


// SYSCOIN: revocation is authorized by the registered global SLH key.
static RPCHelpMan protx_revoke()
{
        return RPCHelpMan{"protx_revoke",
            "\nCreates and sends a ProUpRevTx to the network. This will revoke the operator key of the masternode and\n"
            "put it into the PoSe-banned state. It will also set the service field of the masternode\n"
            "to zero. Use this in case your operator key got compromised or you want to stop providing your service\n"
            "to the masternode owner.\n",
            {
                {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the initial ProRegTx."},
                {"operatorKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The 64-byte SLH-DSA-SHAKE-128s global operator secret key."},
                {"reason", RPCArg::Type::NUM, RPCArg::Default{0}, "The reason for masternode service revocation."},   
                {"feeSourceAddress", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "If specified wallet will only use coins from this address to fund ProTx.\n"
                                    "If not specified, payoutAddress is the one that is going to be used.\n"
                                    "The private key belonging to this address must be known in your wallet."},
            },
            RPCResult{RPCResult::Type::STR_HEX, "", "The transaction hash in hex"},
            RPCExamples{
                    HelpExampleCli("protx_revoke", "<proTxHash> <64-byte-slh-secret-hex> 0 <fee-source-address>")
                + HelpExampleRpc("protx_revoke", "\"<proTxHash>\", \"<64-byte-slh-secret-hex>\", 0, \"<fee-source-address>\"")
            },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    std::shared_ptr<wallet::CWallet> const pwallet = GetWalletForJSONRPCRequest(request);
    if (!pwallet) return NullUniValue;

    EnsureWalletIsUnlocked(*pwallet);

    // Make sure the results are valid at least up to the most recent block
    // the user could have gotten from another RPC command prior to now
    pwallet->BlockUntilSyncedToCurrentChain();
    node::NodeContext& node = GetWalletNodeContext(*pwallet);
    CProUpRevTx ptx;
    int current_height;
    {
        LOCK(cs_main);
        current_height = *pwallet->chain().getHeight();
    }
    EnsurePQProviderRPCActive(current_height);
    ptx.nVersion = CProUpRevTx::PQ_VERSION;
    ptx.proTxHash = ParseHashV(request.params[0], "proTxHash");

    auto keyOperator = ParseSLHSecretKey(request.params[1].get_str(), "operatorKey");

    if (!request.params[2].isNull()) {
        int32_t nReason = request.params[2].getInt<int>();
        if (nReason < 0 || nReason > CProUpRevTx::REASON_LAST) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("invalid reason %d, must be between 0 and %d", nReason, CProUpRevTx::REASON_LAST));
        }
        ptx.nReason = (uint16_t)nReason;
    }
    auto mnList = deterministicMNManager->GetListAtChainTip();
    auto dmn = mnList.GetMN(ptx.proTxHash);
    if (!dmn) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("masternode %s not found", ptx.proTxHash.ToString()));
    }

    llmq::pq::OperatorKeyState operator_state;
    {
        LOCK(cs_main);
        operator_state = GetActivePQOperator(
            node.chainman->ActiveTip(), ptx.proTxHash, keyOperator);
    }
    ptx.globalKeyVersion = operator_state.global_key.key_version;

    CMutableTransaction tx;
    tx.nVersion = SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE;

    if (!request.params[3].isNull()) {
        CTxDestination feeSourceDest = DecodeDestination(request.params[3].get_str());
        if (!IsValidDestination(feeSourceDest))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Syscoin address: ") + request.params[3].get_str());
        FundSpecialTx(*pwallet, tx, ptx, feeSourceDest);
    } else if (dmn->pdmnState->scriptOperatorPayout != CScript()) {
        // Using funds from previousely specified operator payout address
        CTxDestination txDest;
        ExtractDestination(dmn->pdmnState->scriptOperatorPayout, txDest);
        FundSpecialTx(*pwallet, tx, ptx, txDest);
    } else if (dmn->pdmnState->scriptPayout != CScript()) {
        // Using funds from previousely specified masternode payout address
        CTxDestination txDest;
        ExtractDestination(dmn->pdmnState->scriptPayout, txDest);
        FundSpecialTx(*pwallet, tx, ptx, txDest);
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "No payout or fee source addresses found, can't revoke");
    }

    UpdateSpecialTxInputsHash(tx, ptx);
    llmq::pq::ProviderRevokeAuthorization authorization;
    authorization.payload_version = ptx.nVersion;
    authorization.pro_tx_hash = ptx.proTxHash;
    authorization.global_key_version = ptx.globalKeyVersion;
    authorization.reason = ptx.nReason;
    authorization.transaction_inputs_hash = ptx.inputsHash;
    const auto authorization_hash = llmq::pq::GetProviderRevokeAuthorizationHash(
        Params().GetConsensus().hashGenesisBlock,
        operator_state.global_key, authorization);
    if (!authorization_hash ||
        !slhdsa::SignDeterministic(
            keyOperator,
            std::span<const uint8_t>{authorization_hash->begin(),
                                     authorization_hash->size()},
            llmq::pq::GetGlobalAuthContext(
                llmq::pq::GlobalAuthPurpose::PROVIDER_REVOKE),
            ptx.pqSig)) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Failed to sign PQ provider revocation authorization");
    }
    SetTxPayload(tx, ptx);

    return SignAndSendSpecialTx(request, *pwallet, tx);
},
    };
} 


static bool CheckWalletOwnsKey(CWallet* pwallet, const CKeyID& keyID) {
    if (!pwallet) {
        return false;
    }
    LOCK(pwallet->cs_wallet);
    return pwallet->IsMine(GetScriptForDestination(CTxDestination(WitnessV0KeyHash(keyID)))) != ISMINE_NO;
}

static bool CheckWalletOwnsScript(CWallet* pwallet, const CScript& script) {
    if (!pwallet) {
        return false;
    }
    LOCK(pwallet->cs_wallet);
    return pwallet->IsMine(script) != ISMINE_NO;
}
static bool WalletHasMasternodeOwnerKey(CWallet* wallet, const CDeterministicMN& dmn)
{
    if (!wallet) return false;
    return dmn.pdmnState->pqOwnerKey.HasActiveKey()
        ? wallet->HasOwnerKey(dmn.pdmnState->pqOwnerKey.public_key)
        : CheckWalletOwnsKey(wallet, dmn.pdmnState->keyIDOwner);
}

static bool WalletHasMasternodeVotingKey(CWallet* wallet, const CDeterministicMN& dmn, int height)
{
    if (!wallet) return false;
    return IsPQGovernanceEnabledAtHeight(height)
        ? dmn.pdmnState->pqVotingKey.HasActiveKey() && wallet->HasVotingKey(dmn.pdmnState->pqVotingKey.public_key)
        : CheckWalletOwnsKey(wallet, dmn.pdmnState->keyIDVoting);
}

UniValue BuildDMNListEntry(CWallet* pwallet, const CDeterministicMN& dmn, int detailed, int height)
{
    if (!detailed) {
        return dmn.proTxHash.ToString();
    }
    UniValue o(UniValue::VOBJ);
    if(detailed == 1) {
        const CTxDestination &voteDest = WitnessV0KeyHash(dmn.pdmnState->keyIDVoting);
        o.pushKV("collateralHash", dmn.collateralOutpoint.hash.ToString());
        o.pushKV("collateralIndex", (int)dmn.collateralOutpoint.n);
        o.pushKV("collateralHeight", dmn.pdmnState->nCollateralHeight);
        o.pushKV("votingAddress", EncodeDestination(voteDest));
        o.pushKV("pqVotingPublicKey", HexStr(dmn.pdmnState->pqVotingKey.public_key));
        o.pushKV("pqVotingKeyVersion", dmn.pdmnState->pqVotingKey.key_version);
        o.pushKV("hasVotingKey", WalletHasMasternodeVotingKey(pwallet, dmn, height));
        o.pushKV("pqOwnerPublicKey", HexStr(dmn.pdmnState->pqOwnerKey.public_key));
        o.pushKV("pqOwnerKeyVersion", dmn.pdmnState->pqOwnerKey.key_version);
        o.pushKV("hasOwnerKey", WalletHasMasternodeOwnerKey(pwallet, dmn));
        if(pwallet) {
            LOCK(pwallet->cs_wallet);
            const auto* address_book_entry = pwallet->FindAddressBookEntry(voteDest);
            if (address_book_entry) {
                o.pushKV("label", address_book_entry->GetLabel());
            }
        }
        return o;
    } else if(detailed >= 2 && pwallet) {
        dmn.ToJson(pwallet->chain(), o);
        std::map<COutPoint, Coin> coins;
        coins[dmn.collateralOutpoint]; 
        pwallet->chain().findCoins(coins);
        int confirmations = 0;
        const Coin &coin = coins.at(dmn.collateralOutpoint);
        if(!coin.IsSpent()) {
            confirmations = *pwallet->chain().getHeight() - coin.nHeight;
        }
        o.pushKV("confirmations", confirmations);
        if (pwallet) {
            LOCK2(pwallet->cs_wallet, cs_main);
            bool hasOwnerKey = WalletHasMasternodeOwnerKey(pwallet, dmn);
            bool hasVotingKey = WalletHasMasternodeVotingKey(pwallet, dmn, height);

            UniValue walletObj(UniValue::VOBJ);
            walletObj.pushKV("hasOwnerKey", hasOwnerKey);
            walletObj.pushKV("hasOperatorKey", false);
            walletObj.pushKV("hasVotingKey", hasVotingKey);
            walletObj.pushKV("ownsPayeeScript", CheckWalletOwnsScript(pwallet, dmn.pdmnState->scriptPayout));
            walletObj.pushKV("ownsOperatorRewardScript", CheckWalletOwnsScript(pwallet, dmn.pdmnState->scriptOperatorPayout));
            o.pushKV("wallet", walletObj);
        }

        auto metaInfo = mmetaman->GetMetaInfo(dmn.proTxHash);
        o.pushKV("metaInfo", metaInfo->ToJson());
    }

    return o;
}

static RPCHelpMan protx_list_wallet()
{
    return RPCHelpMan{"protx_list_wallet",
        "\nList only ProTx which are found in your wallet at the given chain height.\n"
        "This will also include ProTx which failed PoSe verification.\n",
        {
            {"detailed", RPCArg::Type::NUM, RPCArg::Default{0}, "If 0, only the hashes of the ProTx are returned. If 1, returns public voting details and wallet key availability; if 2, returns full DMN details. No voting secrets are returned."},
            {"height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Height to look for ProTx transactions, if not specified defaults to current chain-tip"},                   
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("protx_list_wallet", "true")
            + HelpExampleRpc("protx_list_wallet", "true")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    CWallet* pwallet = nullptr;
    std::shared_ptr<wallet::CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (wallet)
        pwallet = wallet.get();

    if (g_txindex) {
        g_txindex->BlockUntilSyncedToCurrentChain();
    }
    UniValue ret(UniValue::VARR);

    if (!pwallet) {
        throw std::runtime_error("\"protx_list_wallet\" not supported when wallet is disabled");
    }
    LOCK2(pwallet->cs_wallet, cs_main);

    int detailed = !request.params[0].isNull() ? request.params[0].getInt<int>() : 0;

    int height = !request.params[1].isNull() ? request.params[1].getInt<int>() : *pwallet->chain().getHeight();
    if (height < 1 || height > pwallet->chain().getHeight()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid height specified");
    }

    std::vector<COutPoint> vOutpts;
    pwallet->ListProTxCoins(vOutpts);
    std::set<COutPoint> setOutpts;
    for (const auto& outpt : vOutpts) {
        setOutpts.emplace(outpt);
    }
    CDeterministicMNList mnList = pwallet->chain().getMNList(height);
    mnList.ForEachMN(false, [&](const auto& dmn) {
        if (setOutpts.count(dmn.collateralOutpoint) ||
            WalletHasMasternodeOwnerKey(pwallet, dmn) ||
            WalletHasMasternodeVotingKey(pwallet, dmn, mnList.GetHeight()) ||
            CheckWalletOwnsScript(pwallet, dmn.pdmnState->scriptPayout) ||
            CheckWalletOwnsScript(pwallet, dmn.pdmnState->scriptOperatorPayout)) {
            ret.push_back(BuildDMNListEntry(pwallet, dmn, detailed, mnList.GetHeight()));
        }
    });
    return ret;
},
    };
} 

static RPCHelpMan protx_info_wallet()
{
    return RPCHelpMan{"protx_info_wallet",
        "\nReturns detailed information about a deterministic masternode in current wallet.\n",
        {
            {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "The hash of the initial ProRegTx."},                 
        },
        RPCResult{RPCResult::Type::ANY, "", ""},
        RPCExamples{
                HelpExampleCli("protx_info_wallet", "1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d")
            + HelpExampleRpc("protx_info_wallet", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"")
        },
    [&](const RPCHelpMan& self, const node::JSONRPCRequest& request) -> UniValue
{
    CWallet* pwallet = nullptr;
    std::shared_ptr<wallet::CWallet> const wallet = GetWalletForJSONRPCRequest(request);
    if (wallet)
        pwallet = wallet.get();
    uint256 proTxHash = ParseHashV(request.params[0], "proTxHash");
    auto mnList = deterministicMNManager->GetListAtChainTip();
    auto dmn = mnList.GetMN(proTxHash);
    if (!dmn) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("%s not found", proTxHash.ToString()));
    }
    return BuildDMNListEntry(pwallet, *dmn, 2, mnList.GetHeight());
},
    };
} 

Span<const CRPCCommand> wallet::GetEvoWalletRPCCommands()
{
    static const CRPCCommand commands[]{
        {"evowallet", &protx_list_wallet},
        {"evowallet", &protx_info_wallet},
        {"evowallet", &protx_register},
        {"evowallet", &protx_register_fund},
        {"evowallet", &protx_register_prepare},
        {"evowallet", &protx_register_submit},
        {"evowallet", &protx_generate_voting_key},
        {"evowallet", &protx_generate_owner_key},
        {"evowallet", &protx_update_owner},
        {"evowallet", &protx_register_operator_prepare},
        {"evowallet", &protx_decode_operator_request},
        {"evowallet", &protx_register_operator_sign},
        {"evowallet", &protx_register_operator_submit},
        {"evowallet", &protx_generate_operator_keypair},
        {"evowallet", &protx_register_operator_key},
        {"evowallet", &protx_rotate_operator_key},
        {"evowallet", &protx_recovery_ready},
        {"evowallet", &protx_update_service},
        {"evowallet", &protx_update_registrar},
        {"evowallet", &protx_revoke},
    };
    return commands;
}
