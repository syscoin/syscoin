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
#include <wallet/spend.h>
#include <wallet/rpc/util.h>

#include <netbase.h>

#include <evo/specialtx.h>
#include <evo/providertx.h>
#include <evo/deterministicmns.h>
#include <evo/pq_providertx.h>
#include <evo/pq_registry.h>

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
    llmq::pq::PQRegistrySnapshot snapshot;
    std::string error;
    if (tip == nullptr || !deterministicMNManager->GetPQRegistrySnapshot(
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
    const CKey& owner_key,
    const slhdsa::SecretKey& operator_key,
    const llmq::pq::GlobalKeyRecord* previous_key = nullptr)
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
    std::vector<unsigned char> owner_signature;
    if (!owner_hash || !operator_hash ||
        !CHashSigner::SignHash(*owner_hash, owner_key, owner_signature) ||
        owner_signature.size() != payload.owner_authorization.size()) {
        throw JSONRPCError(RPC_INTERNAL_ERROR,
                           "Failed to sign PQ global-key owner authorization");
    }
    std::copy(owner_signature.begin(), owner_signature.end(),
              payload.owner_authorization.begin());
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
static UniValue SignAndSendSpecialTx(const node::JSONRPCRequest& request, const wallet::CWallet& pwallet, const CMutableTransaction& tx, bool fSubmit = true)
{
    CDataStream ds(SER_NETWORK, PROTOCOL_VERSION);
    ds << tx;

    node::JSONRPCRequest signRequest;
    signRequest.context = request.context;
    signRequest.URI = request.URI;
    signRequest.params.setArray();
    signRequest.params.push_back(HexStr(ds));
    UniValue signResult = signrawtransactionwithwallet().HandleRequest(signRequest);
    if (!fSubmit) {
        return signResult["hex"].get_str();
    }
    CMutableTransaction mtx;
    if(!DecodeHexTx(mtx, signResult["hex"].get_str())) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed. Make sure the tx has at least one input.");
    }
    CTransactionRef txRef(MakeTransactionRef(std::move(mtx)));

    int64_t virtual_size = GetVirtualTransactionSize(*txRef);
    CAmount max_raw_tx_fee = node::DEFAULT_MAX_RAW_TX_FEE_RATE.GetFee(virtual_size);

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
                    {"ownerAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The Syscoin address to use for payee updates and proposal voting.\n"
                                        "The corresponding private key does not have to be known by your wallet.\n"
                                        "The address must be unused and must differ from the collateralAddress."},
                    {"legacyOperatorPubKey", RPCArg::Type::STR, RPCArg::Optional::NO, "Legacy 48-byte operator public key before PQ activation; must be empty after activation. The global SLH-DSA key is registered separately."},
                    {"votingAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The voting key address. The private key does not have to be known by your wallet.\n"
                                        "It has to match the private key which is later used when voting on proposals.\n"
                                        "If set to an empty string, ownerAddress will be used.\n"},
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

        ptx.keyIDOwner = ParsePubKeyIDFromAddress(request.params[paramIdx + 1].get_str(), "owner address");
        ConfigureProviderRegistrationForNextBlock(
            ptx, current_height,
            request.params[paramIdx + 2].get_str());
        CKeyID keyIDVoting = ptx.keyIDOwner;
        if (request.params[paramIdx + 3].get_str() != "") {
            keyIDVoting = ParsePubKeyIDFromAddress(request.params[paramIdx + 3].get_str(), "voting address");
        }

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

        ptx.keyIDVoting = keyIDVoting;
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
                    {"ownerAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The Syscoin address to use for payee updates and proposal voting.\n"
                                        "The corresponding private key does not have to be known by your wallet.\n"
                                        "The address must be unused and must differ from the collateralAddress."},
                    {"legacyOperatorPubKey", RPCArg::Type::STR, RPCArg::Optional::NO, "Legacy 48-byte operator public key before PQ activation; must be empty after activation. Register the global SLH-DSA key separately."},
                    {"votingAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The voting key address. The private key does not have to be known by your wallet.\n"
                                        "It has to match the private key which is later used when voting on proposals.\n"
                                        "If set to an empty string, ownerAddress will be used.\n"},
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

    ptx.keyIDOwner = ParsePubKeyIDFromAddress(request.params[paramIdx + 1].get_str(), "owner address");
    ConfigureProviderRegistrationForNextBlock(
        ptx, current_height,
        request.params[paramIdx + 2].get_str());
    CKeyID keyIDVoting = ptx.keyIDOwner;
    if (request.params[paramIdx + 3].get_str() != "") {
        keyIDVoting = ParsePubKeyIDFromAddress(request.params[paramIdx + 3].get_str(), "voting address");
    }

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

    ptx.keyIDVoting = keyIDVoting;
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
                {"ownerAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The Syscoin address to use for payee updates and proposal voting.\n"
                                    "The corresponding private key does not have to be known by your wallet.\n"
                                    "The address must be unused and must differ from the collateralAddress."},
                {"legacyOperatorPubKey", RPCArg::Type::STR, RPCArg::Optional::NO, "Legacy 48-byte operator public key before PQ activation; must be empty after activation. Register the global SLH-DSA key separately."},
                {"votingAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The voting key address. The private key does not have to be known by your wallet.\n"
                                    "It has to match the private key which is later used when voting on proposals.\n"
                                    "If set to an empty string, ownerAddress will be used.\n"},
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

        ptx.keyIDOwner = ParsePubKeyIDFromAddress(request.params[paramIdx + 1].get_str(), "owner address");
        ConfigureProviderRegistrationForNextBlock(
            ptx, current_height,
            request.params[paramIdx + 2].get_str());
        CKeyID keyIDVoting = ptx.keyIDOwner;
        if (request.params[paramIdx + 3].get_str() != "") {
            keyIDVoting = ParsePubKeyIDFromAddress(request.params[paramIdx + 3].get_str(), "voting address");
        }

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

        ptx.keyIDVoting = keyIDVoting;
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

// SYSCOIN: one-time bootstrap/recovery of the global operator key and child root.
static RPCHelpMan protx_register_operator_key()
{
    return RPCHelpMan{
        "protx_register_operator_key",
        "\nRegisters the initial global SLH-DSA operator key, or recovers a revoked key, using owner ECDSA authorization plus new-key proof of possession.\n",
        {
            {"proTxHash", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The deterministic masternode ProRegTx hash."},
            {"operatorKey", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The exactly 64-byte SLH-DSA-SHAKE-128s secret key. Avoid exposing this argument through shell history."},
            {"chainlockSeed", RPCArg::Type::STR_HEX, RPCArg::Optional::NO,
             "The independent nonzero 32-byte ChainLock seed. It deterministically commits 65,536 epoch keys and is never placed on-chain."},
            {"feeSourceAddress", RPCArg::Type::STR, RPCArg::Default{""},
             "Wallet address used to fund the transaction; defaults to the masternode payout address."},
            {"submit", RPCArg::Type::BOOL, RPCArg::Default{true},
             "Broadcast when true; otherwise return the signed transaction hex."},
        },
        RPCResult{RPCResult::Type::STR_HEX, "", "Transaction hash or signed transaction hex"},
        RPCExamples{HelpExampleCli(
            "protx_register_operator_key",
            "<proTxHash> <64-byte-secret-key> <32-byte-chainlock-seed>")},
        [&](const RPCHelpMan&, const node::JSONRPCRequest& request) -> UniValue {
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
            uint32_t first_epoch{0};
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

                llmq::pq::PQRegistrySnapshot snapshot;
                std::string registry_error;
                if (!deterministicMNManager->GetPQRegistrySnapshot(
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
                llmq::pq::PQRegistryConfig config;
                if (llmq::pq::GetPQRegistryConfig(
                        Params().GetConsensus(), config) !=
                    llmq::pq::PQRegistryDeploymentResult::VALID) {
                    throw JSONRPCError(RPC_INTERNAL_ERROR,
                                       "PQ registry configuration is invalid");
                }
                const auto view = llmq::pq::DeriveOperatorKeyScheduleView(
                    config.schedule, tip->nHeight + 1,
                    config.registration_cutoff_blocks,
                    config.future_horizon_epochs);
                if (!view) {
                    throw JSONRPCError(
                        RPC_INTERNAL_ERROR,
                        "Unable to derive the next-block PQ key schedule");
                }
                first_epoch = view->first_mutable_epoch;
            }

            const auto child_commitment = BuildChildKeyTreeCommitment(
                chainlock_seed, pro_tx_hash, tree_generation, first_epoch);

            CKey owner_key;
            if (!pwallet->GetKey(dmn->pdmnState->keyIDOwner, owner_key)) {
                throw JSONRPCError(RPC_WALLET_ERROR,
                                   "The masternode owner key is not in this wallet");
            }

            llmq::pq::GlobalKeyTxPayload payload;
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
                payload, owner_key, operator_key,
                previous_key ? &*previous_key : nullptr);

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
                payload, owner_key, operator_key,
                previous_key ? &*previous_key : nullptr);
            SetTxPayload(tx, payload);

            const bool submit = request.params[4].isNull() ||
                                request.params[4].get_bool();
            return SignAndSendSpecialTx(request, *pwallet, tx, submit);
        },
    };
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
            uint32_t replacement_first_epoch{0};
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

                    llmq::pq::PQRegistryConfig config;
                    if (llmq::pq::GetPQRegistryConfig(
                            Params().GetConsensus(), config) !=
                        llmq::pq::PQRegistryDeploymentResult::VALID) {
                        throw JSONRPCError(
                            RPC_INTERNAL_ERROR,
                            "PQ registry configuration is invalid");
                    }
                    const auto view{
                        llmq::pq::DeriveOperatorKeyScheduleView(
                            config.schedule, tip->nHeight + 1,
                            config.registration_cutoff_blocks,
                            config.future_horizon_epochs)};
                    if (!view) {
                        throw JSONRPCError(
                            RPC_INTERNAL_ERROR,
                            "Unable to derive the next-block PQ key schedule");
                    }
                    replacement_first_epoch = view->first_mutable_epoch;
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
                    BuildChildKeyTreeCommitment(
                        replacement_chainlock_seed,
                        pro_tx_hash,
                        replacement_tree_generation,
                        replacement_first_epoch);
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
            return SignAndSendSpecialTx(request, *pwallet, tx, submit);
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
                    {"votingAddress", RPCArg::Type::STR, RPCArg::Optional::NO, "The voting key address. The private key does not have to be known by your wallet.\n"
                                    "It has to match the private key which is later used when voting on proposals.\n"
                                    "If set to an empty string, the currently active voting key address is reused."}, 
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
        ptx.scriptPayout = dmn->pdmnState->scriptPayout;

        if (!request.params[1].get_str().empty()) {
            throw JSONRPCError(
                RPC_INVALID_PARAMETER,
                "deprecatedOperatorPubKey must be empty; use a PQ global-key transaction for key rotation");
        }
        if (request.params[2].get_str() != "") {
            ptx.keyIDVoting = ParsePubKeyIDFromAddress(request.params[2].get_str(), "voting address");
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

        // make sure we get anough fees added
        ptx.vchSig.resize(65);

        CTxDestination feeSourceDest = payoutDest;
        if (!request.params[4].isNull()) {
            feeSourceDest = DecodeDestination(request.params[4].get_str());
            if (!IsValidDestination(feeSourceDest))
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid Syscoin address: ") + request.params[4].get_str());
        }
        FundSpecialTx(*pwallet, tx, ptx, feeSourceDest);
        UpdateSpecialTxInputsHash(tx, ptx);
        ptx.vchSig.clear();
        const CTxDestination ownerDest = WitnessV0KeyHash(dmn->pdmnState->keyIDOwner);
        CKey owner_key;
        if (!pwallet->GetKey(dmn->pdmnState->keyIDOwner, owner_key)) {
            throw std::runtime_error(strprintf("Private key for owner address %s not found in your wallet", EncodeDestination(ownerDest)));
        }
        std::vector<unsigned char> owner_sig;
        if (!CHashSigner::SignHash(::SerializeHash(ptx), owner_key, owner_sig)) {
            throw std::runtime_error("Failed to sign ProUpRegTx payload.");
        }
        ptx.vchSig = std::move(owner_sig);
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
UniValue BuildDMNListEntry(CWallet* pwallet, const CDeterministicMN& dmn, int detailed)
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
        if(pwallet) {
            LOCK(pwallet->cs_wallet);
            CKey keyVoting;
            if (pwallet->GetKey(dmn.pdmnState->keyIDVoting, keyVoting)) {
                o.pushKV("votingKey", EncodeSecret(keyVoting));
            }
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
            bool hasOwnerKey = CheckWalletOwnsKey(pwallet, dmn.pdmnState->keyIDOwner);
            bool hasVotingKey = CheckWalletOwnsKey(pwallet, dmn.pdmnState->keyIDVoting);

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
            {"detailed", RPCArg::Type::NUM, RPCArg::Default{0}, "If 0, only the hashes of the ProTx will be returned. If 1 returns voting details for each DMN and keys and if 2 returns full details of each DMN"},
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
            CheckWalletOwnsKey(pwallet, dmn.pdmnState->keyIDOwner) ||
            CheckWalletOwnsKey(pwallet, dmn.pdmnState->keyIDVoting) ||
            CheckWalletOwnsScript(pwallet, dmn.pdmnState->scriptPayout) ||
            CheckWalletOwnsScript(pwallet, dmn.pdmnState->scriptOperatorPayout)) {
            ret.push_back(BuildDMNListEntry(pwallet, dmn, detailed));
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
    return BuildDMNListEntry(pwallet, *dmn, 2);
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
        {"evowallet", &protx_generate_operator_keypair},
        {"evowallet", &protx_register_operator_key},
        {"evowallet", &protx_rotate_operator_key},
        {"evowallet", &protx_update_service},
        {"evowallet", &protx_update_registrar},
        {"evowallet", &protx_revoke},
    };
    return commands;
}
