// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/deterministicmns.h>
#include <evo/pq_registry.h>
#include <evo/providertx.h>
#include <evo/specialtx.h>
#include <consensus/pq_migration_config.h>
#include <llmq/pq_global_auth.h>
#include <llmq/quorums_utils.h>

#include <base58.h>
#include <chainparams.h>
#include <clientversion.h>
#include <core_io.h>
#include <coins.h>
#include <hash.h>
#include <messagesigner.h>
#include <script/script.h>
#include <validation.h>
#include <common/args.h>

namespace {

enum class ProviderAuthEra {
    LEGACY_REPLAY,
    POST_QUANTUM,
    INVALID,
};

ProviderAuthEra GetProviderAuthEra(const CBlockIndex* pindex_prev)
{
    if (pindex_prev == nullptr) return ProviderAuthEra::INVALID;
    const auto& consensus = Params().GetConsensus();
    const auto replay{Consensus::CheckPQLegacyReplay(
        consensus, pindex_prev->nHeight + 1)};
    if (replay == Consensus::PQLegacyReplayResult::INVALID_CONFIGURATION) {
        return ProviderAuthEra::INVALID;
    }
    return replay == Consensus::PQLegacyReplayResult::ALLOWED
        ? ProviderAuthEra::LEGACY_REPLAY
        : ProviderAuthEra::POST_QUANTUM;
}

template <typename Range>
bool HasNonZeroByte(const Range& range)
{
    return std::any_of(range.begin(), range.end(), [](uint8_t byte) {
        return byte != 0;
    });
}

bool GetParentOperatorKey(const CBlockIndex* pindex_prev,
                          const uint256& pro_tx_hash,
                          const llmq::pq::OperatorKeyState*& operator_state,
                          llmq::pq::PQRegistryReadView& snapshot)
{
    if (pindex_prev == nullptr || deterministicMNManager == nullptr) return false;
    std::string error;
    if (!deterministicMNManager->GetPQRegistryReadView(
            pindex_prev, snapshot, error)) {
        return false;
    }
    operator_state = snapshot.FindOperator(pro_tx_hash);
    return operator_state != nullptr && operator_state->HasActiveGlobalKey() &&
           operator_state->global_key.IsStructurallyValid();
}

bool CheckProviderVersion(uint16_t actual,
                          uint16_t legacy_max,
                          uint16_t pq_version,
                          ProviderAuthEra era,
                          TxValidationState& state)
{
    const bool valid = era == ProviderAuthEra::POST_QUANTUM
        ? actual == pq_version
        : era == ProviderAuthEra::LEGACY_REPLAY
            ? actual != 0 && actual <= legacy_max
            : false;
    return valid || state.Invalid(TxValidationResult::TX_CONSENSUS,
                                  "bad-protx-version");
}

bool ShouldCheckProviderAuthorization(
    ProviderAuthEra era,
    bool check_sigs,
    SpecialTxValidationContext validation_context) noexcept
{
    // assumevalid may omit Bitcoin/ECDSA script checks, but post-quantum
    // operator authorization is independent consensus state. The mempool
    // precheck is followed by NORMAL authentication; crash roll-forward reuses
    // the result of the block's earlier full validation.
    const bool explicitly_deferred =
        validation_context == SpecialTxValidationContext::MEMPOOL_PRECHECK ||
        validation_context ==
            SpecialTxValidationContext::ALREADY_VALIDATED_ROLLFORWARD;
    return check_sigs ||
           (era == ProviderAuthEra::POST_QUANTUM && !explicitly_deferred);
}

template <typename Payload>
bool GetProviderPayload(const CTransaction& tx,
                        ProviderAuthEra era,
                        Payload& payload)
{
    std::vector<unsigned char> encoded;
    int output_index{-1};
    if (!GetSyscoinData(tx, encoded, output_index)) return false;
    if (era != ProviderAuthEra::POST_QUANTUM) {
        return GetTxPayload(encoded, payload);
    }
    try {
        CDataStream stream(encoded, SER_NETWORK, PROTOCOL_VERSION);
        stream >> payload;
        return stream.empty();
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace

std::optional<ProviderMutationIdentity>
DecodeProviderMutationIdentity(const CTransaction& tx) noexcept
{
    try {
        std::vector<unsigned char> encoded;
        int output_index{-1};
        if (!GetSyscoinData(tx, encoded, output_index)) return std::nullopt;

        CDataStream stream(encoded, SER_NETWORK, PROTOCOL_VERSION);
        switch (tx.nVersion) {
        case SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE: {
            CProUpServTx payload;
            stream >> payload;
            if (!stream.empty() || payload.nVersion == 0 ||
                payload.nVersion > CProUpServTx::PQ_VERSION ||
                payload.proTxHash.IsNull()) {
                return std::nullopt;
            }
            return ProviderMutationIdentity{payload.proTxHash, false};
        }
        case SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR: {
            CProUpRegTx payload;
            stream >> payload;
            if (!stream.empty() || payload.nVersion == 0 ||
                payload.nVersion > CProUpRegTx::PQ_VERSION ||
                payload.proTxHash.IsNull()) {
                return std::nullopt;
            }
            return ProviderMutationIdentity{payload.proTxHash, false};
        }
        case SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE: {
            CProUpRevTx payload;
            stream >> payload;
            if (!stream.empty() || payload.nVersion == 0 ||
                payload.nVersion > CProUpRevTx::PQ_VERSION ||
                payload.proTxHash.IsNull()) {
                return std::nullopt;
            }
            return ProviderMutationIdentity{
                payload.proTxHash,
                payload.nVersion == CProUpRevTx::PQ_VERSION};
        }
        default:
            return std::nullopt;
        }
    } catch (const std::exception&) {
        return std::nullopt;
    } catch (...) {
        return std::nullopt;
    }
}

bool CProRegTx::IsTriviallyValid(TxValidationState& state, bool) const
{
    if (nVersion == 0 || nVersion > PQ_VERSION) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-version");
    }
    if (nType != 0) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-type");
    }
    if (nMode != 0) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-mode");
    }

    if (keyIDOwner.IsNull() || keyIDVoting.IsNull() ||
        (nVersion <= BASIC_BLS_VERSION && !pubKeyOperator.IsValid()) ||
        (nVersion == PQ_VERSION && !pubKeyOperator.IsNull())) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-key-null");
    }
    CTxDestination payoutDest;
    if (!ExtractDestination(scriptPayout, payoutDest)) {
        // should not happen as we checked script types before
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-payee-dest");
    }
    // don't allow reuse of payout key for other keys (don't allow people to put the payee key onto an online server)
    if (payoutDest == CTxDestination(WitnessV0KeyHash(keyIDOwner)) || payoutDest == CTxDestination(WitnessV0KeyHash(keyIDVoting))) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-payee-reuse");
    }

    if (nOperatorReward > 10000) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-operator-reward");
    }
    return true;
}
template <typename ProTx>
static bool CheckService(const ProTx& proTx, TxValidationState& state, bool fJustCheck)
{
    if (!proTx.addr.IsValid()) {
        return FormatSyscoinErrorMessage(state, "bad-protx-ipaddr", fJustCheck);
    }
    if (Params().RequireRoutableExternalIP() && !proTx.addr.IsRoutable()) {
        return FormatSyscoinErrorMessage(state, "bad-protx-ipaddr", fJustCheck);
    }
    ArgsManager args;
    static int mainnetDefaultPort = CreateChainParams(args, ChainType::MAIN)->GetDefaultPort();
    if (Params().GetChainType() == ChainType::MAIN) {
        if (proTx.addr.GetPort() != mainnetDefaultPort) {
            return FormatSyscoinErrorMessage(state, "bad-protx-ipaddr-port", fJustCheck);
        }
    } else if (proTx.addr.GetPort() == mainnetDefaultPort) {
        return FormatSyscoinErrorMessage(state, "bad-protx-ipaddr-port", fJustCheck);
    }

    if (!proTx.addr.IsIPv4()) {
        return FormatSyscoinErrorMessage(state, "bad-protx-ipaddr", fJustCheck);
    }

    return true;
}

template <typename ProTx>
static bool CheckHashSig(const ProTx& proTx, const CKeyID& keyID, TxValidationState& state, bool fJustCheck)
{
    if (!CHashSigner::VerifyHash(::SerializeHash(proTx), keyID, proTx.vchSig)) {
        return FormatSyscoinErrorMessage(state, "bad-protx-hash-sig", fJustCheck);
    }
    return true;
}

template <typename ProTx>
static bool CheckStringSig(const ProTx& proTx, const CKeyID& keyID, TxValidationState& state, bool fJustCheck)
{
    if (!CMessageSigner::VerifyMessage(keyID, proTx.vchSig, proTx.MakeSignString())) {
        return FormatSyscoinErrorMessage(state, "bad-protx-message-sig", fJustCheck);
    }
    return true;
}

template <typename ProTx>
static bool CheckInputsHash(const CTransaction& tx, const ProTx& proTx, TxValidationState& state, bool fJustCheck)
{
    uint256 inputsHash = CalcTxInputsHash(tx);
    if (inputsHash != proTx.inputsHash) {
        return FormatSyscoinErrorMessage(state, "bad-protx-inputs-hash", fJustCheck);
    }

    return true;
}

bool CheckProRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, CCoinsViewCache& view, bool fJustCheck, bool check_sigs)
{
    AssertLockHeld(cs_main);
    if (tx.nVersion != SYSCOIN_TX_VERSION_MN_REGISTER) {
        return FormatSyscoinErrorMessage(state, "bad-protx-type", fJustCheck);
    }

    const ProviderAuthEra auth_era = GetProviderAuthEra(pindexPrev);
    CProRegTx ptx;
    if (!GetProviderPayload(tx, auth_era, ptx)) {
        return FormatSyscoinErrorMessage(state, "bad-protx-payload", fJustCheck);
    }
    const bool basic_scheme = pindexPrev != nullptr &&
        llmq::CLLMQUtils::IsV19Active(pindexPrev->nHeight);
    if (!CheckProviderVersion(ptx.nVersion,
                              CProRegTx::GetVersion(basic_scheme),
                              CProRegTx::PQ_VERSION, auth_era, state) ||
        !ptx.IsTriviallyValid(state, basic_scheme)) {
        return FormatSyscoinErrorMessage(state, state.GetRejectReason(), fJustCheck);
    }

    // It's allowed to set addr to 0, which will put the MN into PoSe-banned state and require a ProUpServTx to be issues later
    // If any of both is set, it must be valid however
    if (ptx.addr != CService() && !CheckService(ptx, state, fJustCheck)) {
        // pass the state returned by the function above
        return false;
    }

    CTxDestination collateralTxDest;
    CKeyID keyForPayloadSig;
    COutPoint collateralOutpoint;

    if (!ptx.collateralOutpoint.hash.IsNull()) {
        Coin coin;
        if (!view.GetCoin(ptx.collateralOutpoint, coin) || coin.IsSpent() || coin.out.nValue != nMNCollateralRequired) {
            return FormatSyscoinErrorMessage(state, "bad-protx-collateral", fJustCheck);
        }

        if (!ExtractDestination(coin.out.scriptPubKey, collateralTxDest)) {
            return FormatSyscoinErrorMessage(state, "bad-protx-collateral-dest", fJustCheck);
        }

        // Extract key from collateral. This only works for P2PK and P2PKH collaterals and will fail for P2SH.
        // Issuer of this ProRegTx must prove ownership with this key by signing the ProRegTx
        if (auto witness_id = std::get_if<WitnessV0KeyHash>(&collateralTxDest)) {	
            keyForPayloadSig = ToKeyID(*witness_id);
        }	
        else if (auto key_id = std::get_if<PKHash>(&collateralTxDest)) {	
            keyForPayloadSig = ToKeyID(*key_id);
        }	
        if (keyForPayloadSig.IsNull()) {
            return FormatSyscoinErrorMessage(state, "bad-protx-collateral-pkh", fJustCheck);
        }

        collateralOutpoint = ptx.collateralOutpoint;
    } else {
        if (ptx.collateralOutpoint.n >= tx.vout.size()) {
            return FormatSyscoinErrorMessage(state, "bad-protx-collateral-index", fJustCheck);
        }
        if (tx.vout[ptx.collateralOutpoint.n].nValue != nMNCollateralRequired) {
            return FormatSyscoinErrorMessage(state, "bad-protx-collateral", fJustCheck);
        }

        if (!ExtractDestination(tx.vout[ptx.collateralOutpoint.n].scriptPubKey, collateralTxDest)) {
            return FormatSyscoinErrorMessage(state, "bad-protx-collateral-dest", fJustCheck);
        }

        collateralOutpoint = COutPoint(tx.GetHash(), ptx.collateralOutpoint.n);
    }

    // don't allow reuse of collateral key for other keys (don't allow people to put the collateral key onto an online server)
    // this check applies to internal and external collateral, but internal collaterals are not necessarily a P2PKH
    if (collateralTxDest == CTxDestination(WitnessV0KeyHash(ptx.keyIDOwner)) || collateralTxDest == CTxDestination(WitnessV0KeyHash(ptx.keyIDVoting))) {
        return FormatSyscoinErrorMessage(state, "bad-protx-collateral-reuse", fJustCheck);
    }

    if (pindexPrev) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);

        // only allow reusing of addresses when it's for the same collateral (which replaces the old MN)
        if (mnList.HasUniqueProperty(ptx.addr) && mnList.GetUniquePropertyMN(ptx.addr)->collateralOutpoint != collateralOutpoint) {
            return FormatSyscoinErrorMessage(state, "bad-protx-dup-addr", fJustCheck);
        }

        // never allow duplicate keys, even if this ProTx would replace an existing MN
        if (mnList.HasUniqueProperty(ptx.keyIDOwner) ||
            (ptx.nVersion <= CProRegTx::BASIC_BLS_VERSION &&
             mnList.HasUniqueProperty(ptx.pubKeyOperator))) {
            return FormatSyscoinErrorMessage(state, "bad-protx-dup-key", fJustCheck);
        }

    }

    if (!CheckInputsHash(tx, ptx, state, fJustCheck)) {
        return false;
    }

    if (!keyForPayloadSig.IsNull()) {
        // collateral is not part of this ProRegTx, so we must verify ownership of the collateral
        if (check_sigs && !CheckStringSig(ptx, keyForPayloadSig, state, fJustCheck)) {
            // pass the state returned by the function above
            return false;
        }
    } else {
        // collateral is part of this ProRegTx, so we know the collateral is owned by the issuer
        if (!ptx.vchSig.empty()) {
            return FormatSyscoinErrorMessage(state, "bad-protx-sig", fJustCheck);
        }
    }

    return true;
}

bool CheckProUpServTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, bool fJustCheck, bool check_sigs, SpecialTxValidationContext validation_context)
{
    if (tx.nVersion != SYSCOIN_TX_VERSION_MN_UPDATE_SERVICE) {
        return FormatSyscoinErrorMessage(state, "bad-protx-type", fJustCheck);
    }

    const ProviderAuthEra auth_era = GetProviderAuthEra(pindexPrev);
    CProUpServTx ptx;
    if (!GetProviderPayload(tx, auth_era, ptx)) {
        return FormatSyscoinErrorMessage(state, "bad-protx-payload", fJustCheck);
    }
    const bool basic_scheme = pindexPrev != nullptr &&
        llmq::CLLMQUtils::IsV19Active(pindexPrev->nHeight);
    if (!CheckProviderVersion(ptx.nVersion,
                              CProUpServTx::GetVersion(basic_scheme),
                              CProUpServTx::PQ_VERSION, auth_era, state) ||
        !ptx.IsTriviallyValid(state, basic_scheme)) {
        return FormatSyscoinErrorMessage(state, state.GetRejectReason(), fJustCheck);
    }

    if (!CheckService(ptx, state, fJustCheck)) {
        // pass the state returned by the function above
        return false;
    }

    if (pindexPrev) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        auto mn = mnList.GetMN(ptx.proTxHash);
        if (!mn) {
            return FormatSyscoinErrorMessage(state, "bad-protx-hash", fJustCheck);
        }

        // don't allow updating to addresses already used by other MNs
        if (mnList.HasUniqueProperty(ptx.addr) && mnList.GetUniquePropertyMN(ptx.addr)->proTxHash != ptx.proTxHash) {
            return FormatSyscoinErrorMessage(state, "bad-protx-dup-addr", fJustCheck);
        }
        
        if(ptx.vchNEVMAddress != mn->pdmnState->vchNEVMAddress) {
            if (mn->pdmnState->confirmedHash.IsNull()) {
                return FormatSyscoinErrorMessage(state, "bad-protx-unconfirmed-nevm-address", fJustCheck);
            }
            if(mn->pdmnState->IsBanned()) {
                return FormatSyscoinErrorMessage(state, "bad-protx-banned-nevm-address", fJustCheck);
            }
        }
        if(!ptx.vchNEVMAddress.empty()) {
            if (ptx.vchNEVMAddress.size() != 20) {
                return FormatSyscoinErrorMessage(state, "bad-protx-invalid-nevmaddress-size", fJustCheck);
            }
            if (mnList.HasUniqueProperty(ptx.vchNEVMAddress)) {
                auto otherDmn = mnList.GetUniquePropertyMN(ptx.vchNEVMAddress);
                if (ptx.proTxHash != otherDmn->proTxHash) {
                    return FormatSyscoinErrorMessage(state, "bad-protx-dup-nevm-address", fJustCheck);
                }
            }
        }
        
        if (ptx.scriptOperatorPayout != CScript()) {
            if (mn->nOperatorReward == 0) {
                // don't allow to set operator reward payee in case no operatorReward was set
                return FormatSyscoinErrorMessage(state, "bad-protx-operator-payee", fJustCheck);
            }
            CTxDestination payoutDest;
            if (!ExtractDestination(ptx.scriptOperatorPayout, payoutDest)) {
                // should not happen as we checked script types before
                return FormatSyscoinErrorMessage(state, "bad-protx-operator-payee", fJustCheck);
            }
        }

        // we can only check the signature if pindexPrev != nullptr and the MN is known
        if (!CheckInputsHash(tx, ptx, state, fJustCheck)) {
            // pass the state returned by the function above
            return false;
        }
        if (ShouldCheckProviderAuthorization(
                auth_era, check_sigs, validation_context)) {
            if (auth_era == ProviderAuthEra::POST_QUANTUM) {
                llmq::pq::PQRegistryReadView registry_snapshot;
                const llmq::pq::OperatorKeyState* operator_state{nullptr};
                if (!GetParentOperatorKey(pindexPrev, ptx.proTxHash,
                                          operator_state, registry_snapshot) ||
                    ptx.globalKeyVersion != operator_state->global_key.key_version) {
                    return FormatSyscoinErrorMessage(
                        state, "bad-protx-pq-key", fJustCheck);
                }
                const auto endpoint = llmq::pq::MakeNetworkEndpoint(ptx.addr);
                if (!endpoint) {
                    return FormatSyscoinErrorMessage(
                        state, "bad-protx-pq-service", fJustCheck);
                }
                llmq::pq::ProviderServiceAuthorization authorization;
                authorization.payload_version = ptx.nVersion;
                authorization.pro_tx_hash = ptx.proTxHash;
                authorization.global_key_version = ptx.globalKeyVersion;
                authorization.service = *endpoint;
                authorization.operator_payout_script.assign(
                    ptx.scriptOperatorPayout.begin(), ptx.scriptOperatorPayout.end());
                if (!ptx.vchNEVMAddress.empty()) {
                    if (ptx.vchNEVMAddress.size() != llmq::pq::NEVM_ADDRESS_SIZE) {
                        return FormatSyscoinErrorMessage(
                            state, "bad-protx-invalid-nevmaddress-size", fJustCheck);
                    }
                    authorization.nevm_address.emplace();
                    std::copy(ptx.vchNEVMAddress.begin(), ptx.vchNEVMAddress.end(),
                              authorization.nevm_address->begin());
                }
                authorization.transaction_inputs_hash = ptx.inputsHash;
                if (!llmq::pq::VerifyProviderServiceAuthorization(
                        Params().GetConsensus().hashGenesisBlock,
                        operator_state->global_key, authorization, ptx.pqSig)) {
                    return FormatSyscoinErrorMessage(
                        state, "bad-protx-pq-sig", fJustCheck);
                }
            }
        }
    }

    return true;
}

bool CheckProUpRegTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, CCoinsViewCache& view, bool fJustCheck, bool check_sigs)
{
    if (tx.nVersion != SYSCOIN_TX_VERSION_MN_UPDATE_REGISTRAR) {
        return FormatSyscoinErrorMessage(state, "bad-protx-type", fJustCheck);
    }

    const ProviderAuthEra auth_era = GetProviderAuthEra(pindexPrev);
    CProUpRegTx ptx;
    if (!GetProviderPayload(tx, auth_era, ptx)) {
        return FormatSyscoinErrorMessage(state, "bad-protx-payload", fJustCheck);
    }
    const bool basic_scheme = pindexPrev != nullptr &&
        llmq::CLLMQUtils::IsV19Active(pindexPrev->nHeight);
    if (!CheckProviderVersion(ptx.nVersion,
                              CProUpRegTx::GetVersion(basic_scheme),
                              CProUpRegTx::PQ_VERSION, auth_era, state) ||
        !ptx.IsTriviallyValid(state, basic_scheme)) {
        return FormatSyscoinErrorMessage(state, state.GetRejectReason(), fJustCheck);
    }
    

    CTxDestination payoutDest;
    if (!ExtractDestination(ptx.scriptPayout, payoutDest)) {
        // should not happen as we checked script types before
        return FormatSyscoinErrorMessage(state, "bad-protx-payee-dest", fJustCheck);
    }

    if (pindexPrev) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        auto dmn = mnList.GetMN(ptx.proTxHash);
        if (!dmn) {
            return FormatSyscoinErrorMessage(state, "bad-protx-hash", fJustCheck);
        }

        // don't allow reuse of payee key for other keys (don't allow people to put the payee key onto an online server)
        if (payoutDest == CTxDestination(WitnessV0KeyHash(dmn->pdmnState->keyIDOwner)) || payoutDest == CTxDestination(WitnessV0KeyHash(ptx.keyIDVoting))) {
            return FormatSyscoinErrorMessage(state, "bad-protx-payee-reuse", fJustCheck);
        }

        Coin coin;
        if (!view.GetCoin(dmn->collateralOutpoint, coin) || coin.IsSpent()) {
            // this should never happen (there would be no dmn otherwise)
            return FormatSyscoinErrorMessage(state, "bad-protx-collateral", fJustCheck);
        }

        // don't allow reuse of collateral key for other keys (don't allow people to put the collateral key onto an online server)
        CTxDestination collateralTxDest;
        if (!ExtractDestination(coin.out.scriptPubKey, collateralTxDest)) {
            return FormatSyscoinErrorMessage(state, "bad-protx-collateral-dest", fJustCheck);
        }
        if (collateralTxDest == CTxDestination(WitnessV0KeyHash(dmn->pdmnState->keyIDOwner)) || collateralTxDest == CTxDestination(WitnessV0KeyHash(ptx.keyIDVoting))) {
            return FormatSyscoinErrorMessage(state, "bad-protx-collateral-reuse", fJustCheck);
        }

        if (ptx.nVersion <= CProUpRegTx::BASIC_BLS_VERSION &&
            mnList.HasUniqueProperty(ptx.pubKeyOperator)) {
            auto otherDmn = mnList.GetUniquePropertyMN(ptx.pubKeyOperator);
            if (ptx.proTxHash != otherDmn->proTxHash) {
                return FormatSyscoinErrorMessage(state, "bad-protx-dup-key", fJustCheck);
            }
        }
 

        if (!CheckInputsHash(tx, ptx, state, fJustCheck)) {
            // pass the state returned by the function above
            return false;
        }
        if (check_sigs && !CheckHashSig(ptx, dmn->pdmnState->keyIDOwner, state, fJustCheck)) {
            // pass the state returned by the function above
            return false;
        }
    }

    return true;
}

bool CheckProUpRevTx(const CTransaction& tx, const CBlockIndex* pindexPrev, TxValidationState& state, bool fJustCheck, bool check_sigs, SpecialTxValidationContext validation_context)
{
    if (tx.nVersion != SYSCOIN_TX_VERSION_MN_UPDATE_REVOKE) {
        return FormatSyscoinErrorMessage(state, "bad-protx-type", fJustCheck);
    }

    const ProviderAuthEra auth_era = GetProviderAuthEra(pindexPrev);
    CProUpRevTx ptx;
    if (!GetProviderPayload(tx, auth_era, ptx)) {
        return FormatSyscoinErrorMessage(state, "bad-protx-payload", fJustCheck);
    }
    const bool basic_scheme = pindexPrev != nullptr &&
        llmq::CLLMQUtils::IsV19Active(pindexPrev->nHeight);
    if (!CheckProviderVersion(ptx.nVersion,
                              CProUpRevTx::GetVersion(basic_scheme),
                              CProUpRevTx::PQ_VERSION, auth_era, state) ||
        !ptx.IsTriviallyValid(state, basic_scheme)) {
        return FormatSyscoinErrorMessage(state, state.GetRejectReason(), fJustCheck);
    }

    if (pindexPrev) {
        auto mnList = deterministicMNManager->GetListForBlock(pindexPrev);
        auto dmn = mnList.GetMN(ptx.proTxHash);
        if (!dmn)
            return FormatSyscoinErrorMessage(state, "bad-protx-hash", fJustCheck);

        if (!CheckInputsHash(tx, ptx, state, fJustCheck)) {
            // pass the state returned by the function above
            return false;
        }
        const bool registry_owns_authorization{
            auth_era == ProviderAuthEra::POST_QUANTUM &&
            validation_context ==
                SpecialTxValidationContext::PQ_REGISTRY_PRECHECK};
        if (!registry_owns_authorization &&
            ShouldCheckProviderAuthorization(
                auth_era, check_sigs, validation_context)) {
            if (auth_era == ProviderAuthEra::POST_QUANTUM) {
                llmq::pq::PQRegistryReadView registry_snapshot;
                const llmq::pq::OperatorKeyState* operator_state{nullptr};
                if (!GetParentOperatorKey(pindexPrev, ptx.proTxHash,
                                          operator_state, registry_snapshot) ||
                    ptx.globalKeyVersion != operator_state->global_key.key_version) {
                    return FormatSyscoinErrorMessage(
                        state, "bad-protx-pq-key", fJustCheck);
                }
                llmq::pq::ProviderRevokeAuthorization authorization;
                authorization.payload_version = ptx.nVersion;
                authorization.pro_tx_hash = ptx.proTxHash;
                authorization.global_key_version = ptx.globalKeyVersion;
                authorization.reason = ptx.nReason;
                authorization.transaction_inputs_hash = ptx.inputsHash;
                if (!llmq::pq::VerifyProviderRevokeAuthorization(
                        Params().GetConsensus().hashGenesisBlock,
                        operator_state->global_key, authorization, ptx.pqSig)) {
                    return FormatSyscoinErrorMessage(
                        state, "bad-protx-pq-sig", fJustCheck);
                }
            }
        }
    }

    return true;
}

std::string CProRegTx::MakeSignString() const
{
    std::string s;

    // We only include the important stuff in the string form...

    CTxDestination destPayout;
    std::string strPayout;
    if (ExtractDestination(scriptPayout, destPayout)) {
        strPayout = EncodeDestination(destPayout);
    } else {
        strPayout = HexStr(scriptPayout);
    }

    s += strPayout + "|";
    s += strprintf("%d", nOperatorReward) + "|";
    s += EncodeDestination(WitnessV0KeyHash(keyIDOwner)) + "|";
    s += EncodeDestination(WitnessV0KeyHash(keyIDVoting)) + "|";

    // ... and also the full hash of the payload as a protection against malleability and replays
    s += ::SerializeHash(*this).ToString();

    return s;
}

std::string CProRegTx::ToString() const
{
    CTxDestination dest;
    std::string payee = "unknown";
    if (ExtractDestination(scriptPayout, dest)) {
        payee = EncodeDestination(dest);
    }

    return strprintf("CProRegTx(nVersion=%d, collateralOutpoint=%s, addr=%s, nOperatorReward=%f, ownerAddress=%s, pubKeyOperator=%s, votingAddress=%s, scriptPayout=%s)",
    nVersion, collateralOutpoint.ToStringShort(), addr.ToStringAddr(), (double)nOperatorReward / 100, EncodeDestination(WitnessV0KeyHash(keyIDOwner)), pubKeyOperator.ToString(), EncodeDestination(WitnessV0KeyHash(keyIDVoting)), payee);
}

bool CProUpServTx::IsTriviallyValid(TxValidationState& state, bool) const
{
    if (nVersion == 0 || nVersion > PQ_VERSION) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-version");
    }
    if (nVersion == PQ_VERSION &&
        (globalKeyVersion == 0 || !HasNonZeroByte(pqSig))) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-protx-pq-auth");
    }
    return true;
}

std::string CProUpServTx::ToString() const
{
    CTxDestination dest;
    std::string payee = "unknown";
    if (ExtractDestination(scriptOperatorPayout, dest)) {
        payee = EncodeDestination(dest);
    }

    return strprintf("CProUpServTx(nVersion=%d, proTxHash=%s, addr=%s, operatorPayoutAddress=%s, nevmAddress=%s)",
        nVersion, proTxHash.ToString(), addr.ToStringAddr(), payee, vchNEVMAddress.empty()? "" : "0x"+HexStr(vchNEVMAddress));
}

bool CProUpRegTx::IsTriviallyValid(TxValidationState& state, bool) const
{
    if (nVersion == 0 || nVersion > PQ_VERSION) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-version");
    }
    if (nMode != 0) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-mode");
    }

    if (keyIDVoting.IsNull() ||
        (nVersion <= BASIC_BLS_VERSION && !pubKeyOperator.IsValid()) ||
        (nVersion == PQ_VERSION && !pubKeyOperator.IsNull())) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-key-null");
    }
    return true;
}

std::string CProUpRegTx::ToString() const
{
    CTxDestination dest;
    std::string payee = "unknown";
    if (ExtractDestination(scriptPayout, dest)) {
        payee = EncodeDestination(dest);
    }

    return strprintf("CProUpRegTx(nVersion=%d, proTxHash=%s, pubKeyOperator=%s, votingAddress=%s, payoutAddress=%s)",
        nVersion, proTxHash.ToString(), pubKeyOperator.ToString(), EncodeDestination(WitnessV0KeyHash(keyIDVoting)), payee);
}

bool CProUpRevTx::IsTriviallyValid(TxValidationState& state, bool) const
{
    if (nVersion == 0 || nVersion > PQ_VERSION) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-version");
    }

    // nReason < CProUpRevTx::REASON_NOT_SPECIFIED is always `false` since
    // nReason is unsigned and CProUpRevTx::REASON_NOT_SPECIFIED == 0
    if (nReason > CProUpRevTx::REASON_LAST) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-protx-reason");
    }
    if (nVersion == PQ_VERSION &&
        (globalKeyVersion == 0 || !HasNonZeroByte(pqSig))) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS,
                             "bad-protx-pq-auth");
    }
    return true;
}

std::string CProUpRevTx::ToString() const
{
    return strprintf("CProUpRevTx(nVersion=%d, proTxHash=%s, nReason=%d)",
        nVersion, proTxHash.ToString(), nReason);
}
