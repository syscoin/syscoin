// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsbase.h>
#include <common/args.h>
#include <consensus/params.h>
#include <deploymentinfo.h>
#include <logging.h>
#include <tinyformat.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <assert.h>
#include <algorithm> // SYSCOIN: complete PQ anchor argument groups.
#include <array> // SYSCOIN: fixed PQ anchor argument groups.
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

// SYSCOIN: begin PQ activation-anchor argument parsing.
namespace {

constexpr std::array<const char*, 4> PQ_LEGACY_ANCHOR_ARGS{
    "-pqlegacyanchorheight",
    "-pqlegacyanchorblockhash",
    "-pqlegacydmnstatehash",
    "-pqlegacypqregistrystatehash",
};

// SYSCOIN: This release-updatable receipt-crypto assumption must never be
// inferred from or overwrite the immutable PQ migration anchor.
constexpr std::array<const char*, 6> PQ_BTCC_RECEIPT_ANCHOR_ARGS{
    "-pqbtccreceiptanchorheight",
    "-pqbtccreceiptanchorblockhash",
    "-pqbtccreceiptanchorcursorheight",
    "-pqbtccreceiptanchorcursorsyshash",
    "-pqbtccreceiptanchorcursorbtchash",
    "-pqbtccreceiptanchorstatehash",
};

bool HasPQLegacyAnchorArg(const ArgsManager& args)
{
    return std::any_of(PQ_LEGACY_ANCHOR_ARGS.begin(),
                       PQ_LEGACY_ANCHOR_ARGS.end(),
                       [&](const char* name) { return args.IsArgSet(name); });
}

bool HasPQBTCCReceiptAnchorArg(const ArgsManager& args)
{
    return std::any_of(PQ_BTCC_RECEIPT_ANCHOR_ARGS.begin(),
                       PQ_BTCC_RECEIPT_ANCHOR_ARGS.end(),
                       [&](const char* name) { return args.IsArgSet(name); });
}

std::string GetSinglePQLegacyAnchorArg(const ArgsManager& args,
                                       const char* name)
{
    const auto values = args.GetArgs(name);
    if (values.size() != 1) {
        throw std::runtime_error(strprintf(
            "%s must be specified exactly once", name));
    }
    return values.front();
}

uint256 ParseNonNullPQLegacyAnchorHash(const ArgsManager& args,
                                       const char* name)
{
    const std::string value = GetSinglePQLegacyAnchorArg(args, name);
    if (value.size() != 64 || !IsHex(value)) {
        throw std::runtime_error(strprintf(
            "%s must be exactly 64 hexadecimal characters", name));
    }
    uint256 hash;
    hash.SetHex(value);
    if (hash.IsNull()) {
        throw std::runtime_error(strprintf("%s must be non-zero", name));
    }
    return hash;
}

uint256 ParsePQBTCCReceiptAnchorHash(const ArgsManager& args,
                                     const char* name,
                                     bool require_nonzero)
{
    const std::string value = GetSinglePQLegacyAnchorArg(args, name);
    if (value.size() != 64 || !IsHex(value)) {
        throw std::runtime_error(strprintf(
            "%s must be exactly 64 hexadecimal characters", name));
    }
    uint256 hash;
    hash.SetHex(value);
    if (require_nonzero && hash.IsNull()) {
        throw std::runtime_error(strprintf("%s must be non-zero", name));
    }
    return hash;
}

} // namespace
// SYSCOIN: end PQ activation-anchor argument parsing.

void ReadSigNetArgs(const ArgsManager& args, CChainParams::SigNetOptions& options)
{
    if (args.IsArgSet("-signetseednode")) {
        options.seeds.emplace(args.GetArgs("-signetseednode"));
    }
    if (args.IsArgSet("-signetchallenge")) {
        const auto signet_challenge = args.GetArgs("-signetchallenge");
        if (signet_challenge.size() != 1) {
            throw std::runtime_error("-signetchallenge cannot be multiple values.");
        }
        const auto val{TryParseHex<uint8_t>(signet_challenge[0])};
        if (!val) {
            throw std::runtime_error(strprintf("-signetchallenge must be hex, not '%s'.", signet_challenge[0]));
        }
        options.challenge.emplace(*val);
    }
}
void ReadRegTestArgs(const ArgsManager& args, CChainParams::RegTestOptions& options)
{
    if (auto value = args.GetBoolArg("-fastprune")) options.fastprune = *value;

    for (const std::string& arg : args.GetArgs("-testactivationheight")) {
        const auto found{arg.find('@')};
        if (found == std::string::npos) {
            throw std::runtime_error(strprintf("Invalid format (%s) for -testactivationheight=name@height.", arg));
        }

        const auto value{arg.substr(found + 1)};
        int32_t height;
        if (!ParseInt32(value, &height) || height < 0 || height >= std::numeric_limits<int>::max()) {
            throw std::runtime_error(strprintf("Invalid height value (%s) for -testactivationheight=name@height.", arg));
        }

        const auto deployment_name{arg.substr(0, found)};
        if (const auto buried_deployment = GetBuriedDeployment(deployment_name)) {
            options.activation_heights[*buried_deployment] = height;
        } else {
            throw std::runtime_error(strprintf("Invalid name (%s) for -testactivationheight=name@height.", arg));
        }
    }
    // SYSCOIN
    if (args.IsArgSet("-mncollateral")) {
        uint32_t collateral = args.GetIntArg("-mncollateral", DEFAULT_MN_COLLATERAL_REQUIRED);
        nMNCollateralRequired = collateral*COIN;
    }
    if (args.IsArgSet("-dip3params")) {
        std::string strDIP3Params = args.GetArg("-dip3params", "");
        std::vector<std::string> vDIP3Params = SplitString(strDIP3Params, ':');
        if (vDIP3Params.size() != 2) {
            throw std::runtime_error("DIP3 parameters malformed, expecting DIP3ActivationHeight:DIP3EnforcementHeight");
        }
        if (!ParseInt32(vDIP3Params[0], &options.dip3startblock)) {
            throw std::runtime_error(strprintf("Invalid nDIP3ActivationHeight (%s)", vDIP3Params[0]));
        }
        if (!ParseInt32(vDIP3Params[1], &options.dip3enforcement)) {
            throw std::runtime_error(strprintf("Invalid nDIP3EnforcementHeight (%s)", vDIP3Params[1]));
        }
    }
    if (args.IsArgSet("-dip19params")) {
        std::string strDIP19Params = args.GetArg("-dip19params", "");
        if (!ParseInt32(strDIP19Params, &options.v19startblock)) {
            throw std::runtime_error(strprintf("Invalid nDIP19ActivationHeight (%s)", strDIP19Params));
        }
    }
    if (args.IsArgSet("-nevmstartheight")) {
        options.nevmstartblock = args.GetIntArg("-nevmstartheight", 2050);
    }
    if (args.IsArgSet("-clreceiptstartheight")) {
        options.clreceiptstartblock = args.GetIntArg("-clreceiptstartheight", std::numeric_limits<int>::max());
    }
    // SYSCOIN: begin regtest PQ activation and receipt policy.
    if (HasPQLegacyAnchorArg(args)) {
        if (!std::all_of(PQ_LEGACY_ANCHOR_ARGS.begin(),
                         PQ_LEGACY_ANCHOR_ARGS.end(),
                         [&](const char* name) { return args.IsArgSet(name); })) {
            throw std::runtime_error(
                "The four PQ legacy anchor arguments must be specified together");
        }
        const std::string height_value = GetSinglePQLegacyAnchorArg(
            args, PQ_LEGACY_ANCHOR_ARGS[0]);
        int32_t height;
        if (!ParseInt32(height_value, &height) || height < 0 ||
            height == std::numeric_limits<int32_t>::max()) {
            throw std::runtime_error(strprintf(
                "%s must be a non-negative 32-bit height below INT_MAX",
                PQ_LEGACY_ANCHOR_ARGS[0]));
        }
        options.pqlegacyanchor =
            CChainParams::RegTestOptions::PQLegacyAnchorOptions{
                height,
                ParseNonNullPQLegacyAnchorHash(
                    args, PQ_LEGACY_ANCHOR_ARGS[1]),
                ParseNonNullPQLegacyAnchorHash(
                    args, PQ_LEGACY_ANCHOR_ARGS[2]),
                ParseNonNullPQLegacyAnchorHash(
                    args, PQ_LEGACY_ANCHOR_ARGS[3]),
            };
    }
    // SYSCOIN: Regtest can exercise a release-pinned historical receipt
    // boundary, but partial records are rejected rather than default-filled.
    if (HasPQBTCCReceiptAnchorArg(args)) {
        if (!std::all_of(PQ_BTCC_RECEIPT_ANCHOR_ARGS.begin(),
                         PQ_BTCC_RECEIPT_ANCHOR_ARGS.end(),
                         [&](const char* name) { return args.IsArgSet(name); })) {
            throw std::runtime_error(
                "The six PQ BTCC receipt anchor arguments must be specified together");
        }
        int32_t height;
        const std::string height_value = GetSinglePQLegacyAnchorArg(
            args, PQ_BTCC_RECEIPT_ANCHOR_ARGS[0]);
        if (!ParseInt32(height_value, &height) || height < 0 ||
            height == std::numeric_limits<int32_t>::max()) {
            throw std::runtime_error(strprintf(
                "%s must be a non-negative 32-bit height below INT_MAX",
                PQ_BTCC_RECEIPT_ANCHOR_ARGS[0]));
        }
        int32_t cursor_height;
        const std::string cursor_height_value = GetSinglePQLegacyAnchorArg(
            args, PQ_BTCC_RECEIPT_ANCHOR_ARGS[2]);
        if (!ParseInt32(cursor_height_value, &cursor_height) ||
            cursor_height < -1 || cursor_height > height) {
            throw std::runtime_error(strprintf(
                "%s must be -1 or a height not above the receipt anchor",
                PQ_BTCC_RECEIPT_ANCHOR_ARGS[2]));
        }
        const bool has_cursor{cursor_height >= 0};
        const uint256 cursor_sys_hash{ParsePQBTCCReceiptAnchorHash(
            args, PQ_BTCC_RECEIPT_ANCHOR_ARGS[3], has_cursor)};
        const uint256 cursor_btc_hash{ParsePQBTCCReceiptAnchorHash(
            args, PQ_BTCC_RECEIPT_ANCHOR_ARGS[4], has_cursor)};
        const uint256 receipt_state_hash{ParsePQBTCCReceiptAnchorHash(
            args, PQ_BTCC_RECEIPT_ANCHOR_ARGS[5], has_cursor)};
        if (!has_cursor && (!cursor_sys_hash.IsNull() ||
                            !cursor_btc_hash.IsNull() ||
                            !receipt_state_hash.IsNull())) {
            throw std::runtime_error(
                "A null PQ BTCC receipt-anchor cursor requires three zero hashes");
        }
        options.pqbtccreceiptanchor =
            CChainParams::RegTestOptions::PQBTCCReceiptAnchorOptions{
                height,
                ParsePQBTCCReceiptAnchorHash(
                    args, PQ_BTCC_RECEIPT_ANCHOR_ARGS[1], true),
                cursor_height,
                cursor_sys_hash,
                cursor_btc_hash,
                receipt_state_hash,
            };
    }
    options.pqpreparationheight = args.GetIntArg(
        "-pqpreparationheight", std::numeric_limits<int>::max());
    options.pqchainlockepochorigin = args.GetIntArg(
        "-pqchainlockepochorigin", std::numeric_limits<int>::max());
    options.pqregistrationcutoffblocks = args.GetIntArg(
        "-pqregistrationcutoffblocks", 0);
    // SYSCOIN: PQ roster snapshot policy is independent of per-key registration.
    options.pqrostersnapshotlag = args.GetIntArg("-pqrostersnapshotlag", 288);
    options.pqfuturehorizonepochs = args.GetIntArg("-pqfuturehorizonepochs", 0);
    options.pqbtcccandidateorigin = args.GetIntArg(
        "-pqbtcccandidateorigin", std::numeric_limits<int>::max());
    options.pqbtccnevminjectionlag = args.GetIntArg("-pqbtccnevminjectionlag", 10);
    // SYSCOIN: end regtest PQ activation and receipt policy.
    if (args.IsArgSet("-bridgev2startheight")) {
        options.bridgev2startblock = args.GetIntArg("-bridgev2startheight", std::numeric_limits<int>::max());
    }
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams = SplitString(strDeployment, ':');
        if (vDeploymentParams.size() < 3 || 4 < vDeploymentParams.size()) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end[:min_activation_height]");
        }
        CChainParams::VersionBitsParameters vbparams{};
        if (!ParseInt64(vDeploymentParams[1], &vbparams.start_time)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &vbparams.timeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        if (vDeploymentParams.size() >= 4) {
            if (!ParseInt32(vDeploymentParams[3], &vbparams.min_activation_height)) {
                throw std::runtime_error(strprintf("Invalid min_activation_height (%s)", vDeploymentParams[3]));
            }
        } else {
            vbparams.min_activation_height = 0;
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                options.version_bits_parameters[Consensus::DeploymentPos(j)] = vbparams;
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld, min_activation_height=%d\n", vDeploymentParams[0], vbparams.start_time, vbparams.timeout, vbparams.min_activation_height);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}
// SYSCOIN
void ReadMainNetArgs(const ArgsManager& args, CChainParams::MainNetOptions& options)
{
    if (args.IsArgSet("-hrp")) {
        options.bech32_hrp = args.GetArg("-hrp", "");
    }
}
static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const ArgsManager& args, const ChainType chain)
{
    // SYSCOIN: Production networks may not override release-pinned PQ anchors.
    if (chain != ChainType::REGTEST &&
        (HasPQLegacyAnchorArg(args) || HasPQBTCCReceiptAnchorArg(args))) {
        throw std::runtime_error(
            "PQ anchor overrides are valid only on regtest");
    }
    switch (chain) {
    // SYSCOIN
    case ChainType::MAIN: {
        auto opts = CChainParams::MainNetOptions{};
        ReadMainNetArgs(args, opts);
        return CChainParams::Main(opts);
    }
    case ChainType::TESTNET:
        return CChainParams::TestNet();
    case ChainType::SIGNET: {
        auto opts = CChainParams::SigNetOptions{};
        ReadSigNetArgs(args, opts);
        return CChainParams::SigNet(opts);
    }
    case ChainType::REGTEST: {
        auto opts = CChainParams::RegTestOptions{};
        ReadRegTestArgs(args, opts);
        return CChainParams::RegTest(opts);
    }
    }
    assert(false);
}

void SelectParams(const ChainType chain)
{
    SelectBaseParams(chain);
    globalChainParams = CreateChainParams(gArgs, chain);
}
