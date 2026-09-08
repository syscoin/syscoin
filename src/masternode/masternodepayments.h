// Copyright (c) 2014-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_MASTERNODE_MASTERNODEPAYMENTS_H
#define SYSCOIN_MASTERNODE_MASTERNODEPAYMENTS_H



class CMasternodePayments;
class CChain;
class CBlockIndex;

enum class MasternodePaymentStatus {
    PAYEE,
    LEGACY_NO_PAYEE,
    PQ_NO_PAYEE,
    UNAVAILABLE,
};

CAmount GetMinerPayment(MasternodePaymentStatus status, const CAmount& blockReward, const CAmount& fees);
CAmount GetBlockPaymentValueLimit(MasternodePaymentStatus status, const CAmount& blockReward, const CAmount& fees, const CAmount& mnSeniority, const CAmount& mnFloorDiff);
// Reuse exact governance provenance only for the same committed block payments.
bool HasValidatedSuperblockPayments(const CBlock& block, const CBlockIndex& index);
/// TODO: all 4 functions do not belong here really, they should be refactored/moved somewhere (main.cpp ?)
bool IsBlockValueValid(const CBlock& block, const CBlockIndex* pindex, const CAmount &blockReward, std::string& strErrorRet, bool fJustCheck, bool check_superblock, bool* exact_superblock_validation = nullptr, const std::vector<bool>* matched_outputs = nullptr, bool* governance_state_available = nullptr);
bool IsBlockPayeeValid(CChain& activeChain, const CTransaction& txNew, int nBlockHeight, const CAmount &blockReward, const CAmount &fees, CAmount& nMNSeniorityRet, CAmount &nMNFloorDiffRet, std::vector<bool>* matched_outputs = nullptr, MasternodePaymentStatus* payment_status = nullptr);
bool FillBlockPayments(CChain& activeChain, CMutableTransaction& txNew, int nBlockHeight, const CAmount &blockReward, const CAmount &fees, std::vector<CTxOut>& voutMasternodePaymentsRet, std::vector<CTxOut>& voutSuperblockPaymentsRet);

extern CMasternodePayments mnpayments;

//
// Masternode Payments Class
// Keeps track of who should get paid for which blocks
//

class CMasternodePayments
{
public:
    static MasternodePaymentStatus GetBlockTxOuts(CChain& activeChain, int nBlockHeight, const CAmount &blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet, const CAmount &nHalfFee, CAmount& nMNSeniorityRet, CAmount &nMNFloorDiffRet, int& nCollateralHeight);
    static bool IsTransactionValid(CChain& activeChain, const CTransaction& txNew, int nBlockHeight, const CAmount &blockReward, const CAmount& nHalfFee, CAmount& nMNSeniorityRet, CAmount &nMNFloorDiffRet, MasternodePaymentStatus& payment_status, std::vector<bool>* matched_outputs = nullptr);
    static MasternodePaymentStatus GetMasternodeTxOuts(CChain& activeChain, int nBlockHeight, const CAmount &blockReward, std::vector<CTxOut>& voutMasternodePaymentsRet, const CAmount &nHalfFee);
};

#endif // SYSCOIN_MASTERNODE_MASTERNODEPAYMENTS_H
