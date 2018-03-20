#include "transactionrecord.h"

#include "wallet.h"
#include "base58.h"

using namespace std;

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction(const CWalletTx &wtx)
{
    if (wtx.IsCoinBase())
    {
        // Ensures we show generated coins / mined transactions at depth 1
        if (!wtx.IsInMainChain())
        {
            return false;
        }
    }
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const CWallet *wallet, const CWalletTx &wtx)
{
    QList<TransactionRecord> parts;
    int64 nTime = wtx.GetTxTime();
    int64 nCredit = wtx.GetCredit(true);
    int64 nDebit = wtx.GetDebit();
    int64 nNet = nCredit - nDebit;
    uint256 hash = wtx.GetHash();
    std::map<std::string, std::string> mapValue = wtx.mapValue;

    if (nNet > 0 || wtx.IsCoinBase())
    {
        //
        // Credit
        //
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            if(wallet->IsMine(txout))
            {
                TransactionRecord sub(hash, nTime);
                CTxDestination address;
                sub.idx = parts.size(); // sequence number
                sub.credit = txout.nValue;
                if (ExtractDestination(txout.scriptPubKey, address) && IsMine(*wallet, address))
                {
                    // Received by Bitcoin Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.IsCoinBase())
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }

                parts.append(sub);
            }
        }
    }
    else
    {   
        //Check if tx is a valid alias (name alias for the moment).
        vector<vector<unsigned char> > vvchArgs;
        int op, nOut;
        if (wtx.nVersion == SYSCOIN_TX_VERSION) {
            bool o = DecodeAliasTx(wtx, op, nOut, vvchArgs, -1);
            if (IsOfferOp(op)) {
                DecodeOfferTx(wtx, op, nOut, vvchArgs, -1);
            } else if (IsCertOp(op)) {
                DecodeCertTx(wtx, op, nOut, vvchArgs, -1);
            }
        }

        bool fAllFromMe = true;
        BOOST_FOREACH(const CTxIn& txin, wtx.vin)
            fAllFromMe = fAllFromMe && wallet->IsMine(txin);

        bool fAllToMe = true;
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            fAllToMe = fAllToMe && wallet->IsMine(txout);

        if (fAllFromMe && fAllToMe)
        {
            // Payment to self
            int64 nChange = wtx.GetChange();

            parts.append(TransactionRecord(hash, nTime, TransactionRecord::SendToSelf, "",
                            -(nDebit - nChange), nCredit - nChange));
        }
        else if (fAllFromMe)
        {
            //
            // Debit
            //
            int64 nTxFee = nDebit - wtx.GetValueOut();

            for (unsigned int nOut = 0; nOut < wtx.vout.size(); nOut++)
            {
                const CTxOut& txout = wtx.vout[nOut];
                TransactionRecord sub(hash, nTime);
                sub.idx = parts.size();

                if(wallet->IsMine(txout))
                {
                    // Ignore parts sent to self, as this is usually the change
                    // from a transaction sent back to our own address.
                    continue;
                }

                CTxDestination address;
                if (ExtractDestination(txout.scriptPubKey, address))
                {
                    // Sent to Bitcoin Address
                    sub.type = TransactionRecord::SendToAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                }
                else
                {
                    if (op) {
                        vector<unsigned char> vchName;
                        switch(op)
                        {
                        case OP_ALIAS_NEW:
                            sub.type = TransactionRecord::AliasNew;
                            sub.address = mapValue["to"];
                            break;
                        case OP_OFFER_NEW:
                            sub.type = TransactionRecord::OfferNew;
                            sub.address = mapValue["to"];
                            break;
                        case OP_OFFER_ACCEPT:
                            sub.type = TransactionRecord::OfferAccept;
                            vchName = vvchArgs[0];
                            sub.address = stringFromVch(vchName);
                            break;
                        case OP_CERTISSUER_NEW:
                            sub.type = TransactionRecord::CertIssuerNew;
                            sub.address = mapValue["to"];
                            break;
                        case OP_CERT_NEW:
                            sub.type = TransactionRecord::CertNew;
                            vchName = vvchArgs[0];
                            sub.address = stringFromVch(vchName);
                            break;
                        default:
                            sub.type = TransactionRecord::SendToOther;
                            sub.address = mapValue["to"];
                        }
                        //if (op == OP_ALIAS_NEW) {
                        //    sub.type = TransactionRecord::AliasNew;
                            //sub.address = stringFromVch(vchName);
                        //    sub.address = mapValue["to"];
                        //}
                    } else {
                        // Sent to IP, or other non-address transaction like OP_EVAL
                        sub.type = TransactionRecord::SendToOther;
                        sub.address = mapValue["to"];
                    }
                }

                int64 nValue = txout.nValue;
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }
        }
        else
        {
            //
            // Mixed debit transaction, can't break down payees
            //

            if (op){
                TransactionRecord sub(hash, nTime);
                //vector<unsigned char> &vchName = vvchArgs[0];
                vector<unsigned char> vchName;
                std::string strGUID;
                switch(op)
                {
                case OP_ALIAS_ACTIVATE:
                    sub.type = (!wtx.data.size()) ? TransactionRecord::AliasActivate : TransactionRecord::DataActivate;
                    vchName = vvchArgs[0];
                    break;
                case OP_ALIAS_UPDATE:
                    vchName = vvchArgs[0];
                    if (!wtx.data.size()) {
                        sub.type = (IsAliasMine(wtx)) ? TransactionRecord::AliasUpdate : TransactionRecord::AliasTransfer;
                    }
                    else {
                        sub.type = (IsAliasMine(wtx)) ? TransactionRecord::DataUpdate : TransactionRecord::DataTransfer;
                    }
                    break;
                case OP_OFFER_ACTIVATE:
                    vchName = vvchArgs[0];
                    sub.type = TransactionRecord::OfferActivate;
                    break;
                case OP_OFFER_UPDATE:
                    vchName = vvchArgs[0];
                    sub.type = TransactionRecord::OfferUpdate;
                    break;
                case OP_OFFER_PAY:
                    vchName = vvchArgs[0];
                    sub.type = TransactionRecord::OfferPay;
                    break;
                case OP_CERTISSUER_ACTIVATE:
                    strGUID += " ("; strGUID += stringFromVch(vvchArgs[0]); strGUID += ")";
                    vchName = vvchArgs[2];
                    sub.type = TransactionRecord::CertIssuerActivate;
                    break;
                case OP_CERTISSUER_UPDATE:
                    strGUID += " ("; strGUID += stringFromVch(vvchArgs[0]); strGUID += ")";
                    vchName = vvchArgs[1];
                    sub.type = TransactionRecord::CertIssuerUpdate;
                    break;
                case OP_CERT_TRANSFER:
                    vchName = vvchArgs[0];
                    sub.type = TransactionRecord::CertTransfer;
                    break;
                }
                sub.address = stringFromVch(vchName) + strGUID;
                sub.debit = nNet;
                parts.append(sub);
            } else {

                parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
            }
        }
    }

    return parts;
}

void TransactionRecord::updateStatus(const CWalletTx &wtx)
{
    // Determine transaction status

    // Find the block the tx is in
    CBlockIndex* pindex = NULL;
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(wtx.hashBlock);
    if (mi != mapBlockIndex.end())
        pindex = (*mi).second;

    // Sort order, unrecorded transactions sort to the top
    status.sortKey = strprintf("%010d-%01d-%010u-%03d",
        (pindex ? pindex->nHeight : std::numeric_limits<int>::max()),
        (wtx.IsCoinBase() ? 1 : 0),
        wtx.nTimeReceived,
        idx);
    status.confirmed = wtx.IsConfirmed();
    status.depth = wtx.GetDepthInMainChain();
    status.cur_num_blocks = nBestHeight;

    if (!wtx.IsFinal())
    {
        if (wtx.nLockTime < LOCKTIME_THRESHOLD)
        {
            status.status = TransactionStatus::OpenUntilBlock;
            status.open_for = wtx.nLockTime - nBestHeight + 1;
        }
        else
        {
            status.status = TransactionStatus::OpenUntilDate;
            status.open_for = wtx.nLockTime;
        }
    }
    else
    {
        if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
        {
            status.status = TransactionStatus::Offline;
        }
        else if (status.depth < NumConfirmations)
        {
            status.status = TransactionStatus::Unconfirmed;
        }
        else
        {
            status.status = TransactionStatus::HaveConfirmations;
        }
    }

    // For generated transactions, determine maturity
    if(type == TransactionRecord::Generated)
    {
        int64 nCredit = wtx.GetCredit(true);
        if (nCredit == 0)
        {
            status.maturity = TransactionStatus::Immature;

            if (wtx.IsInMainChain())
            {
                status.matures_in = wtx.GetBlocksToMaturity();

                // Check if the block was requested by anyone
                if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
                    status.maturity = TransactionStatus::MaturesWarning;
            }
            else
            {
                status.maturity = TransactionStatus::NotAccepted;
            }
        }
        else
        {
            status.maturity = TransactionStatus::Mature;
        }
    }
}

bool TransactionRecord::statusUpdateNeeded()
{
    return status.cur_num_blocks != nBestHeight;
}

std::string TransactionRecord::getTxID()
{
    return hash.ToString() + strprintf("-%03d", idx);
}

