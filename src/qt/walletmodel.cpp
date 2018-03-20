#include "walletmodel.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include "aliastablemodel.h"
#include "offertablemodel.h"
#include "certtablemodel.h"
#include "transactiontablemodel.h"

#include "ui_interface.h"
#include "wallet.h"
#include "walletdb.h" // for BackupWallet
#include "base58.h"

#include <QSet>
#include <QTimer>

class COfferDB;
extern COfferDB *pofferdb;
int GetOfferExpirationDepth(int nHeight);

class CCertDB;
extern CCertDB *pcertdb;
int GetCertExpirationDepth(int nHeight);

class CAliasDB;
extern CAliasDB *paliasdb;

class COfferAccept;

WalletModel::WalletModel(CWallet *wallet, OptionsModel *optionsModel, QObject *parent) :
    QObject(parent),
    wallet(wallet),
    optionsModel(optionsModel),
    addressTableModel(0),
    transactionTableModel(0),
    aliasTableModelMine(0),
	aliasTableModelAll(0),
    offerTableModelMine(0),
	offerTableModelAll(0),
	certIssuerTableModel(0),
    cachedBalance(0),
    cachedUnconfirmedBalance(0),
    cachedImmatureBalance(0),
    cachedNumTransactions(0),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0)
{
    addressTableModel = new AddressTableModel(wallet, this);
  
    //do not load SYS service data this way at the moment, need more efficient load mechanism.
	/*offerTableModelAll = new OfferTableModel(wallet, this, AllOffers);
	offerTableModelMine = new OfferTableModel(wallet, this, MyOffers);
    certIssuerTableModel = new CertIssuerTableModel(wallet, this);*/

    transactionTableModel = new TransactionTableModel(wallet, this);
    aliasTableModelMine = new AliasTableModel(wallet, this, MyAlias);
	aliasTableModelAll = new AliasTableModel(wallet, this, AllAlias);
    // This timer will be fired repeatedly to update the balance
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollBalanceChanged()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

qint64 WalletModel::getBalance(const CCoinControl *coinControl) const
{
    if (coinControl)
    {
        int64 nBalance = 0;
        std::vector<COutput> vCoins;
        wallet->AvailableCoins(vCoins, true, coinControl);
        BOOST_FOREACH(const COutput& out, vCoins)
            nBalance += out.tx->vout[out.i].nValue;   
        
        return nBalance;
    }
    
    return wallet->GetBalance();
}

qint64 WalletModel::getUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedBalance();
}

qint64 WalletModel::getImmatureBalance() const
{
    return wallet->GetImmatureBalance();
}

int WalletModel::getNumTransactions() const
{
    int numTransactions = 0;
    {
        LOCK(wallet->cs_wallet);
        // the size of mapWallet contains the number of unique transaction IDs
        // (e.g. payments to yourself generate 2 transactions, but both share the same transaction ID)
        numTransactions = wallet->mapWallet.size();
    }
    return numTransactions;
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus)
        emit encryptionStatusChanged(newEncryptionStatus);
}

void WalletModel::pollBalanceChanged()
{
    if(nBestHeight != cachedNumBlocks)
    {
        // Balance and number of transactions might have changed
        cachedNumBlocks = nBestHeight;
        checkBalanceChanged();
    }
}

void WalletModel::checkBalanceChanged()
{
    qint64 newBalance = getBalance();
    qint64 newUnconfirmedBalance = getUnconfirmedBalance();
    qint64 newImmatureBalance = getImmatureBalance();

    if(cachedBalance != newBalance || cachedUnconfirmedBalance != newUnconfirmedBalance || cachedImmatureBalance != newImmatureBalance)
    {
        cachedBalance = newBalance;
        cachedUnconfirmedBalance = newUnconfirmedBalance;
        cachedImmatureBalance = newImmatureBalance;
        emit balanceChanged(newBalance, newUnconfirmedBalance, newImmatureBalance);
    }
}

void WalletModel::updateTransaction(const QString &hash, int status)
{
    if(transactionTableModel)
        transactionTableModel->updateTransaction(hash, status);

    // Balance and number of transactions might have changed
    checkBalanceChanged();

    int newNumTransactions = getNumTransactions();
    if(cachedNumTransactions != newNumTransactions)
    {
        cachedNumTransactions = newNumTransactions;
        emit numTransactionsChanged(newNumTransactions);
    }
}

void WalletModel::updateAddressBook(const QString &address, const QString &label, bool isMine, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, status);
}

bool WalletModel::validateAddress(const QString &address)
{
    CBitcoinAddress addressParsed(address.toStdString());
    return addressParsed.IsValid();
}

bool WalletModel::validateAlias(const QString &alias)
{
    return true;
}

void WalletModel::updateAlias(const QString &alias, const QString &value, const QString &expDepth, int status)
{
    if(aliasTableModelMine)
        aliasTableModelMine->refreshAliasTable();
    //if(aliasTableModelAll)
      //  aliasTableModelAll->updateEntry(alias, value, expDepth, AllAlias, status);
}

void WalletModel::updateOffer(const QString &offer, const QString &title, const QString &category, 
    const QString &price, const QString &quantity, const QString &expDepth, const QString &description, int status)
{
    if(offerTableModelMine)
		offerTableModelMine->updateEntry(offer, title, category, price, quantity, expDepth, description, MyOffers, status);
    if(offerTableModelAll)
		offerTableModelAll->updateEntry(offer, title, category, price, quantity, expDepth, description, AllOffers, status);
}

void WalletModel::updateCertIssuer(const QString &cert, const QString &title, const QString &expDepth, int status)
{
    if(certIssuerTableModel)
        certIssuerTableModel->updateEntry(cert, title, expDepth, false, status);
}


WalletModel::SendCoinsReturn WalletModel::sendCoins(const QList<SendCoinsRecipient> &recipients, const CCoinControl *coinControl)
{
    qint64 total = 0;
    QSet<QString> setAddress;
    QString hex;

    if(recipients.empty())
    {
        return OK;
    }

    // Pre-check input data for validity
    foreach(const SendCoinsRecipient &rcp, recipients)
    {
        if(!validateAddress(rcp.address))
        {
            return InvalidAddress;
        }
        setAddress.insert(rcp.address);

        if(rcp.amount <= 0)
        {
            return InvalidAmount;
        }
        total += rcp.amount;
    }

    if(recipients.size() > setAddress.size())
    {
        return DuplicateAddress;
    }

    int64 nBalance = getBalance(coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    if((total + nTransactionFee) > nBalance)
    {
        return SendCoinsReturn(AmountWithFeeExceedsBalance, nTransactionFee);
    }
	
    
        

        // Sendmany
        std::vector<std::pair<CScript, int64> > vecSend;
        foreach(const SendCoinsRecipient &rcp, recipients)
        {
			CBitcoinAddress myAddress = CBitcoinAddress(rcp.address.toStdString());
			LOCK2(cs_main, wallet->cs_wallet);
			{
				CScript scriptPubKey;
				scriptPubKey.SetDestination(myAddress.Get());
				vecSend.push_back(make_pair(scriptPubKey, rcp.amount));
			}
        }

        CWalletTx wtx;
        CReserveKey keyChange(wallet);
        int64 nFeeRequired = 0;
        std::string strFailReason;
        bool fCreated = wallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired, strFailReason, coinControl);

        if(!fCreated)
        {
            if((total + nFeeRequired) > nBalance)
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance, nFeeRequired);
            }
            emit message(tr("Send Coins"), QString::fromStdString(strFailReason),
                         CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }
        if(!uiInterface.ThreadSafeAskFee(nFeeRequired))
        {
            return Aborted;
        }
        if(!wallet->CommitTransaction(wtx, keyChange))
        {
            return TransactionCommitFailed;
        }
        hex = QString::fromStdString(wtx.GetHash().GetHex());
    

    // Add addresses / update labels that we've sent to to the address book
    foreach(const SendCoinsRecipient &rcp, recipients)
    {
        std::string strAddress = rcp.address.toStdString();
		CBitcoinAddress myAddress = CBitcoinAddress(strAddress);
        CTxDestination dest = myAddress.Get();
        std::string strLabel = rcp.label.toStdString();
        {
            LOCK(wallet->cs_wallet);

            std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(dest);
			if(strLabel.length() <= 0 && myAddress.IsValid() && myAddress.isAlias)
			{
				strLabel = myAddress.aliasName;
			}
            // Check if we have a new address or an updated label
            if (mi == wallet->mapAddressBook.end() || mi->second != strLabel)
            {

                wallet->SetAddressBookName(dest, strLabel);
            }
        }
    }

    return SendCoinsReturn(OK, 0, hex);
}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

AliasTableModel *WalletModel::getAliasTableModelMine()
{
    return aliasTableModelMine;
}
AliasTableModel *WalletModel::getAliasTableModelAll()
{
    return aliasTableModelAll;
}

OfferTableModel *WalletModel::getOfferTableModelMine()
{
    return offerTableModelMine;
}
OfferTableModel *WalletModel::getOfferTableModelAll()
{
    return offerTableModelAll;
}
CertIssuerTableModel *WalletModel::getCertIssuerTableModel()
{
    return certIssuerTableModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!wallet->IsCrypted())
    {
        return Unencrypted;
    }
    else if(wallet->IsLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted)
    {
        // Encrypt
        return wallet->EncryptWallet(passphrase);
    }
    else
    {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return wallet->Lock();
    }
    else
    {
        // Unlock
        return wallet->Unlock(passPhrase);
    }
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    bool retval;
    {
        LOCK(wallet->cs_wallet);
        wallet->Lock(); // Make sure wallet is locked before attempting pass change
        retval = wallet->ChangeWalletPassphrase(oldPass, newPass);
    }
    return retval;
}

bool WalletModel::backupWallet(const QString &filename)
{
    return BackupWallet(*wallet, filename.toLocal8Bit().data());
}

// Handlers for core signals
static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel, CCryptoKeyStore *wallet)
{
    OutputDebugStringF("NotifyKeyStoreStatusChanged\n");
    QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel, CWallet *wallet, const CTxDestination &address, const std::string &label, bool isMine, ChangeType status)
{
    OutputDebugStringF("NotifyAddressBookChanged %s %s isMine=%i status=%i\n", CBitcoinAddress(address).ToString().c_str(), label.c_str(), isMine, status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(CBitcoinAddress(address).ToString())),
                              Q_ARG(QString, QString::fromStdString(label)),
                              Q_ARG(bool, isMine),
                              Q_ARG(int, status));
}

static void NotifyAliasListChanged(WalletModel *walletmodel, CWallet *wallet, const CTransaction *tx, ChangeType status)
{
    std::vector<std::vector<unsigned char> > vvchArgs;
    int op, nOut;
    if (!DecodeAliasTx(*tx, op, nOut, vvchArgs, -1)) {
        return;
    }
	if(!IsAliasOp(op) || op == OP_ALIAS_NEW)  return;
	
	const std::vector<unsigned char> &vchName = vvchArgs[0];
	const std::vector<unsigned char> &vchValue = vvchArgs[op == OP_ALIAS_ACTIVATE ? 2 : 1];
    //unsigned long nExpDepth = nHeight + GetAliasExpirationDepth(nHeight)- pindexBest->nHeight;
    OutputDebugStringF("NotifyAliasListChanged %s %s status=%i\n", stringFromVch(vchName).c_str(), stringFromVch(vchValue).c_str(), status);
    QMetaObject::invokeMethod(walletmodel, "updateAlias", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(stringFromVch(vchName))),
                              Q_ARG(QString, QString::fromStdString(stringFromVch(vchValue))),
                              Q_ARG(QString, QString::fromStdString("0")),
                              Q_ARG(int, status)); 

}

static void NotifyOfferListChanged(WalletModel *walletmodel, CWallet *wallet, const CTransaction *tx, COffer offer, ChangeType status)
{
    unsigned long nExpDepth = offer.nHeight + GetOfferExpirationDepth(offer.nHeight);
    COfferAccept theAccept;
    std::vector<unsigned char> vchRand, vchTitle, vchDescription;
    int64 nPrice;
    int nQty;
    vchRand = offer.vchRand;
    vchTitle = offer.sTitle;
	vchDescription = offer.sDescription;
    nPrice = offer.nPrice;
    nQty = offer.nQty;
    if(offer.accepts.size()) {
        theAccept = offer.accepts.back();
        vchRand = theAccept.vchRand;
        nPrice = theAccept.nPrice;
        nQty = theAccept.nQty;
        nExpDepth = 0;
    }

    OutputDebugStringF("NotifyOfferListChanged %s %s status=%i\n",
                       stringFromVch(offer.vchRand).c_str(),
                       stringFromVch(vchTitle).c_str(), status);
    QMetaObject::invokeMethod(walletmodel, "updateOffer", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(stringFromVch(vchRand))),
                              Q_ARG(QString, QString::fromStdString(stringFromVch(vchTitle))),
                              Q_ARG(QString, QString::fromStdString(stringFromVch(offer.sCategory))),
                              Q_ARG(QString, QString::fromStdString(strprintf("%lf", (double)nPrice / COIN))),
                              Q_ARG(QString, QString::fromStdString(strprintf("%d", nQty))),
                              Q_ARG(QString, QString::fromStdString(strprintf("%lu", nExpDepth))),
							  Q_ARG(QString, QString::fromStdString(stringFromVch(vchDescription))),
                              Q_ARG(int, status));
}

static void NotifyCertIssuerListChanged(WalletModel *walletmodel, CWallet *wallet, const CTransaction *tx, CCertIssuer issuer, ChangeType status)
{
    CCertItem theCert;
    unsigned long nExpDepth = issuer.nHeight + GetCertExpirationDepth(issuer.nHeight);
    std::vector<unsigned char> vchRand, vchTitle;
    vchRand = issuer.vchRand;
    vchTitle = issuer.vchTitle;
    if(issuer.certs.size()) {
        theCert = issuer.certs.back();
        vchRand = theCert.vchRand;
        vchTitle = theCert.vchTitle;
        nExpDepth = 0;
    }

    OutputDebugStringF("NotifyCertIssuerListChanged %s %s status=%i\n",
                       stringFromVch(vchRand).c_str(),
                       stringFromVch(vchTitle).c_str(), status);
    QMetaObject::invokeMethod(walletmodel, "updateCertIssuer", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(stringFromVch(vchRand))),
                              Q_ARG(QString, QString::fromStdString(stringFromVch(vchTitle))),
                              Q_ARG(QString, QString::fromStdString(strprintf("%lu", nExpDepth))),
                              Q_ARG(int, status));
}

static void NotifyTransactionChanged(WalletModel *walletmodel, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    OutputDebugStringF("NotifyTransactionChanged %s status=%i\n", hash.GetHex().c_str(), status);
    QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(hash.GetHex())),
                              Q_ARG(int, status));
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyStatusChanged.connect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.connect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5));
    wallet->NotifyAliasListChanged.connect(boost::bind(NotifyAliasListChanged, this, _1, _2, _3));
    wallet->NotifyOfferListChanged.connect(boost::bind(NotifyOfferListChanged, this, _1, _2, _3, _4));
    wallet->NotifyCertIssuerListChanged.connect(boost::bind(NotifyCertIssuerListChanged, this, _1, _2, _3, _4));
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyStatusChanged.disconnect(boost::bind(&NotifyKeyStoreStatusChanged, this, _1));
    wallet->NotifyAddressBookChanged.disconnect(boost::bind(NotifyAddressBookChanged, this, _1, _2, _3, _4, _5));
    wallet->NotifyAliasListChanged.disconnect(boost::bind(NotifyAliasListChanged, this, _1, _2, _3));
    wallet->NotifyOfferListChanged.disconnect(boost::bind(NotifyOfferListChanged, this, _1, _2, _3, _4));
    wallet->NotifyCertIssuerListChanged.disconnect(boost::bind(NotifyCertIssuerListChanged, this, _1, _2, _3, _4));
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyTransactionChanged, this, _1, _2, _3));
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    bool was_locked = getEncryptionStatus() == Locked;
    if(was_locked)
    {
        // Request UI to unlock wallet
        emit requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *wallet, bool valid, bool relock):
        wallet(wallet),
        valid(valid),
        relock(relock)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        wallet->setWalletLocked(true);
    }
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}

bool WalletModel::getPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    return wallet->GetPubKey(address, vchPubKeyOut);   
}

// returns a list of COutputs from COutPoints
void WalletModel::getOutputs(const std::vector<COutPoint>& vOutpoints, std::vector<COutput>& vOutputs)
{
    BOOST_FOREACH(const COutPoint& outpoint, vOutpoints)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, wallet->mapWallet[outpoint.hash].GetDepthInMainChain());
        vOutputs.push_back(out);
    }
}

// AvailableCoins + LockedCoins grouped by wallet address (put change in one group with wallet address) 
void WalletModel::listCoins(std::map<QString, std::vector<COutput> >& mapCoins) const
{
    std::vector<COutput> vCoins;
    wallet->AvailableCoins(vCoins);
    
    std::vector<COutPoint> vLockedCoins;
    wallet->ListLockedCoins(vLockedCoins);
    
    // add locked coins
    BOOST_FOREACH(const COutPoint& outpoint, vLockedCoins)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, wallet->mapWallet[outpoint.hash].GetDepthInMainChain());
        vCoins.push_back(out);
    }
       
    BOOST_FOREACH(const COutput& out, vCoins)
    {
        COutput cout = out;
        
        while (wallet->IsChange(cout.tx->vout[cout.i]) && cout.tx->vin.size() > 0 && wallet->IsMine(cout.tx->vin[0]))
        {
            if (!wallet->mapWallet.count(cout.tx->vin[0].prevout.hash)) break;
            cout = COutput(&wallet->mapWallet[cout.tx->vin[0].prevout.hash], cout.tx->vin[0].prevout.n, 0);
        }

        CTxDestination address;
        if(!ExtractDestination(cout.tx->vout[cout.i].scriptPubKey, address)) continue;
        mapCoins[CBitcoinAddress(address).ToString().c_str()].push_back(out);
    }
}

bool WalletModel::isLockedCoin(uint256 hash, unsigned int n) const
{
    return wallet->IsLockedCoin(hash, n);
}

void WalletModel::lockCoin(COutPoint& output)
{
    wallet->LockCoin(output);
}

void WalletModel::unlockCoin(COutPoint& output)
{
    wallet->UnlockCoin(output);
}

void WalletModel::listLockedCoins(std::vector<COutPoint>& vOutpts)
{
    wallet->ListLockedCoins(vOutpts);
}
