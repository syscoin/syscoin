#ifndef CERT_H
#define CERT_H

#include "bitcoinrpc.h"
#include "leveldb.h"

class CTransaction;
class CTxOut;
class CValidationState;
class CCoinsViewCache;
class COutPoint;
class CCoins;
class CScript;
class CWalletTx;
class CDiskTxPos;

bool CheckCertInputs(CBlockIndex *pindex, const CTransaction &tx, CValidationState &state, CCoinsViewCache &inputs,
                     std::map<std::vector<unsigned char>,uint256> &mapTestPool, bool fBlock, bool fMiner, bool fJustCheck);
bool IsCertMine(const CTransaction& tx);
bool IsCertMine(const CTransaction& tx, const CTxOut& txout, bool ignore_aliasnew = false);
std::string SendCertMoneyWithInputTx(CScript scriptPubKey, int64 nValue, int64 nNetFee, CWalletTx& wtxIn,
                                     CWalletTx& wtxNew, bool fAskFee, const std::string& txData = "");
bool CreateCertTransactionWithInputTx(const std::vector<std::pair<CScript, int64> >& vecSend, CWalletTx& wtxIn,
                                      int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, const std::string& txData);
bool DecodeCertTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool DecodeCertTx(const CCoins& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch, int nHeight);
bool DecodeCertScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);
bool IsCertOp(int op);
int IndexOfCertIssuerOutput(const CTransaction& tx);
uint64 GetCertFeeSubsidy(unsigned int nHeight);
bool GetValueOfCertIssuerTxHash(const uint256 &txHash, std::vector<unsigned char>& vchValue, uint256& hash, int& nHeight);
int GetCertTxHashHeight(const uint256 txHash);
int GetCertTxPosHeight(const CDiskTxPos& txPos);
int GetCertTxPosHeight2(const CDiskTxPos& txPos, int nHeight);
int GetCertDisplayExpirationDepth(int nHeight);
int64 GetCertNetworkFee(int seed, int nHeight);
int64 GetCertNetFee(const CTransaction& tx);
bool InsertCertFee(CBlockIndex *pindex, uint256 hash, uint64 nValue);
bool ExtractCertIssuerAddress(const CScript& script, std::string& address);

std::string certissuerFromOp(int op);

extern std::map<std::vector<unsigned char>, uint256> mapMyCertIssuers;
extern std::map<std::vector<unsigned char>, uint256> mapMyCertItems;
extern std::map<std::vector<unsigned char>, std::set<uint256> > mapCertIssuerPending;
extern std::map<std::vector<unsigned char>, std::set<uint256> > mapCertItemPending;

class CBitcoinAddress;

class CCertItem {
public:
    std::vector<unsigned char> vchRand;
    std::vector<unsigned char> vchTitle;
    std::vector<unsigned char> vchData;
    uint256 txHash;
    uint64 nHeight;
    uint64 nTime;
    uint64 nFee;
    uint256 txPayId;

    CCertItem() {
        SetNull();
    }
    IMPLEMENT_SERIALIZE (
        READWRITE(vchRand);
        READWRITE(vchTitle);
        READWRITE(vchData);
        READWRITE(txHash);
        READWRITE(txPayId);
        READWRITE(nHeight);
        READWRITE(nTime);
        READWRITE(nFee);
    )

    friend bool operator==(const CCertItem &a, const CCertItem &b) {
        return (
        a.vchRand == b.vchRand
        && a.vchTitle == b.vchTitle
        && a.vchData == b.vchData
        && a.txHash == b.txHash
        && a.nHeight == b.nHeight
        && a.nTime == b.nTime
        && a.nFee == b.nFee
        && a.txPayId == b.txPayId
        );
    }

    CCertItem operator=(const CCertItem &b) {
        vchRand = b.vchRand;
        vchTitle = b.vchTitle;
        vchData = b.vchData;
        txHash = b.txHash;
        nHeight = b.nHeight;
        nTime = b.nTime;
        txPayId = b.txPayId;
        nFee = b.nFee;
        return *this;
    }

    friend bool operator!=(const CCertItem &a, const CCertItem &b) {
        return !(a == b);
    }

    void SetNull() { nHeight = nTime = 0; txHash = 0; nFee = 0; vchRand.clear(); }
    bool IsNull() const { return (nTime == 0 && txHash == 0 && nFee == 0 && nHeight == 0 && vchRand.size() == 0); }

};

class CCertIssuer {
public:
    std::vector<unsigned char> vchRand;
    std::vector<unsigned char> vchTitle;
    std::vector<unsigned char> vchData;
    uint256 txHash;
    uint64 nHeight;
    uint64 nTime;
    uint256 hash;
    uint64 n;
    uint64 nFee;
    std::vector<CCertItem>certs;

    CCertIssuer() {
        SetNull();
    }
    
    CCertIssuer(const CTransaction &tx) {
        SetNull();
        UnserializeFromTx(tx);
    }
        
    IMPLEMENT_SERIALIZE (
        READWRITE(vchRand);
        READWRITE(vchTitle);
        READWRITE(vchData);
        READWRITE(txHash);
        READWRITE(nHeight);
        READWRITE(nTime);
        READWRITE(hash);
        READWRITE(n);
        READWRITE(nFee);
        READWRITE(certs);
    )

    bool GetCertItemByHash(std::vector<unsigned char> ahash, CCertItem &ca) {
        for(unsigned int i=0;i<certs.size();i++) {
            if(certs[i].vchRand == ahash) {
                ca = certs[i];
                return true;
            }
        }
        return false;
    }

    void PutCertItem(CCertItem &theOA) {
        for(unsigned int i=0;i<certs.size();i++) {
            CCertItem oa = certs[i];
            if(theOA.vchRand == oa.vchRand) {
                certs[i] = theOA;
                return;
            }
        }
        certs.push_back(theOA);
    }

    void PutToCertIssuerList(std::vector<CCertIssuer> &certIssuerList) {
        for(unsigned int i=0;i<certIssuerList.size();i++) {
            CCertIssuer o = certIssuerList[i];
            if(o.nHeight == nHeight) {
                certIssuerList[i] = *this;
                return;
            }
        }
        certIssuerList.push_back(*this);
    }

    bool GetCertFromList(const std::vector<CCertIssuer> &certIssuerList) {
        if(certIssuerList.size() == 0) return false;
        for(unsigned int i=0;i<certIssuerList.size();i++) {
            CCertIssuer o = certIssuerList[i];
            if(o.nHeight == nHeight) {
                *this = certIssuerList[i];
                return true;
            }
        }
        *this = certIssuerList.back();
        return false;
    }

    friend bool operator==(const CCertIssuer &a, const CCertIssuer &b) {
        return (
           a.vchRand == b.vchRand
        && a.vchTitle==b.vchTitle
        && a.vchData==b.vchData
        && a.nFee == b.nFee
        && a.n == b.n
        && a.hash == b.hash
        && a.txHash == b.txHash
        && a.nHeight == b.nHeight
        && a.nTime == b.nTime
        && a.certs == b.certs
        );
    }

    CCertIssuer operator=(const CCertIssuer &b) {
        vchRand = b.vchRand;
        vchTitle = b.vchTitle;
        vchData = b.vchData;
        nFee = b.nFee;
        n = b.n;
        hash = b.hash;
        txHash = b.txHash;
        nHeight = b.nHeight;
        nTime = b.nTime;
        certs = b.certs;
        return *this;
    }

    friend bool operator!=(const CCertIssuer &a, const CCertIssuer &b) {
        return !(a == b);
    }

    void SetNull() { nHeight = n = 0; txHash = hash = 0; certs.clear(); vchRand.clear(); vchTitle.clear(); vchData.clear(); }
    bool IsNull() const { return (n == 0 && txHash == 0 && hash == 0 && nHeight == 0 && vchRand.size() == 0); }

    bool UnserializeFromTx(const CTransaction &tx);
    void SerializeToTx(CTransaction &tx);
    std::string SerializeToString();
};

class CCertFee {
public:
    uint256 hash;
    uint64 nHeight;
    uint64 nTime;
    uint64 nFee;

    CCertFee() {
        nTime = 0; nHeight = 0; hash = 0; nFee = 0;
    }

    IMPLEMENT_SERIALIZE (
        READWRITE(hash);
        READWRITE(nHeight);
        READWRITE(nTime);
        READWRITE(nFee);
    )

    friend bool operator==(const CCertFee &a, const CCertFee &b) {
        return (
        a.nTime==b.nTime
        && a.hash==b.hash
        && a.nHeight==b.nHeight
        && a.nFee == b.nFee
        );
    }

    CCertFee operator=(const CCertFee &b) {
        nTime = b.nTime;
        nFee = b.nFee;
        hash = b.hash;
        nHeight = b.nHeight;
        return *this;
    }

    friend bool operator!=(const CCertFee &a, const CCertFee &b) { return !(a == b); }
    void SetNull() { hash = nTime = nHeight = nFee = 0;}
    bool IsNull() const { return (nTime == 0 && nFee == 0 && hash == 0 && nHeight == 0); }
};
bool RemoveCertFee(CCertFee &txnVal);

class CCertDB : public CLevelDB {
public:
    CCertDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDB(GetDataDir() / "certificates", nCacheSize, fMemory, fWipe) {}

    bool WriteCertIssuer(const std::vector<unsigned char>& name, std::vector<CCertIssuer>& vtxPos) {
        return Write(make_pair(std::string("certissueri"), name), vtxPos);
    }

    bool EraseCertIssuer(const std::vector<unsigned char>& name) {
        return Erase(make_pair(std::string("certissueri"), name));
    }

    bool ReadCertIssuer(const std::vector<unsigned char>& name, std::vector<CCertIssuer>& vtxPos) {
        return Read(make_pair(std::string("certissueri"), name), vtxPos);
    }

    bool ExistsCertIssuer(const std::vector<unsigned char>& name) {
        return Exists(make_pair(std::string("certissueri"), name));
    }

    bool WriteCertItem(const std::vector<unsigned char>& name, std::vector<unsigned char>& vchValue) {
        return Write(make_pair(std::string("certissuera"), name), vchValue);
    }

    bool EraseCertItem(const std::vector<unsigned char>& name) {
        return Erase(make_pair(std::string("certissuera"), name));
    }

    bool ReadCertItem(const std::vector<unsigned char>& name, std::vector<unsigned char>& vchValue) {
        return Read(make_pair(std::string("certissuera"), name), vchValue);
    }

    bool ExistsCertItem(const std::vector<unsigned char>& name) {
        return Exists(make_pair(std::string("certissuera"), name));
    }

    bool WriteCertFees(std::vector<CCertFee>& vtxPos) {
        return Write(make_pair(std::string("certissuera"), std::string("certissuertxf")), vtxPos);
    }

    bool ReadCertFees(std::vector<CCertFee>& vtxPos) {
        return Read(make_pair(std::string("certissuera"), std::string("certissuertxf")), vtxPos);
    }

    bool ScanCertIssuers(
            const std::vector<unsigned char>& vchName,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CCertIssuer> >& certIssuerScan);

    bool ReconstructCertIndex(CBlockIndex *pindexRescan);
};
extern std::list<CCertFee> lstCertIssuerFees;


bool GetTxOfCertIssuer(CCertDB& dbCertIssuer, const std::vector<unsigned char> &vchCertIssuer, CTransaction& tx);

#endif // CERT_H
