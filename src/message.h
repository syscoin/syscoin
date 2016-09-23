#ifndef MESSAGE_H
#define MESSAGE_H

#include "rpc/server.h"
#include "dbwrapper.h"
#include "script/script.h"
#include "serialize.h"
class CWalletTx;
class CTransaction;
class CReserveKey;
class CCoinsViewCache;
class CCoins;
class CBlock;

bool CheckMessageInputs( const CTransaction &tx, int op, int nOut, const std::vector<std::vector<unsigned char> > &vvchArgs, const CCoinsViewCache &inputs, bool fJustCheck, int nHeight, std::string &errorMessage, const CBlock* block = NULL, bool dontaddtodb=false);
bool DecodeMessageTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeAndParseMessageTx(const CTransaction& tx, int& op, int& nOut, std::vector<std::vector<unsigned char> >& vvch);
bool DecodeMessageScript(const CScript& script, int& op, std::vector<std::vector<unsigned char> > &vvch);
bool IsMessageOp(int op);
int IndexOfMessageOutput(const CTransaction& tx);
int GetMessageExpirationDepth();
bool ExtractMessageAddress(const CScript& script, std::string& address);
CScript RemoveMessageScriptPrefix(const CScript& scriptIn);
extern bool IsSys21Fork(const uint64_t& nHeight);
std::string messageFromOp(int op);


class CMessage {
public:
	std::vector<unsigned char> vchMessage;
	std::vector<unsigned char> vchAliasTo;
	std::vector<unsigned char> vchAliasFrom;
	std::vector<unsigned char> vchSubject;
	std::vector<unsigned char> vchMessageTo;
	std::vector<unsigned char> vchMessageFrom;
    uint256 txHash;
    uint64_t nHeight;
    CMessage() {
        SetNull();
    }
    CMessage(const CTransaction &tx) {
        SetNull();
        UnserializeFromTx(tx);
    }
	ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
		READWRITE(vchSubject);
		READWRITE(vchMessageTo);
		READWRITE(vchMessageFrom);
		READWRITE(txHash);
		READWRITE(VARINT(nHeight));
		READWRITE(vchMessage);
        READWRITE(vchAliasTo);
		READWRITE(vchAliasFrom);		
		
	}

    friend bool operator==(const CMessage &a, const CMessage &b) {
        return (
        a.vchAliasTo == b.vchAliasTo
		&& a.vchAliasFrom == b.vchAliasFrom
		&& a.vchSubject == b.vchSubject
		&& a.vchMessageTo == b.vchMessageTo
		&& a.vchMessageFrom == b.vchMessageFrom
		&& a.txHash == b.txHash
		&& a.nHeight == b.nHeight
		&& a.vchMessage == b.vchMessage
        );
    }

    CMessage operator=(const CMessage &b) {
        vchAliasTo = b.vchAliasTo;
		vchAliasFrom = b.vchAliasFrom;
		vchSubject = b.vchSubject;
		vchMessageTo = b.vchMessageTo;
		vchMessageFrom = b.vchMessageFrom;
		txHash = b.txHash;
		nHeight = b.nHeight;
		vchMessage = b.vchMessage;
        return *this;
    }

    friend bool operator!=(const CMessage &a, const CMessage &b) {
        return !(a == b);
    }

    void SetNull() {vchMessage.clear(); txHash.SetNull(); nHeight = 0; vchAliasTo.clear(); vchAliasFrom.clear(); vchSubject.clear(); vchMessageTo.clear();vchMessageFrom.clear();}
    bool IsNull() const { return (vchMessage.empty() && txHash.IsNull() && nHeight == 0 && vchAliasTo.empty() && vchAliasFrom.empty()); }
    bool UnserializeFromTx(const CTransaction &tx);
	bool UnserializeFromData(const std::vector<unsigned char> &vchData, const std::vector<unsigned char> &vchHash);
	const std::vector<unsigned char> Serialize();
};


class CMessageDB : public CDBWrapper {
public:
    CMessageDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "message", nCacheSize, fMemory, fWipe) {}

    bool WriteMessage(const std::vector<unsigned char>& name, std::vector<CMessage>& vtxPos) {
        return Write(make_pair(std::string("messagei"), name), vtxPos);
    }

    bool EraseMessage(const std::vector<unsigned char>& name) {
        return Erase(make_pair(std::string("messagei"), name));
    }

    bool ReadMessage(const std::vector<unsigned char>& name, std::vector<CMessage>& vtxPos) {
        return Read(make_pair(std::string("messagei"), name), vtxPos);
    }

    bool ExistsMessage(const std::vector<unsigned char>& name) {
        return Exists(make_pair(std::string("messagei"), name));
    }

    bool ScanMessages(
            const std::vector<unsigned char>& vchMessage,
            unsigned int nMax,
            std::vector<std::pair<std::vector<unsigned char>, CMessage> >& MessageScan);

};

bool GetTxOfMessage(const std::vector<unsigned char> &vchMessage, CTransaction& tx);

#endif // MESSAGE_H
