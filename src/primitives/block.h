// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_PRIMITIVES_BLOCK_H
#define SYSCOIN_PRIMITIVES_BLOCK_H
#include <auxpow.h>
#include <primitives/transaction.h>
#include <primitives/pureheader.h>
#include <serialize.h>
#include <uint256.h>
#include <util/time.h>

#include <memory>

/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
// SYSCOIN BEGIN: Extend Bitcoin's header through the inherited AuxPoW design.
// Bitcoin original: class CBlockHeader
class CBlockHeader : public CPureBlockHeader
// SYSCOIN END: Extend the header through CPureBlockHeader.
{
public:
    // SYSCOIN BEGIN: Move Bitcoin's committed header fields to CPureBlockHeader
    // and retain the optional merged-mining proof in this wrapper.
    // Bitcoin fields now inherited:
    // int32_t nVersion;
    // uint256 hashPrevBlock;
    // uint256 hashMerkleRoot;
    // uint32_t nTime;
    // uint32_t nBits;
    // uint32_t nNonce;
    // auxpow (if this is a merge-minded block)
    std::shared_ptr<CAuxPow> auxpow;
    // SYSCOIN END: Separate committed header fields from the AuxPoW wrapper.
    CBlockHeader()
    {
        SetNull();
    }

    // SYSCOIN BEGIN: Modify Bitcoin's header serialization for optional AuxPoW.
    // The original committed-field serialization moved to CPureBlockHeader:
    // SERIALIZE_METHODS(CBlockHeader, obj) { READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce); }
    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s << *(CPureBlockHeader*)this;
        if (this->IsAuxpow())
        {
            assert(auxpow != nullptr);
            s << *auxpow;
        }
    }
    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s >> *(CPureBlockHeader*)this;
        if (this->IsAuxpow())
        {
            auxpow = std::make_shared<CAuxPow>();
            assert(auxpow != nullptr);
            s >> *auxpow;
        } else {
            auxpow.reset();
        }
    }
    // SYSCOIN END: Serialize the committed header and optional AuxPoW.


    void SetNull()
    {
        // SYSCOIN BEGIN: Delegate Bitcoin's field reset and clear the AuxPoW wrapper.
        // Bitcoin original field reset, now in CPureBlockHeader::SetNull():
        // nVersion = 0;
        // hashPrevBlock.SetNull();
        // hashMerkleRoot.SetNull();
        // nTime = 0;
        // nBits = 0;
        // nNonce = 0;
        CPureBlockHeader::SetNull();
        auxpow.reset();
        // SYSCOIN END: Reset committed fields and the AuxPoW wrapper.
    }

    // SYSCOIN BEGIN: Inherit these original Bitcoin declarations from CPureBlockHeader.
    // bool IsNull() const
    // {
    //     return (nBits == 0);
    // }
    // uint256 GetHash() const;
    // SYSCOIN END: Inherit null testing and committed-header hashing.

    NodeSeconds Time() const
    {
        return NodeSeconds{std::chrono::seconds{nTime}};
    }
    // SYSCOIN BEGIN: Inherit Bitcoin's block-time accessor from CPureBlockHeader.
    // int64_t GetBlockTime() const
    // {
    //     return (int64_t)nTime;
    // }
    // SYSCOIN END: Inherit the block-time accessor.

    // SYSCOIN BEGIN: Set the inherited AuxPoW wrapper and its version flag together.
    /**
     * Set the block's auxpow (or unset it).  This takes care of updating
     * the version accordingly.
     */
    void SetAuxpow (std::unique_ptr<CAuxPow> apow);
    // SYSCOIN END: Set the AuxPoW wrapper and version flag together.
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransactionRef> vtx;
    // memory only
    mutable bool fChecked;
    // SYSCOIN
    std::vector<unsigned char> vchNEVMBlockData;
    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *(static_cast<CBlockHeader*>(this)) = header;
    }

    SERIALIZE_METHODS(CBlock, obj)
    {
        READWRITE(AsBase<CBlockHeader>(obj), obj.vtx);
        // SYSCOIN
        if (obj.IsNEVM() && !(s.GetType() & SER_GETHASH) && !(s.GetType() & SER_SIZE))
            READWRITE(obj.vchNEVMBlockData);
    }

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        fChecked = false;
        // SYSCOIN
        vchNEVMBlockData.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
        block.nTime          = nTime;
        block.nBits          = nBits;
        block.nNonce         = nNonce;
        // SYSCOIN BEGIN: Extend Bitcoin's header copy with the AuxPoW wrapper.
        block.auxpow         = auxpow;
        // SYSCOIN END: Copy the AuxPoW wrapper.
        return block;
    }

    std::string ToString() const;
};

/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    /** Historically CBlockLocator's version field has been written to network
     * streams as the negotiated protocol version and to disk streams as the
     * client version, but the value has never been used.
     *
     * Hard-code to the highest protocol version ever written to a network stream.
     * SerParams can be used if the field requires any meaning in the future,
     **/
    static constexpr int DUMMY_VERSION = 70016;

    std::vector<uint256> vHave;

    CBlockLocator() {}

    explicit CBlockLocator(std::vector<uint256>&& have) : vHave(std::move(have)) {}

    SERIALIZE_METHODS(CBlockLocator, obj)
    {
        int nVersion = DUMMY_VERSION;
        READWRITE(nVersion);
        READWRITE(obj.vHave);
    }

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull() const
    {
        return vHave.empty();
    }
};

#endif // SYSCOIN_PRIMITIVES_BLOCK_H
