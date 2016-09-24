// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/pureheader.h"

#include "chainparams.h"
#include "hash.h"
#include "utilstrencodings.h"
void CBlockVersion::SetAuxpow(bool auxpow)
    {
        if (auxpow)
		{
            nVersion |= VERSION_AUXPOW;
			SetChainId(Params ().GetConsensus ().nAuxpowChainId);
		}
        else
		{
            nVersion &= ~VERSION_AUXPOW;
			SetChainId(0);
		}
    }
// SYSCOIN fix setbaseversion to only set base and not chain bits
void CBlockVersion::SetBaseVersion(int32_t nBaseVersion)
{
	if(IsAuxpow())
	{
		nVersion = nBaseVersion;
		SetAuxpow(true);
	}
	else
		nVersion = nBaseVersion;

}

uint256 CPureBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}