// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "primitives/pureheader.h"

#include "chainparams.h"
#include "hash.h"
#include "utilstrencodings.h"
void CPureBlockHeader::SetAuxpow (bool auxpow)
{
    if (auxpow)
	{
        nAuxPowVersion |= VERSION_AUXPOW;
		SetChainId(Params ().GetConsensus ().nAuxpowChainId);
	}
    else
	{
        nAuxPowVersion &= ~VERSION_AUXPOW;
		SetChainId(0);
	}
}
uint256 CPureBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}