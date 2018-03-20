// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "main.h"
#include "uint256.h"

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    // How many times we expect transactions after the last checkpoint to
    // be slower. This number is a compromise, as it can't be accurate for
    // every system. When reindexing from a fast disk with a slow CPU, it
    // can be up to 20, while when downloading from a slow network with a
    // fast multicore CPU, it won't be much higher than 1.
    static const double fSigcheckVerificationFactor = 5.0;

    struct CCheckpointData {
        const MapCheckpoints *mapCheckpoints;
        int64 nTimeLastCheckpoint;
        int64 nTransactionsLastCheckpoint;
        double fTransactionsPerDay;
    };

    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        (     0, uint256("0xc84c8d0f52a7418b28a24e7b5354d6febed47c8cc33b3fa20fdbe4b3a1fcd9c4"))
        (   666, uint256("0x3347d1782965ae18ab2cbfeff089ece5b7f9167ef6a843b959e8ee1e5c0849c1"))
        (  1333, uint256("0xae8f479d8251f1099272e7ce17688fb84d2f0842655efb53ace678a79b6f5f1a"))
        (  1669, uint256("0xa5bc32e784d38e95cc23984d2225b6fd14a830065029a6bb53e1366486cfb553"))
        (  1759, uint256("0x67dbfe2a58176a5e7c640b8ce047776d828c4c3a52dc88653227e56c29cb9409"))
        (  2021, uint256("0xcb0a506b70a38ef7f301f17a4b14133c50bf9391d8bfe2d6108c177d9436e09e"))
        (  2375, uint256("0x1819af6faaa15ca12cf51ab67e75507f8d5c41fc8215d458afe6ad62bff90276"))
        (  2947, uint256("0x586ca99b24ca99b1f3b8d48cb9d29c176065d92d13d84f8420577c7e60256e10"))
        (  3643, uint256("0xd39eb7844ea66caa2f5a5c78cca57623abe6ec4b0102697acabf614a329c417d"))
        (  4719, uint256("0x4cb63627475f1512cb5de607c9efbab40445c61a64fe13998e95700e334ecb16"))
        (  6205, uint256("0x4895b445deb4ecd28d6d62f46e282dc03187a64efcd66f7106cb995df2638fbe"))
        (  8494, uint256("0xd669bab6f606b6e2ef0b4711b18336c2f79ca2b926e867f72040300f09975722"))
        ( 10360, uint256("0xdd8d9937d8bb5784f161407442b84055280c7b843942d35d912db4a7562875f1"))
        ( 12815, uint256("0x5434de9b6916bf5f93f112777bd72b0a3040e705febfd5d00a492468aea29315"))
        ( 14333, uint256("0x1a6052a87543cbdc0f676d00bf7c4ebca757f67c05b6fdc76d41a4d256363bcb"))
        ( 16749, uint256("0x8a3b162afac24e3f68dd7e795f9160b8c3a99d41600ace69d2ce797baada1c2a"))
        ( 19410, uint256("0x5c78ff28da3299a36515eab91e237f3a3fd307cf4400037b97f845db4226c8d9"))
        ( 21367, uint256("0x22ae8cf4fde776105eeda79b8661a2b6e8cc8aa85d7acdbf2a1e88bde167ce2f"))
        ( 23962, uint256("0xa178657581363ca7ea21dc661db65ae29462d98920405008bba5b0e145645e76"))
        ( 26231, uint256("0x782f9a9361d1d6dab203b436253b0d8c7623c8bbafe56f11d8f66af9ff5cafee"))
        ( 29001, uint256("0x6d6a4593fc9f8cf087987f94c5097f079e15c4ae698a09f0f1f7708556901b55"))
        ( 30000, uint256("0xa3a31bc5bf64cedda5faaf77f08b687fac83a2debde33e15f1a1be1d4208711d"))
        ( 31739, uint256("0x296a8c87ab470eaf2906923a70f1f48dae80381cfccb5923a6c6bb1d15895d31"))
        ( 32690, uint256("0xd1f45af1539f37442bda5aa147e441fe6ffa987c679f05fe0423e96e18d83a50"))
        ( 33843, uint256("0x2df0bc28c1647e49d575c5da81f3f991a6501f5ad9134b8f29c0b48dc7acca96"))
        ( 35185, uint256("0x11e952d57dbce33a9573bdcdcad20c083b7250155c05c3cceffa04fed04b6c0d"))
        ( 37882, uint256("0xda3166819d979279fb3967575d72e5b30914eb93e62c02d05b0d4a04c36f52f1"))
        ( 39001, uint256("0x99c471f5487e5a0ce60cdc6d53a9ab58df52e5b9cbd121547265235ddb987058"))
        ( 42315, uint256("0xe693c717c8946c80aea631a30c00315f8811c1fd019b8c792c35eb576fa23f1f"))
        ( 44000, uint256("0x98def7268d9ee11641b73f91593611d9e077e257ebf91a85dbb7a6c15bd8c271"))
        ( 46156, uint256("0x0ceceb0f4cd94f9d7f6e1b90ff1a10fc9fe9ce307428339d8b0910ede31eeaaf"))
        ( 48912, uint256("0xa5504453a92ca1aa324a39dde92756195688bae94adac3e6c1887450e6625c09"))
        ( 50104, uint256("0x06abb38124327da7a156e598fc52927d97be5104a80a62f639d383a485831986"))
        ( 51030, uint256("0x0b6476e61a4ead747ac975b753c4812aaf766ab7effea80d448611ccb717d6ad")) 
        ( 52576, uint256("0x3020d95556e84c8fc9b894e801bffcab5712ee208dfac6b384afcab8eef4011b"))
        ( 53300, uint256("0x6ef0e805125dd35f94898cd0354807f20ac8eb7ffb3818dd6a358f9dd28f7db6"))
        ( 54843, uint256("0x71610e58ee19fe0b315de48eb91395a044937c8281b972811587412861f9a14f"))
        ( 55985, uint256("0x5bc10326585bc2247b42c74463aba987db611e98194437d44429a40ca0a9e5b1"))
        ( 57882, uint256("0x352955890c856314497b4f2c20f4d016a94127ee09316af552a0adcc910d0b74"))
        ( 59001, uint256("0x612d979ed0537beab063c0063e3a0ce5a9e9178f73f1ba78b0b2410e21dfadd5"))
        ( 61315, uint256("0x5c058a5c0ecba83dbcc0bfeff943624306b6864ae70aab663fe843f0e8150843"))
        ( 63000, uint256("0x20c49a84cd5d652a6fc928fbcb5ee850ce29e1e444222b5d7747d7783d3be82b"))
        ( 64956, uint256("0x0a744275bc97b27fb51abd32816c311c492b7b186cf5a8b7f9a8ebb7baec2994"))
        ( 66912, uint256("0x89fa0a97a09504255eba7f4d2c0714e8ca5356d9e648577444b31ab3905597ca"))
        ( 68104, uint256("0x7185ce7e3c8bd0d76a307c91af4d4d75c62e40e3c84380009598c5b0797747bb"))
        ( 71030, uint256("0x28806e75b384a1f10f9d517d0d634dd416c17790a05374977c8d9faa1b9e61d3"))
        ( 73215, uint256("0x501587d0a4fe1b9a3443e06f2f3c1bcc9f63f9032f3640ae74c6ac7b637345f2"))
        ( 74655, uint256("0x675d9f273167c68a07e6a2e9f720b57af2a6fa96cb2e269df03d7080c8236a1a"))
        ( 76105, uint256("0x0f9f3474c6ba41a3a025cf570ec2eaf530c5d2d48406c9a9f5a81380796f17da"))
        ( 77889, uint256("0x50cc5d37753e5c2e89dda224e1b93fac2df43971c7085e0052ab3a4380db0671"))
        ( 79001, uint256("0xfbca22dfc1e97aebc9717ce8b15e443a683bac60fa2503c0ca0788f43067eb53"))
        ( 80700, uint256("0x24e06f5775b755d91cd5cd264271662c2a94c9a7b1c6d63894a2bf7af1b14cc3"))
        ( 82430, uint256("0xf66884638cee157e7d5225fb0064643ebf3ffe2c88451a3dc898cc7fe54a0cb7"))
        ( 85132, uint256("0x3f8395e614fb722f50e72ccf7001f5d9e73d4573b4ea2f466e18da866336549e"))
        ( 87115, uint256("0x9ec1504d00fdd9c0c049f5321cf055a651e090641f9656acc332ef2830fef39c"))
        ( 92105, uint256("0x0405d50ec62f578f714b74a32140585fe8c2366dc4d7a7a8f4185d027aa2cc83"))
        ( 95110, uint256("0xfd25cd418f6706246186ee94f8a09ce5fdbf8c700c56fdb72bd174bec46df152"))
        ( 96890, uint256("0x9bed50e5fcbf2adc58bd6053b9abaccbccabfb56908e8785b840c55c95d7c94e"))
        ( 98105, uint256("0x14ff4722b6891bbec768d4aa773c3a64e9a551b94f999adf6031a9babc67dc4d"))
        ( 101901, uint256("0xb3d4b27af1b75db3009791f455acfff616ab4dff70c1258393a8a7586876a4a3"))
        ( 106793, uint256("0x4666daa8b44616dca9aad6b413b296acff2933e666d795f4f286640f94f1abff"))
        ( 110280, uint256("0xb28ab3a9db5849d84456d833755c9c01611a9c98b3da2daff6f4883e50f5c36c"))
        ( 113151, uint256("0x5f0901cb9acb48d30426c359da9f9260b7c99ee5bca76a7e254283b73e2a734a"))
        ( 116182, uint256("0x3b563424f766c83b7bd4f71cbfa55d36bd63e78e3203df316aa8955a208192e1"))
        ( 119100, uint256("0xf1ae217c317865da6562ca62a469b3b64c089a04ca4d54925a96bf4b1cdf91b2"))
        ( 125360, uint256("0xcbce71a0702af2bb2607966ac19a03f28f7459383249166a05f55fa71b7e3c18"))
        ( 140998, uint256("0xb7aee5d5dc68bc56835fc9a9fa17dd169cddbe61aae855d223b59d9c50abdd2b"))
        ( 163221, uint256("0x316394844198d9bce5669a2d51ab08f206e40c158ce4eabad19adc0d7c930bf5"))
        ( 185411, uint256("0x43f0395e7555bd56a3445154095e313ed4ed2aa931a4f40a8ebeaecda63b437b"))
        ( 197200, uint256("0xe9a50ea75118573870c8d9c7908e3e0c589ce581dd98020f4a736b8ed17e1c51"))
        ( 201990, uint256("0x27ef8fd089e999b0a88fe0829a23b73e178b91882e2541fd356a5ac25222f7b6"))
        ( 218123, uint256("0xeb56da11c1ea2ad511813b2c114e20be7c7113181eeea5acc86451c23a451236"))
        ( 240351, uint256("0xb123a60541f00310404c311d2f9168a46dce7c033314a2981557557d464d555a"))
        ( 258999, uint256("0x5bf820f9b91b812a5976e5321d4928e79d83103b40a77e21fc6cfb77a01583a9"))
        ( 286405, uint256("0x3d590a93302cff768268788d244e7326c042f9d14c2746fa3b52ba15d5c5a108"))
        ( 291330, uint256("0x05e3cc54af99ce0c8a35adeb3a093138333a1ed7800a11d1c8a3aea9b39eeeee"))
        ( 302005, uint256("0x1088aacdce9739c41cb57633637250759d67f70583e23ca9d9c9169b0f18c2eb"))
        ( 325100, uint256("0x22b10a33fdf17d31e18fd6b491702505a6162f61e263de1b19ae5ac52be747dd"))
        ( 341290, uint256("0x97dbfe0ce6028d7fef32a57c147a67f743899f59b499664550a19e96fbfd1e9e"))
        ( 356001, uint256("0x50a48f51df7167afbcb3d6ddbaae0d42f383a85367eb6961ced22f9263c8c0f9"))
        ( 362544, uint256("0x6bf678b95f1fe7ab8a9d48baefc990aab41b7444715e1e86c2ade2ce77739862"))
        ;

    static const CCheckpointData data = {
        &mapCheckpoints,
        1430366011, // * UNIX timestamp of last checkpoint block
        468511,      // * total number of transactions between genesis and last checkpoint
                    //   (the tx=... number in the SetBestChain debug.log lines)
        600.0       // * estimated number of transactions per day after checkpoint
    };

    static MapCheckpoints mapCheckpointsTestnet = 
        boost::assign::map_list_of
        ( 0, uint256("0x0"))
        ;
    static const CCheckpointData dataTestnet = {
        &mapCheckpointsTestnet,
        1392757043,
        1,
        300.0
    };

    static MapCheckpoints mapCheckpointsCakenet = 
        boost::assign::map_list_of
        ( 0, uint256("0x0"))
        ;
    static const CCheckpointData dataCakenet = {
        &mapCheckpointsCakenet,
        1392757043,
        1,
        300.0
    };

    const CCheckpointData &Checkpoints() {
        if (fTestNet )
            return dataTestnet;
        else if (fCakeNet )
            return dataCakenet;
        else
            return data;
    }

    bool CheckBlock(int nHeight, const uint256& hash)
    {
        if (fTestNet||fCakeNet) return true; // Testnet has no checkpoints
        if (!GetBoolArg("-checkpoints", false))
            return true;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    // Guess how far we are in the verification process at the given block index
    double GuessVerificationProgress(CBlockIndex *pindex) {
        if (pindex==NULL)
            return 0.0;

        int64 nNow = time(NULL);

        double fWorkBefore = 0.0; // Amount of work done before pindex
        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
        // Work is defined as: 1.0 per transaction before the last checkoint, and
        // fSigcheckVerificationFactor per transaction after.

        const CCheckpointData &data = Checkpoints();

        if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
            double nCheapBefore = pindex->nChainTx;
            double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
            double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore;
            fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
        } else {
            double nCheapBefore = data.nTransactionsLastCheckpoint;
            double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
            double nExpensiveAfter = (nNow - pindex->nTime)/86400.0*data.fTransactionsPerDay;
            fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
            fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
        }

        return fWorkBefore / (fWorkBefore + fWorkAfter);
    }

    int GetTotalBlocksEstimate()
    {
        if (fTestNet||fCakeNet) return 0; // Testnet has no checkpoints
        if (!GetBoolArg("-checkpoints", false))
            return 0;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        if (fTestNet||fCakeNet) return NULL; // Testnet has no checkpoints
        if (!GetBoolArg("-checkpoints", false))
            return NULL;

        const MapCheckpoints& checkpoints = *Checkpoints().mapCheckpoints;

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }
}
