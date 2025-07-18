// Copyright (c) 2018-2023 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_BLS_BLS_WORKER_H
#define SYSCOIN_BLS_BLS_WORKER_H

#include <bls/bls.h>

#include <ctpl_stl.h>

#include <future>
#include <mutex>
#include <utility>

// Low level BLS/DKG stuff. All very compute intensive and optimized for parallelization
// The worker tries to parallelize as much as possible and utilizes a few properties of BLS aggregation to speed up things
// For example, public key vectors can be aggregated in parallel if they are split into batches and the batched aggregations are
// aggregated to a final public key. This utilizes that when aggregating keys (a+b+c+d) gives the same result as (a+b)+(c+d)
class CBLSWorker
{
public:
    using SignDoneCallback = std::function<void(const CBLSSignature&)>;
    using SigVerifyDoneCallback = std::function<void(bool)>;
    using CancelCond = std::function<bool()>;

private:
    ctpl::thread_pool workerPool;

    static const int SIG_VERIFY_BATCH_SIZE = 8;
    struct SigVerifyJob {
        SigVerifyDoneCallback doneCallback;
        CancelCond cancelCond;
        CBLSSignature sig;
        CBLSPublicKey pubKey;
        uint256 msgHash;
        SigVerifyJob(SigVerifyDoneCallback&& _doneCallback, CancelCond&& _cancelCond, const CBLSSignature& _sig, CBLSPublicKey _pubKey, const uint256& _msgHash) :
            doneCallback(_doneCallback),
            cancelCond(_cancelCond),
            sig(_sig),
            pubKey(std::move(_pubKey)),
            msgHash(_msgHash)
        {
        }
    };

    std::mutex sigVerifyMutex;
    int sigVerifyBatchesInProgress{0};
    std::vector<SigVerifyJob> sigVerifyQueue;

public:
    CBLSWorker();
    ~CBLSWorker();

    void Start();
    void Stop();

    bool GenerateContributions(int threshold, Span<CBLSId> ids, BLSVerificationVectorPtr& vvecRet, std::vector<CBLSSecretKey>& skSharesRet);

    // The following functions are all used to aggregate verification (public key) vectors
    // Inputs are in the following form:
    //   [
    //     [a1, b1, c1, d1],
    //     [a2, b2, c2, d2],
    //     [a3, b3, c3, d3],
    //     [a4, b4, c4, d4],
    //   ]
    // The result is in the following form:
    //   [ a1+a2+a3+a4, b1+b2+b3+b4, c1+c2+c3+c4, d1+d2+d3+d4]
    // Multiple things can be parallelized here. For example, all 4 entries in the result vector can be calculated in parallel
    // Also, each individual vector can be split into multiple batches and aggregating the batches can also be parallelized.
    void AsyncBuildQuorumVerificationVector(Span<BLSVerificationVectorPtr> vvecs, bool parallel,
                                            std::function<void(const BLSVerificationVectorPtr&)> doneCallback);
    std::future<BLSVerificationVectorPtr> AsyncBuildQuorumVerificationVector(Span<BLSVerificationVectorPtr> vvecs, bool parallel);
    BLSVerificationVectorPtr BuildQuorumVerificationVector(Span<BLSVerificationVectorPtr> vvecs, bool parallel = true);

    // The following functions are all used to aggregate single vectors
    // Inputs are in the following form:
    //   [a, b, c, d],
    // The result is simply a+b+c+d
    // Aggregation is parallelized by splitting up the input vector into multiple batches and then aggregating the individual batch results
    void AsyncAggregateSecretKeys(Span<CBLSSecretKey>,
                                  bool parallel,
                                  std::function<void(const CBLSSecretKey&)> doneCallback);
    std::future<CBLSSecretKey> AsyncAggregateSecretKeys(Span<CBLSSecretKey> secKeys, bool parallel);
    CBLSSecretKey AggregateSecretKeys(Span<CBLSSecretKey> secKeys, bool parallel = true);

    void AsyncAggregatePublicKeys(Span<CBLSPublicKey> pubKeys, bool parallel,
                                  std::function<void(const CBLSPublicKey&)> doneCallback);
    std::future<CBLSPublicKey> AsyncAggregatePublicKeys(Span<CBLSPublicKey> pubKeys, bool parallel);

    void AsyncAggregateSigs(Span<CBLSSignature> sigs, bool parallel,
                            std::function<void(const CBLSSignature&)> doneCallback);
    std::future<CBLSSignature> AsyncAggregateSigs(Span<CBLSSignature> sigs, bool parallel);

    // Calculate public key share from public key vector and id. Not parallelized
    static CBLSPublicKey BuildPubKeyShare(const BLSVerificationVectorPtr& vvec, const CBLSId& id);

    // The following functions verify multiple verification vectors and contributions for the same id
    // This is parallelized by performing batched verification. The verification vectors and the contributions of
    // a batch are aggregated (in parallel, see AsyncBuildQuorumVerificationVector and AsyncBuildSecretKeyShare). The
    // result per batch is a single aggregated verification vector and a single aggregated contribution, which are then
    // verified with VerifyContributionShare. If verification of the aggregated inputs is successful, the whole batch
    // is marked as valid. If the batch verification fails, the individual entries are verified in a non-aggregated manner
    void AsyncVerifyContributionShares(const CBLSId& forId, Span<BLSVerificationVectorPtr> vvecs, Span<CBLSSecretKey> skShares,
                                       bool parallel, bool aggregated, std::function<void(const std::vector<bool>&)> doneCallback);
    std::future<std::vector<bool> > AsyncVerifyContributionShares(const CBLSId& forId, Span<BLSVerificationVectorPtr> vvecs, Span<CBLSSecretKey> skShares,
                                                                  bool parallel, bool aggregated);
    std::vector<bool> VerifyContributionShares(const CBLSId& forId, Span<BLSVerificationVectorPtr> vvecs, Span<CBLSSecretKey> skShares,
                                               bool parallel = true, bool aggregated = true);

    std::future<bool> AsyncVerifyContributionShare(const CBLSId& forId, const BLSVerificationVectorPtr& vvec, const CBLSSecretKey& skContribution);

    // Simple verification of vectors. Checks x.IsValid() for every entry and checks for duplicate entries
    static bool VerifyVerificationVector(Span<CBLSPublicKey> vvec);
    static bool VerifyVerificationVectors(Span<BLSVerificationVectorPtr> vvecs);

    // Internally batched signature signing and verification
    void AsyncSign(const CBLSSecretKey& secKey, const uint256& msgHash, const SignDoneCallback& doneCallback);
    void AsyncVerifySig(const CBLSSignature& sig, const CBLSPublicKey& pubKey, const uint256& msgHash, SigVerifyDoneCallback doneCallback, CancelCond cancelCond = [] { return false; });
    std::future<bool> AsyncVerifySig(const CBLSSignature& sig, const CBLSPublicKey& pubKey, const uint256& msgHash, CancelCond cancelCond = [] { return false; });
    bool IsAsyncVerifyInProgress();

private:
    void PushSigVerifyBatch();
};

// Builds and caches different things from CBLSWorker
// Cache keys are provided externally as computing hashes on BLS vectors is too expensive
// If multiple threads try to build the same thing at the same time, only one will actually build it
// and the other ones will wait for the result of the first caller
class CBLSWorkerCache
{
private:
    CBLSWorker& worker;

    std::mutex cacheCs;
    std::map<uint256, std::shared_future<BLSVerificationVectorPtr> > vvecCache;
    std::map<uint256, std::shared_future<CBLSSecretKey> > secretKeyShareCache;
    std::map<uint256, std::shared_future<CBLSPublicKey> > publicKeyShareCache;

public:
    explicit CBLSWorkerCache(CBLSWorker& _worker) :
        worker(_worker) {}

    BLSVerificationVectorPtr BuildQuorumVerificationVector(const uint256& cacheKey, Span<BLSVerificationVectorPtr> vvecs)
    {
        return GetOrBuild(cacheKey, vvecCache, [this, &vvecs]() {
            return worker.BuildQuorumVerificationVector(vvecs);
        });
    }
    CBLSSecretKey AggregateSecretKeys(const uint256& cacheKey, Span<CBLSSecretKey> skShares)
    {
        return GetOrBuild(cacheKey, secretKeyShareCache, [this, &skShares]() {
            return worker.AggregateSecretKeys(skShares);
        });
    }
    CBLSPublicKey BuildPubKeyShare(const uint256& cacheKey, const BLSVerificationVectorPtr& vvec, const CBLSId& id)
    {
        return GetOrBuild(cacheKey, publicKeyShareCache, [&vvec, &id]() {
            return CBLSWorker::BuildPubKeyShare(vvec, id);
        });
    }

private:
    template <typename T, typename Builder>
    T GetOrBuild(const uint256& cacheKey, std::map<uint256, std::shared_future<T> >& cache, Builder&& builder)
    {
        cacheCs.lock();
        auto it = cache.find(cacheKey);
        if (it != cache.end()) {
            auto f = it->second;
            cacheCs.unlock();
            return f.get();
        }

        std::promise<T> p;
        cache.emplace(cacheKey, p.get_future());
        cacheCs.unlock();

        T v = builder();
        p.set_value(v);
        return v;
    }
};

#endif // SYSCOIN_BLS_BLS_WORKER_H
