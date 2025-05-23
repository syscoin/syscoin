// Copyright (c) 2018-2019 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <llmq/quorums_dkgsessionhandler.h>
#include <llmq/quorums_dkgsessionmgr.h>
#include <llmq/quorums_blockprocessor.h>
#include <llmq/quorums_commitment.h>
#include <llmq/quorums_debug.h>
#include <llmq/quorums_init.h>
#include <llmq/quorums_utils.h>
#include <evo/deterministicmns.h>
#include <masternode/activemasternode.h>
#include <chainparams.h>
#include <net_processing.h>
#include <spork.h>
#include <validation.h>
#include <shutdown.h>
#include <util/thread.h>
namespace llmq
{

void CDKGPendingMessages::PushPendingMessage(CNode* pfrom, CDataStream& vRecv)
{
    NodeId from = -1;
    if(pfrom)
        from = pfrom->GetId();
    // this will also consume the data, even if we bail out early
    auto pm = std::make_shared<CDataStream>(std::move(vRecv));
    CHashWriter hw(SER_GETHASH, 0);
    hw.write(AsWritableBytes(Span{*pm}));
    const uint256 hash = hw.GetHash();
    if(pfrom) {
        PeerRef peer = peerman.GetPeerRef(pfrom->GetId());
        if (peer)
            peerman.AddKnownTx(*peer, hash);
    }
    if(pfrom) {
        LOCK(cs_main);
        peerman.ReceivedResponse(from, hash);
    }
    LOCK2(cs_main, cs_messages);
    if (messagesPerNode[from] >= maxMessagesPerNode) {
        // TODO ban?
        LogPrint(BCLog::LLMQ_DKG, "CDKGPendingMessages::%s -- too many messages, peer=%d\n", __func__, from);
        return;
    }
    messagesPerNode[from]++;
    
    if (!seenMessages.emplace(hash).second) {
        if(pfrom)
            peerman.ForgetTxHash(from, hash);
        LogPrint(BCLog::LLMQ_DKG, "CDKGPendingMessages::%s -- already seen %s, peer=%d\n", __func__, hash.ToString(), from);
        return;
    }
    if(pfrom) {
        peerman.ForgetTxHash(from, hash);
    }
    pendingMessages.emplace_back(std::make_pair(from, std::move(pm)));
}

std::list<CDKGPendingMessages::BinaryMessage> CDKGPendingMessages::PopPendingMessages(size_t maxCount)
{
    LOCK(cs_messages);

    std::list<BinaryMessage> ret;
    while (!pendingMessages.empty() && ret.size() < maxCount) {
        ret.emplace_back(std::move(pendingMessages.front()));
        pendingMessages.pop_front();
    }

    return ret;
}

bool CDKGPendingMessages::HasSeen(const uint256& hash) const
{
    LOCK(cs_messages);
    return seenMessages.count(hash) != 0;
}

void CDKGPendingMessages::Clear()
{
    LOCK(cs_messages);
    pendingMessages.clear();
    messagesPerNode.clear();
    seenMessages.clear();
}

//////

CDKGSessionHandler::CDKGSessionHandler(CBLSWorker& _blsWorker, CDKGSessionManager& _dkgManager, PeerManager& _peerman, ChainstateManager& _chainman) :
    blsWorker(_blsWorker),
    dkgManager(_dkgManager),
    chainman(_chainman),
    curSession(std::make_unique<CDKGSession>(_blsWorker, _dkgManager)),
    pendingContributions((size_t)Params().GetConsensus().llmqTypeChainLocks.size * 2, _peerman), // we allow size*2 messages as we need to make sure we see bad behavior (double messages)
    pendingComplaints((size_t)Params().GetConsensus().llmqTypeChainLocks.size * 2, _peerman),
    pendingJustifications((size_t)Params().GetConsensus().llmqTypeChainLocks.size* 2, _peerman),
    pendingPrematureCommitments((size_t)Params().GetConsensus().llmqTypeChainLocks.size * 2, _peerman),
    peerman(_peerman)
{
}

void CDKGSessionHandler::UpdatedBlockTip(const CBlockIndex* pindexNew)
{
    LOCK(cs_phase_qhash);
    const auto& params = Params().GetConsensus().llmqTypeChainLocks;
    int quorumStageInt = pindexNew->nHeight % params.dkgInterval;
    const CBlockIndex* pQuorumBaseBlockIndex = pindexNew->GetAncestor(pindexNew->nHeight - quorumStageInt);

    currentHeight = pindexNew->nHeight;
    quorumHash = pQuorumBaseBlockIndex->GetBlockHash();

    bool fNewPhase = (quorumStageInt % params.dkgPhaseBlocks) == 0;
    int phaseInt = quorumStageInt / params.dkgPhaseBlocks + 1;
    QuorumPhase oldPhase = phase;
    if (fNewPhase && phaseInt >= QuorumPhase_Initialized && phaseInt <= QuorumPhase_Idle) {
        phase = static_cast<QuorumPhase>(phaseInt);
    }

    LogPrint(BCLog::LLMQ_DKG, "CDKGSessionHandler::%s -- currentHeight=%d, pQuorumBaseBlockIndex->nHeight=%d, oldPhase=%d, newPhase=%d\n", __func__,
            currentHeight, pQuorumBaseBlockIndex->nHeight, oldPhase, phase);
}

void CDKGSessionHandler::ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv)
{
    // We don't handle messages in the calling thread as deserialization/processing of these would block everything
    if (strCommand == NetMsgType::QCONTRIB) {
        pendingContributions.PushPendingMessage(pfrom, vRecv);
    } else if (strCommand == NetMsgType::QCOMPLAINT) {
        pendingComplaints.PushPendingMessage(pfrom, vRecv);
    } else if (strCommand == NetMsgType::QJUSTIFICATION) {
        pendingJustifications.PushPendingMessage(pfrom, vRecv);
    } else if (strCommand == NetMsgType::QPCOMMITMENT) {
        pendingPrematureCommitments.PushPendingMessage(pfrom, vRecv);
    }
}

void CDKGSessionHandler::StartThread()
{
    if (phaseHandlerThread.joinable()) {
        throw std::runtime_error("Tried to start an already started CDKGSessionHandler thread.");
    }
    phaseHandlerThread = std::thread(&util::TraceThread, GetName(), [this] { CDKGSessionHandler::PhaseHandlerThread(); });
}

void CDKGSessionHandler::StopThread()
{
    stopRequested = true;
    if (phaseHandlerThread.joinable()) {
        phaseHandlerThread.join();
    }
}

bool CDKGSessionHandler::InitNewQuorum(const CBlockIndex* pQuorumBaseBlockIndex)
{
    curSession = std::make_unique<CDKGSession>(blsWorker, dkgManager);

    if (!deterministicMNManager || !deterministicMNManager->IsDIP3Enforced(pQuorumBaseBlockIndex->nHeight)) {
        return false;
    }
    auto mns = CLLMQUtils::GetAllQuorumMembers(pQuorumBaseBlockIndex);

    if (!curSession->Init(pQuorumBaseBlockIndex, mns, WITH_LOCK(activeMasternodeInfoCs, return activeMasternodeInfo.proTxHash))) {
        LogPrintf("CDKGSessionManager::%s -- quorum initialization failed\n", __func__);
        return false;
    }

    return true;
}

std::pair<QuorumPhase, uint256> CDKGSessionHandler::GetPhaseAndQuorumHash() const
{
    LOCK(cs_phase_qhash);
    return std::make_pair(phase, quorumHash);
}

class AbortPhaseException : public std::exception {
};

void CDKGSessionHandler::WaitForNextPhase(std::optional<QuorumPhase> curPhase,
                                          QuorumPhase nextPhase,
                                          const uint256& expectedQuorumHash,
                                          const WhileWaitFunc& shouldNotWait) const
{
    LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- starting, curPhase=%d, nextPhase=%d\n", __func__, curPhase.has_value() ? *curPhase : -1, nextPhase);

    while (true) {
        if (stopRequested) {
            LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- aborting due to stop/shutdown requested\n", __func__);
            throw AbortPhaseException();
        }
        auto [_phase, _quorumHash] = GetPhaseAndQuorumHash();
        if (!expectedQuorumHash.IsNull() && _quorumHash != expectedQuorumHash) {
            LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- aborting due unexpected expectedQuorumHash change\n", __func__);
            throw AbortPhaseException();
        }
        if (_phase == nextPhase) {
            break;
        }
        if (curPhase.has_value() && _phase != curPhase) {
            LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- aborting due unexpected phase change, _phase=%d, curPhase=%d\n", __func__, _phase, curPhase.has_value() ? *curPhase : -1);
            throw AbortPhaseException();
        }
        if (!shouldNotWait()) {
            UninterruptibleSleep(std::chrono::milliseconds{100});
        }
    }

    LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- done, curPhase=%d, nextPhase=%d\n", __func__, curPhase.has_value() ? *curPhase : -1, nextPhase);

    if (nextPhase == QuorumPhase_Initialized) {
        quorumDKGDebugManager->ResetLocalSessionStatus();
    } else {
        quorumDKGDebugManager->UpdateLocalSessionStatus([&](CDKGDebugSessionStatus& status) {
            bool changed = status.phase != (uint8_t) nextPhase;
            status.phase = (uint8_t) nextPhase;
            return changed;
        });
    }
    
}

void CDKGSessionHandler::WaitForNewQuorum(const uint256& oldQuorumHash) const
{
    LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- starting\n", __func__);

    while (true) {
        if (stopRequested) {
            LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- aborting due to stop/shutdown requested\n", __func__);
            throw AbortPhaseException();
        }
        auto [_, _quorumHash] = GetPhaseAndQuorumHash();
        if (_quorumHash != oldQuorumHash) {
            break;
        }
        UninterruptibleSleep(std::chrono::milliseconds{100});
    }

    LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- done\n", __func__);
}

void CDKGSessionHandler::SleepBeforePhase(QuorumPhase curPhase,
                                          const uint256& expectedQuorumHash,
                                          double randomSleepFactor,
                                          const WhileWaitFunc& runWhileWaiting) const
{
    if (!curSession->AreWeMember()) {
        // Non-members do not participate and do not create any network load, no need to sleep.
        return;
    }

    if (Params().MineBlocksOnDemand()) {
        // On regtest, blocks can be mined on demand without any significant time passing between these.
        // We shouldn't wait before phases in this case.
        return;
    }
    const auto& params = Params().GetConsensus().llmqTypeChainLocks;
    // Two blocks can come very close to each other, this happens pretty regularly. We don't want to be
    // left behind and marked as a bad member. This means that we should not count the last block of the
    // phase as a safe one to keep sleeping, that's why we calculate the phase sleep time as a time of
    // the full phase minus one block here.
    double phaseSleepTime = (params.dkgPhaseBlocks - 1) * Params().GetConsensus().nPowTargetSpacing * 1000;
    // Expected phase sleep time per member
    double phaseSleepTimePerMember = phaseSleepTime / params.size;
    // Don't expect perfect block times and thus reduce the phase time to be on the secure side (caller chooses factor)
    double adjustedPhaseSleepTimePerMember = phaseSleepTimePerMember * randomSleepFactor;

    int64_t sleepTime = (int64_t)(adjustedPhaseSleepTimePerMember * curSession->GetMyMemberIndex().value_or(0));
    int64_t endTime = TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now()) + sleepTime;
    int heightTmp{currentHeight.load()};
    int heightStart{heightTmp};

    LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- %s - starting sleep for %d ms, curPhase=%d\n", __func__, params.name, sleepTime, curPhase);

    while (TicksSinceEpoch<std::chrono::milliseconds>(SystemClock::now()) < endTime) {
        if (stopRequested) {
            LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- %s - aborting due to stop/shutdown requested\n", __func__, params.name);
            throw AbortPhaseException();
        }
        auto cur_height = currentHeight.load();
        if (cur_height > heightTmp) {
            // New block(s) just came in
            int64_t expectedBlockTime = (cur_height - heightStart) * Params().GetConsensus().nPowTargetSpacing * 1000;
            if (expectedBlockTime > sleepTime) {
                // Blocks came faster than we expected, jump into the phase func asap
                break;
            }
            heightTmp = cur_height;
        }
        if (WITH_LOCK(cs_phase_qhash, return phase != curPhase || quorumHash != expectedQuorumHash)) {
            // Something went wrong and/or we missed quite a few blocks and it's just too late now
            LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- %s - aborting due unexpected phase/expectedQuorumHash change\n", __func__, params.name);
            throw AbortPhaseException();
        }
        if (!runWhileWaiting()) {
            UninterruptibleSleep(std::chrono::milliseconds{100});
        }
    }

    LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- %s - done, curPhase=%d\n", __func__, params.name, curPhase);
}

void CDKGSessionHandler::HandlePhase(QuorumPhase curPhase,
                                     QuorumPhase nextPhase,
                                     const uint256& expectedQuorumHash,
                                     double randomSleepFactor,
                                     const StartPhaseFunc& startPhaseFunc,
                                     const WhileWaitFunc& runWhileWaiting)
{
    LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- starting, curPhase=%d, nextPhase=%d\n", __func__, curPhase, nextPhase);

    SleepBeforePhase(curPhase, expectedQuorumHash, randomSleepFactor, runWhileWaiting);
    startPhaseFunc();
    WaitForNextPhase(curPhase, nextPhase, expectedQuorumHash, runWhileWaiting);

    LogPrint(BCLog::LLMQ_DKG, "CDKGSessionManager::%s -- done, curPhase=%d, nextPhase=%d\n", __func__, curPhase, nextPhase);
}

// returns a set of NodeIds which sent invalid messages
template<typename Message>
std::set<NodeId> BatchVerifyMessageSigs(CDKGSession& session, const std::vector<std::pair<NodeId, std::shared_ptr<Message>>>& messages)
{
    if (messages.empty()) {
        return {};
    }

    std::set<NodeId> ret;
    bool revertToSingleVerification = false;

    CBLSSignature aggSig;
    std::vector<CBLSPublicKey> pubKeys;
    std::vector<uint256> messageHashes;
    std::set<uint256> messageHashesSet;
    pubKeys.reserve(messages.size());
    messageHashes.reserve(messages.size());
    bool first = true;
    for (const auto& p : messages ) {
        const auto& msg = *p.second;

        auto member = session.GetMember(msg.proTxHash);
        if (!member) {
            // should not happen as it was verified before
            ret.emplace(p.first);
            continue;
        }

        if (first) {
            aggSig = msg.sig;
        } else {
            aggSig.AggregateInsecure(msg.sig);
        }
        first = false;

        auto msgHash = msg.GetSignHash();
        if (!messageHashesSet.emplace(msgHash).second) {
            // can only happen in 2 cases:
            // 1. Someone sent us the same message twice but with differing signature, meaning that at least one of them
            //    must be invalid. In this case, we'd have to revert to single message verification nevertheless
            // 2. Someone managed to find a way to create two different binary representations of a message that deserializes
            //    to the same object representation. This would be some form of malleability. However, this shouldn't be
            //    possible as only deterministic/unique BLS signatures and very simple data types are involved
            revertToSingleVerification = true;
            break;
        }

        pubKeys.emplace_back(member->dmn->pdmnState->pubKeyOperator.Get());
        messageHashes.emplace_back(msgHash);
    }
    if (!revertToSingleVerification) {
        if (aggSig.VerifyInsecureAggregated(pubKeys, messageHashes)) {
            // all good
            return ret;
        }

        // are all messages from the same node?
        bool nodeIdsAllSame = std::adjacent_find( messages.begin(), messages.end(), [](const auto& first, const auto& second){
            return first.first != second.first;
        }) == messages.end();

        // if yes, take a short path and return a set with only him
        if (nodeIdsAllSame) {
            ret.emplace(messages[0].first);
            return ret;
        }
        // different nodes, let's figure out who are the bad ones
    }

    for (const auto& p : messages) {
        if (ret.count(p.first)) {
            continue;
        }

        const auto& msg = *p.second;
        auto member = session.GetMember(msg.proTxHash);
        bool valid = msg.sig.VerifyInsecure(member->dmn->pdmnState->pubKeyOperator.Get(), msg.GetSignHash());
        if (!valid) {
            ret.emplace(p.first);
        }
    }
    return ret;
}

template<typename Message>
bool ProcessPendingMessageBatch(CDKGSession& session, CDKGPendingMessages& pendingMessages, size_t maxCount, PeerManager& peerman)
{
    const auto msgs = pendingMessages.PopAndDeserializeMessages<Message>(maxCount);
    if (msgs.empty()) {
        return false;
    }

    std::vector<uint256> hashes;
    std::vector<std::pair<NodeId, std::shared_ptr<Message>>> preverifiedMessages;
    hashes.reserve(msgs.size());
    preverifiedMessages.reserve(msgs.size());

    for (const auto& p : msgs) {
        PeerRef peer = peerman.GetPeerRef(p.first);
        if (!p.second) {
            LogPrint(BCLog::LLMQ_DKG, "%s -- failed to deserialize message, peer=%d\n", __func__, p.first);
            if(peer)
                peerman.Misbehaving(*peer, 100, "failed to deserialize message");
            continue;
        }
        const auto& msg = *p.second;

        const uint256 hash = ::SerializeHash(msg);
        if (peer)
            peerman.AddKnownTx(*peer, hash);
        {
            LOCK(cs_main);
            peerman.ReceivedResponse(p.first, hash);
        }

        bool ban = false;
        if (!session.PreVerifyMessage(msg, ban)) {
            if (ban) {
                {
                    LOCK(cs_main);
                    peerman.ForgetTxHash(p.first, hash);
                }
                LogPrint(BCLog::LLMQ_DKG, "%s -- banning node due to failed preverification, peer=%d\n", __func__, p.first);
                if(peer)
                    peerman.Misbehaving(*peer, 100, "banning node due to failed preverification");
            }
            LogPrint(BCLog::LLMQ_DKG, "%s -- skipping message due to failed preverification, peer=%d\n", __func__, p.first);
            continue;
        }
        hashes.emplace_back(hash);
        preverifiedMessages.emplace_back(p);
        {
            LOCK(cs_main);
            peerman.ForgetTxHash(p.first, hash);
        }
    }
    if (preverifiedMessages.empty()) {
        return true;
    }

    auto badNodes = BatchVerifyMessageSigs(session, preverifiedMessages);
    if (!badNodes.empty()) {
        for (auto nodeId : badNodes) {
            PeerRef peer = peerman.GetPeerRef(nodeId);
            LogPrint(BCLog::LLMQ_DKG, "%s -- failed to verify signature, peer=%d\n", __func__, nodeId);
            if(peer)
                peerman.Misbehaving(*peer, 100, "failed to verify signature");
        }
    }

    for (size_t i = 0; i < preverifiedMessages.size(); i++) {
        const NodeId &nodeId = preverifiedMessages[i].first;
        if (badNodes.count(nodeId)) {
            continue;
        }
        const auto& msg = *preverifiedMessages[i].second;
        session.ReceiveMessage(hashes[i], msg);
    }

    return true;
}

void CDKGSessionHandler::HandleDKGRound() {

    WaitForNextPhase(std::nullopt, QuorumPhase_Initialized, uint256(), []{return false;});

    pendingContributions.Clear();
    pendingComplaints.Clear();
    pendingJustifications.Clear();
    pendingPrematureCommitments.Clear();
    uint256 curQuorumHash = WITH_LOCK(cs_phase_qhash, return quorumHash);
    const CBlockIndex* pQuorumBaseBlockIndex = WITH_LOCK(cs_main, return chainman.m_blockman.LookupBlockIndex(curQuorumHash));

    if (!InitNewQuorum(pQuorumBaseBlockIndex)) {
        // should actually never happen
        WaitForNewQuorum(curQuorumHash);
        throw AbortPhaseException();
    }

    quorumDKGDebugManager->UpdateLocalSessionStatus([&](CDKGDebugSessionStatus& status) {
        bool changed = status.phase != (uint8_t) QuorumPhase_Initialized;
        status.phase = (uint8_t) QuorumPhase_Initialized;
        return changed;
    });

    CLLMQUtils::EnsureQuorumConnections(pQuorumBaseBlockIndex, curSession->myProTxHash, dkgManager.connman);
    if (curSession->AreWeMember()) {
        CLLMQUtils::AddQuorumProbeConnections(pQuorumBaseBlockIndex, curSession->myProTxHash, dkgManager.connman);
    }

    WaitForNextPhase(QuorumPhase_Initialized, QuorumPhase_Contribute, curQuorumHash, []{return false;});

    // Contribute
    auto fContributeStart = [this]() {
        curSession->Contribute(pendingContributions);
    };
    auto fContributeWait = [this] {
        return ProcessPendingMessageBatch<CDKGContribution>(*curSession, pendingContributions, 8, peerman);
    };
    HandlePhase(QuorumPhase_Contribute, QuorumPhase_Complain, curQuorumHash, 0.05, fContributeStart, fContributeWait);

    // Complain
    auto fComplainStart = [this]() {
        curSession->VerifyAndComplain(pendingComplaints);
    };
    auto fComplainWait = [this] {
        return ProcessPendingMessageBatch<CDKGComplaint>(*curSession, pendingComplaints, 8, peerman);
    };
    HandlePhase(QuorumPhase_Complain, QuorumPhase_Justify, curQuorumHash, 0.05, fComplainStart, fComplainWait);

    // Justify
    auto fJustifyStart = [this]() {
        curSession->VerifyAndJustify(pendingJustifications);
    };
    auto fJustifyWait = [this] {
        return ProcessPendingMessageBatch<CDKGJustification>(*curSession, pendingJustifications, 8, peerman);
    };
    HandlePhase(QuorumPhase_Justify, QuorumPhase_Commit, curQuorumHash, 0.05, fJustifyStart, fJustifyWait);

    // Commit
    auto fCommitStart = [this]() {
        curSession->VerifyAndCommit(pendingPrematureCommitments);
    };
    auto fCommitWait = [this] {
        return ProcessPendingMessageBatch<CDKGPrematureCommitment>(*curSession, pendingPrematureCommitments, 8, peerman);
    };
    HandlePhase(QuorumPhase_Commit, QuorumPhase_Finalize, curQuorumHash, 0.1, fCommitStart, fCommitWait);

    auto finalCommitments = curSession->FinalizeCommitments();
    for (const auto& fqc : finalCommitments) {
        if (auto inv_opt = quorumBlockProcessor->AddMineableCommitment(fqc); inv_opt.has_value()) {
            peerman.RelayInv(inv_opt.value());
        }
    }
}

void CDKGSessionHandler::PhaseHandlerThread()
{
    while (!stopRequested) {
        try {
            LogPrint(BCLog::LLMQ_DKG, "CDKGSessionHandler::%s -- starting HandleDKGRound\n", __func__);
            HandleDKGRound();
        } catch (AbortPhaseException& e) {
            quorumDKGDebugManager->UpdateLocalSessionStatus([&](CDKGDebugSessionStatus& status) {
                status.statusBits.aborted = true;
                return true;
            });
            LogPrint(BCLog::LLMQ_DKG, "CDKGSessionHandler::%s -- aborted current DKG session\n", __func__);
        }
    }
}


bool CDKGSessionHandler::GetContribution(const uint256& hash, CDKGContribution& ret) const
{
    LOCK(curSession->invCs);
    auto it = curSession->contributions.find(hash);
    if (it != curSession->contributions.end()) {
        ret = it->second;
        return true;
    }
    return false;
}

bool CDKGSessionHandler::GetComplaint(const uint256& hash, CDKGComplaint& ret) const
{
    LOCK(curSession->invCs);
    auto it = curSession->complaints.find(hash);
    if (it != curSession->complaints.end()) {
        ret = it->second;
        return true;
    }
    return false;
}

bool CDKGSessionHandler::GetJustification(const uint256& hash, CDKGJustification& ret) const
{
    LOCK(curSession->invCs);
    auto it = curSession->justifications.find(hash);
    if (it != curSession->justifications.end()) {
        ret = it->second;
        return true;
    }
    return false;
}

bool CDKGSessionHandler::GetPrematureCommitment(const uint256& hash, CDKGPrematureCommitment& ret) const
{
    LOCK(curSession->invCs);
    auto it = curSession->prematureCommitments.find(hash);
    if (it != curSession->prematureCommitments.end() && curSession->validCommitments.count(hash)) {
        ret = it->second;
        return true;
    }
    return false;
}
} // namespace llmq
