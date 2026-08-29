// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_NET_PROCESSING_H
#define SYSCOIN_NET_PROCESSING_H

#include <net.h>
#include <validationinterface.h>
#include <version.h> // SYSCOIN: PQ MNAUTH protocol gate.
// SYSCOIN
#include <headerssync.h>

// SYSCOIN: begin bounded fork peer-state support.
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <tuple>
#include <vector>
// SYSCOIN: end bounded fork peer-state support.

class AddrMan;
class CChainParams;
class CTxMemPool;
class ChainstateManager;
// SYSCOIN: begin fork-only peer-state declarations.
class GovernancePageImmutableSnapshot;
struct GovernancePageBuildResult;
struct Peer;
// SYSCOIN: end fork-only peer-state declarations.

/** Whether transaction reconciliation protocol should be enabled by default. */
static constexpr bool DEFAULT_TXRECONCILIATION_ENABLE{false};
/** Default for -maxorphantx, maximum number of orphan transactions kept in memory */
static const uint32_t DEFAULT_MAX_ORPHAN_TRANSACTIONS{100};
/** Default number of non-mempool transactions to keep around for block reconstruction. Includes
    orphan, replaced, and rejected transactions. */
static const uint32_t DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN{100};
static const bool DEFAULT_PEERBLOOMFILTERS = false;
static const bool DEFAULT_PEERBLOCKFILTERS = false;
/** Threshold for marking a node to be discouraged, e.g. disconnected and added to the discouragement filter. */
static const int DISCOURAGEMENT_THRESHOLD{100};
// SYSCOIN
/** The number of most recently announced transactions a peer can request. */
static const unsigned int INVENTORY_MAX_RECENT_RELAY = 35000;
/** Maximum number of outstanding CMPCTBLOCK requests for the same block. */
static const unsigned int MAX_CMPCTBLOCKS_INFLIGHT_PER_BLOCK = 3;

// SYSCOIN: begin bounded PQ ChainLock and governance relay admission.
/** PQ ChainLocks are never transaction relay, even though they use inventory. */
[[nodiscard]] bool IsActualTransactionInv(const CInv& inv) noexcept;
[[nodiscard]] bool SupportsPQChainLocks(int common_version) noexcept;
/** Quarantine downgrades an advertised masternode to an ordinary block peer. */
[[nodiscard]] bool ShouldClassifyRemoteMasternodeIdentity(
    bool participation_allowed, bool identity_advertised) noexcept;
/**
 * Whether a connection may carry bounded exact governance pages.
 *
 * Authenticated masternode links deliberately suppress generic relay, but
 * their exact page traffic remains source-bound and byte-limited.
 */
[[nodiscard]] bool CanUseGovernancePageProtocol(const CNode& node);
/** Structural and binding checks performed before admitting a page inventory. */
[[nodiscard]] bool IsValidGovernancePageResponse(
    const CGovernancePageRequest& request,
    const CGovernancePageResponse& response) noexcept;
/** Each independent PQ certificate request tracker admits two peer entries. */
[[nodiscard]] bool HasTooManyPQCertificateInvs(
    const std::vector<CInv>& inventory) noexcept;
/** Generic audits require live operation outside IBD; exact dependencies do not. */
[[nodiscard]] bool ShouldRequestPaymentAuditCertificate(
    bool operational, bool required_dependency,
    bool initial_block_download) noexcept;
/** A required dependency may promote a source already seen as generic. */
[[nodiscard]] bool ShouldProcessPQCertificateAnnouncement(
    bool peer_already_knows, bool required_dependency) noexcept;
/** Queue consensus-certificate inventory independently of transaction relay. */
[[nodiscard]] bool QueuePQCertificateInventory(Peer& peer,
                                               const CInv& inv);

/**
 * Consume-once authorization for serving a PQ ChainLock certificate.
 *
 * Final certificates are multi-megabyte objects. Only hashes explicitly
 * announced by us may be requested, repeating an INV never replenishes a
 * consumed authorization, and an explicit by-ID retry permits at most one
 * second upload per logical ID on the connection. Callers serialize access
 * with the peer's m_pq_certificate_mutex.
 */
class ChainLockUploadTracker final {
public:
    static constexpr std::size_t MAX_ANNOUNCED{2};
    static constexpr std::size_t MAX_UPLOAD_HISTORY{16};
    static constexpr uint8_t MAX_UPLOADS_PER_LOGICAL_ID{2};

    void Announce(const uint256& logical_id);
    [[nodiscard]] bool Reauthorize(const uint256& logical_id,
                                   bool upload_budget_reserved = false);
    [[nodiscard]] bool HasActiveTargetedAuthorization(
        const uint256& logical_id) const;
    void CancelTargetedAuthorization(const uint256& logical_id);
    [[nodiscard]] bool Consume(const uint256& logical_id,
                               bool* upload_budget_reserved = nullptr);

private:
    struct Authorization {
        uint256 logical_id;
        bool consumed{false};
        /** A targeted GET may not repeatedly reopen the same pending upload. */
        bool targeted_request_active{false};
        /** GETPQPOSE already charged the process-wide source bucket. */
        bool upload_budget_reserved{false};
    };

    std::vector<Authorization> m_authorizations;
    std::vector<std::pair<uint256, uint8_t>> m_upload_history;
};

/**
 * Reconnect-resistant bandwidth admission for PQ ChainLock uploads.
 *
 * The per-connection tracker above binds GETDATA to an announcement. This
 * process-wide bucket supplies the missing bandwidth bound: a reconnect keeps
 * the same authenticated proTx identity or keyed network group and therefore
 * cannot mint another burst of multi-megabyte responses.
 */
class ChainLockUploadRateLimiter final {
public:
    static constexpr std::size_t MAX_SOURCES{65536};
    static constexpr uint8_t BURST_UPLOADS{2};
    static constexpr auto REFILL_INTERVAL{std::chrono::minutes{5}};
    static constexpr auto SOURCE_EXPIRY{std::chrono::hours{24}};

    [[nodiscard]] bool Consume(
        const uint256& authenticated_pro_tx, uint64_t keyed_net_group,
        std::chrono::microseconds now);
    [[nodiscard]] std::size_t Size() const noexcept { return m_buckets.size(); }

private:
    struct SourceIdentity {
        uint256 authenticated_pro_tx;
        uint64_t keyed_net_group{0};

        friend bool operator<(const SourceIdentity& lhs,
                              const SourceIdentity& rhs)
        {
            return std::tie(lhs.authenticated_pro_tx,
                            lhs.keyed_net_group) <
                   std::tie(rhs.authenticated_pro_tx,
                            rhs.keyed_net_group);
        }
    };

    struct Bucket {
        uint8_t tokens{BURST_UPLOADS};
        std::chrono::microseconds last_refill{0};
        std::chrono::microseconds last_seen{0};
    };

    std::map<SourceIdentity, Bucket> m_buckets;
};

/**
 * Admission state for multi-megabyte PQ ChainLock certificates.
 *
 * Keeping this separate from TxRequestTracker prevents one peer from turning
 * thousands of cheap inventory announcements into concurrent 1,000,364-byte
 * downloads. Callers serialize access with cs_main.
 */
class ChainLockRequestTracker final {
public:
    static constexpr std::size_t MAX_ANNOUNCEMENTS_PER_PEER{2};
    // One fake ID cannot consume the global table, while eight sources still
    // leave ample room for honest alternate-peer retry.
    static constexpr std::size_t MAX_ANNOUNCERS_PER_LOGICAL_ID{8};
    /** Maximum generic announcements; the one required ID is counted apart. */
    static constexpr std::size_t MAX_ANNOUNCEMENTS{128};
    static constexpr std::size_t MAX_IN_FLIGHT{2};
    static constexpr std::size_t MAX_UNTRUSTED_IN_FLIGHT{1};
    static constexpr std::size_t MAX_CANCELLED_PER_PEER{4};
    static constexpr auto SOURCE_FAILURE_COOLDOWN{std::chrono::minutes{2}};

    enum class SourcePriority : uint8_t {
        INBOUND = 0,
        AUTHENTICATED = 1,
        OUTBOUND = 2,
        AUTHENTICATED_OUTBOUND = 3,
    };

    struct SourceIdentity {
        uint256 authenticated_pro_tx;
        uint64_t keyed_net_group{0};
        NodeId fallback_peer{-1};

        friend bool operator==(const SourceIdentity&,
                               const SourceIdentity&) = default;
        friend bool operator<(const SourceIdentity& lhs,
                              const SourceIdentity& rhs)
        {
            return std::tie(lhs.authenticated_pro_tx,
                            lhs.keyed_net_group,
                            lhs.fallback_peer) <
                   std::tie(rhs.authenticated_pro_tx,
                            rhs.keyed_net_group,
                            rhs.fallback_peer);
        }
    };

    struct Announcement {
        uint256 logical_id;
        SourcePriority priority{SourcePriority::INBOUND};
        SourceIdentity source_identity;
        /** The exact certificate currently blocking best-chain activation. */
        bool required{false};
        uint64_t sequence{0};

        friend bool operator==(const Announcement&,
                               const Announcement&) = default;
    };

    struct InFlight {
        NodeId peer{-1};
        uint256 logical_id;
        std::chrono::microseconds expiry{0};
        SourcePriority priority{SourcePriority::INBOUND};
        SourceIdentity source_identity;
        bool required{false};
        std::size_t advertiser_count{0};

        friend bool operator==(const InFlight&, const InFlight&) = default;
    };

    struct Cancelled {
        uint256 logical_id;
        std::chrono::microseconds expiry{0};
    };

    [[nodiscard]] bool Announce(
        NodeId peer, const uint256& logical_id,
        SourcePriority priority = SourcePriority::INBOUND,
        bool required = false,
        const uint256& authenticated_pro_tx = {},
        uint64_t keyed_net_group = 0);
    [[nodiscard]] std::optional<uint256> Request(NodeId peer,
                                                 std::chrono::microseconds now,
                                                 std::chrono::microseconds expiry,
                                                 std::vector<InFlight>* expired = nullptr);
    [[nodiscard]] bool IsRequested(NodeId peer, const uint256& logical_id) const;
    [[nodiscard]] std::optional<uint256> RequestedBy(NodeId peer) const;
    [[nodiscard]] std::optional<uint256> RequiredLogicalId() const;
    [[nodiscard]] bool TakeCancelled(
        NodeId peer, const uint256& logical_id,
        std::chrono::microseconds now);
    [[nodiscard]] bool HasCancelled(
        NodeId peer, std::chrono::microseconds now) const;
    void ClearRequired(const uint256& logical_id);
    void ReceivedResponse(NodeId peer, const uint256& logical_id);
    [[nodiscard]] bool ReceivedFailure(
        NodeId peer, const uint256& logical_id,
        std::chrono::microseconds now);
    void UpdateSourceIdentity(NodeId peer,
                              const uint256& authenticated_pro_tx,
                              uint64_t keyed_net_group,
                              SourcePriority priority);
    void Forget(const uint256& logical_id);
    void DisconnectedPeer(NodeId peer, std::chrono::microseconds now);
    [[nodiscard]] std::size_t Count(NodeId peer) const;
    [[nodiscard]] std::size_t Size() const;

private:
    [[nodiscard]] static SourceIdentity IdentifySource(
        NodeId peer, const uint256& authenticated_pro_tx,
        uint64_t keyed_net_group);
    void EraseAnnouncement(NodeId peer, const uint256& logical_id);
    [[nodiscard]] bool HasAnnouncement(const uint256& logical_id) const;
    void RequeueAnnouncement(const uint256& logical_id);
    void RememberCancelled(NodeId peer, const uint256& logical_id,
                           std::chrono::microseconds expiry);
    void Expire(std::chrono::microseconds now,
                std::vector<InFlight>* expired);

    std::map<NodeId, std::vector<Announcement>> m_announcements;
    std::vector<InFlight> m_in_flight;
    std::map<NodeId, std::vector<Cancelled>> m_cancelled;
    std::map<SourceIdentity, std::chrono::microseconds> m_cooldowns;
    std::set<uint256> m_attempted;
    std::optional<uint256> m_required_logical_id;
    uint64_t m_sequence{0};
};

/**
 * Admission state for governance payloads that can require global-key SLH
 * verification.
 *
 * The transport peer is part of every request key. A relay is not required to
 * be the claimed governance signer, but an unsolicited payload from another
 * peer can never consume or inherit the request. The single in-flight slot and
 * verification cadence bound aggregate CPU independently of Sybil count.
 */
class GovernanceRequestTracker final {
public:
    static constexpr std::size_t MAX_ANNOUNCEMENTS_PER_PEER{2};
    static constexpr std::size_t MAX_ANNOUNCEMENTS{32};
    static constexpr std::size_t SOURCE_BURST{2};
    static constexpr auto SOURCE_REFILL_INTERVAL{std::chrono::seconds{2}};
    static constexpr auto MIN_VERIFICATION_INTERVAL{
        std::chrono::milliseconds{250}};
    static constexpr auto SOURCE_FAILURE_COOLDOWN{
        std::chrono::minutes{5}};

    struct Source {
        NodeId peer{-1};
        uint64_t keyed_net_group{0};
        uint256 authenticated_pro_tx;
        bool outbound{false};
    };

    struct InFlight {
        Source source;
        CInv inv;
        std::chrono::microseconds expiry{0};
        uint64_t request_id{0};
        bool page_required{false};
        bool verifying{false};
    };

    enum class ResponseOutcome : uint8_t {
        VALID_OR_EXACT_KNOWN,
        VALID_SUPERSEDED,
        VALID_ORPHAN_STORED,
        NOT_FOUND,
        PAYLOAD_INVALID,
        PAGE_INVALID,
        LOCAL_CONTEXT_CHANGED,
    };

    struct ResponseAuthorization {
        uint64_t request_id{0};
        NodeId peer{-1};
        CInv inv;
        bool page_required{false};
        uint256 page_scope;
        Source page_source;
    };

    struct PageResult {
        Source source;
        CGovernancePageRequest request;
        std::optional<CGovernancePageResponse> response;
        bool success{false};
    };

    [[nodiscard]] bool Announce(const Source& source, const CInv& inv);
    /** Lease the governance request lane and two admission slots. */
    [[nodiscard]] bool BeginPageSession(
        const Source& source, std::chrono::microseconds now);
    /** Move an existing lease without reopening its admission budget. */
    [[nodiscard]] bool SetPageSessionSource(
        const Source& source, std::chrono::microseconds now);
    /** Cancel any pending page and release the governance lane lease. */
    void EndPageSession();
    /** Begin one cursor-bound page inside the active session. */
    [[nodiscard]] bool BeginPage(
        const CGovernancePageRequest& request,
        std::chrono::microseconds now,
        std::chrono::microseconds expiry);
    [[nodiscard]] bool IsPageRequested(
        NodeId peer, const CGovernancePageResponse& response) const;
    /** Bind a valid page and mark locally missing entries as required. */
    [[nodiscard]] bool ReceivedPage(
        NodeId peer, const CGovernancePageResponse& response,
        const std::vector<CInv>& missing,
        std::chrono::microseconds now);
    [[nodiscard]] std::optional<PageResult> TakePageResult(
        std::chrono::microseconds now);
    [[nodiscard]] bool HasActivePage() const noexcept
    {
        return m_page.has_value();
    }
    [[nodiscard]] bool HasActivePageSession() const noexcept
    {
        return m_page_session.has_value();
    }
    [[nodiscard]] std::optional<CInv> Request(
        NodeId peer, std::chrono::microseconds now,
        std::chrono::microseconds expiry,
        std::optional<InFlight>* expired = nullptr);
    [[nodiscard]] bool IsRequested(NodeId peer, const CInv& inv) const;
    /** Bind one delivered payload to this exact request attempt. */
    [[nodiscard]] std::optional<ResponseAuthorization>
    BeginResponse(NodeId peer, const CInv& inv,
                  std::chrono::microseconds now);
    /** Complete semantic validation and only then advance a page. */
    [[nodiscard]] bool CompleteResponse(
        const ResponseAuthorization& authorization, ResponseOutcome outcome,
        std::chrono::microseconds now);
    /** Consume an exact payload response and start the verification cadence. */
    [[nodiscard]] bool ReceivedResponse(NodeId peer, const CInv& inv,
                                        std::chrono::microseconds now);
    /** Consume an exact NOTFOUND without charging the verification cadence. */
    [[nodiscard]] bool ReceivedNotFound(NodeId peer, const CInv& inv,
                                        std::chrono::microseconds now);
    /** Fail one exact source without committing its cursor-bound page. */
    [[nodiscard]] bool ReceivedFailure(NodeId peer, const CInv& inv,
                                       std::chrono::microseconds now);
    /** Release transport authorization after a local context race only. */
    [[nodiscard]] bool ReceivedLocalFailure(
        NodeId peer, const CInv& inv, std::chrono::microseconds now);
    /** Reject a bound page response before it can name payloads. */
    [[nodiscard]] bool RejectPage(NodeId peer,
                                  const CGovernancePageResponse& response,
                                  std::chrono::microseconds now);
    /** Cool the active page source after bounded canonical restart churn. */
    [[nodiscard]] bool FailPageSource(NodeId expected_peer,
                                      std::chrono::microseconds now);
    // SYSCOIN: preserve source history when MNAUTH replaces a netgroup key.
    void UpdateSourceIdentity(NodeId peer,
                              const uint256& authenticated_pro_tx,
                              uint64_t keyed_net_group, bool outbound);
    void Forget(const CInv& inv);
    void DisconnectedPeer(NodeId peer, std::chrono::microseconds now);
    [[nodiscard]] std::size_t Count(NodeId peer) const;
    [[nodiscard]] std::size_t CountInFlight(NodeId peer) const;
    [[nodiscard]] std::size_t Size() const;
    /** Whether this exact transport identity may start or resume page work. */
    [[nodiscard]] bool CanUsePageSource(
        const Source& source, std::chrono::microseconds now) const;

private:
    static constexpr std::size_t MAX_SOURCE_RECORDS{512};

    struct SourceKey {
        bool authenticated{false};
        uint256 pro_tx_hash;
        uint64_t keyed_net_group{0};
        NodeId fallback_peer{-1};

        friend bool operator<(const SourceKey& lhs,
                              const SourceKey& rhs) noexcept
        {
            return std::tie(lhs.authenticated, lhs.pro_tx_hash,
                            lhs.keyed_net_group, lhs.fallback_peer) <
                   std::tie(rhs.authenticated, rhs.pro_tx_hash,
                            rhs.keyed_net_group, rhs.fallback_peer);
        }

        friend bool operator==(const SourceKey&,
                               const SourceKey&) noexcept = default;
    };

    struct SourceRate {
        std::size_t tokens{SOURCE_BURST};
        std::chrono::microseconds last_refill{0};
        std::chrono::microseconds last_seen{0};
        std::chrono::microseconds failure_cooldown_until{0};
    };

    struct PreAuthFailure {
        uint64_t keyed_net_group{0};
        std::chrono::microseconds cooldown_until{0};
    };

    struct SourceKeys {
        std::array<SourceKey, 2> keys;
        std::size_t size{0};
    };

    struct Announcements {
        Source source;
        std::vector<CInv> invs;
        uint64_t sequence{0};
        std::vector<CInv> deferred_invs;
    };

    struct PageState {
        CGovernancePageRequest request;
        std::chrono::microseconds deadline{0};
        std::chrono::microseconds response_deadline{0};
        bool response_received{false};
        bool failed{false};
        std::optional<CGovernancePageResponse> response;
        std::vector<CInv> required;
    };

    struct PageSession {
        Source source;
        bool source_connected{true};
        // One live-relay request may escape each successfully begun page.
        // Exact page payloads still have exclusive priority while required.
        bool ordinary_request_credit{false};
    };

    [[nodiscard]] static bool IsGovernanceInv(const CInv& inv) noexcept;
    [[nodiscard]] static bool SameInv(const CInv& lhs,
                                      const CInv& rhs) noexcept;
    [[nodiscard]] static bool IsDeferred(
        const Announcements& announcements, const CInv& inv) noexcept;
    static void ClearDeferred(Announcements& announcements,
                              const CInv& inv);
    void EraseAnnouncement(NodeId peer, const CInv& inv);
    void RotateAnnouncement(NodeId peer, const CInv& inv);
    [[nodiscard]] std::size_t AnnouncementSize() const;
    [[nodiscard]] bool ReservePageCapacity(const Source& source);
    void Expire(std::chrono::microseconds now,
                std::optional<InFlight>* expired);
    void ExpirePage(std::chrono::microseconds now);
    void ResolvePageInv(const CInv& inv);
    [[nodiscard]] std::optional<Source> SelectPageSource(
        std::chrono::microseconds now) const;
    [[nodiscard]] static SourceKeys GetSourceKeys(
        const Source& source) noexcept;
    [[nodiscard]] static int GetSourcePriority(const Source& source) noexcept;
    [[nodiscard]] bool IsSourceCoolingDown(
        const Source& source, std::chrono::microseconds now) const;
    [[nodiscard]] bool CanConsumeSourceBudget(
        const Source& source, std::chrono::microseconds now) const;
    [[nodiscard]] bool ConsumeSourceBudget(const Source& source,
                                           std::chrono::microseconds now);
    void RecordMetadataFailure(const Source& source,
                               std::chrono::microseconds now);
    void RecordSourceFailure(const Source& source,
                             std::chrono::microseconds now);
    [[nodiscard]] SourceRate& GetOrCreateSourceRate(
        const SourceKey& key, const SourceKeys& protected_keys,
        std::chrono::microseconds now);
    static void RefillSourceRate(SourceRate& rate,
                                 std::chrono::microseconds now);
    [[nodiscard]] uint64_t NextRequestId() noexcept;

    std::map<NodeId, Announcements> m_announcements;
    std::map<SourceKey, SourceRate> m_source_rates;
    std::map<NodeId, PreAuthFailure> m_pre_auth_failures;
    std::optional<InFlight> m_in_flight;
    std::optional<PageSession> m_page_session;
    std::optional<PageState> m_page;
    std::chrono::microseconds m_next_request_time{0};
    std::chrono::microseconds m_next_page_time{0};
    uint64_t m_sequence{0};
    uint64_t m_next_request_id{1};
    uint64_t m_last_page_nonce{0};
};
// SYSCOIN: end bounded PQ ChainLock and governance relay admission.

struct CNodeStateStats {
    int nSyncHeight = -1;
    int nCommonHeight = -1;
    int m_starting_height = -1;
    std::chrono::microseconds m_ping_wait;
    std::vector<int> vHeightInFlight;
    bool m_relay_txs;
    CAmount m_fee_filter_received;
    uint64_t m_addr_processed = 0;
    uint64_t m_addr_rate_limited = 0;
    bool m_addr_relay_enabled{false};
    ServiceFlags their_services;
    int64_t presync_height{-1};
};
// SYSCOIN
extern RecursiveMutex g_cs_orphans;
/** Data structure for an individual peer. This struct is not protected by
 * cs_main since it does not contain validation-critical data.
 *
 * Memory is owned by shared pointers and this object is destructed when
 * the refcount drops to zero.
 *
 * Mutexes inside this struct must not be held when locking m_peer_mutex.
 *
 * TODO: move most members from CNodeState to this structure.
 * TODO: move remaining application-layer data members from CNode to this structure.
 */
struct Peer {
    /** Same id as the CNode object for this peer */
    const NodeId m_id{0};

    /** Services we offered to this peer.
     *
     *  This is supplied by CConnman during peer initialization. It's const
     *  because there is no protocol defined for renegotiating services
     *  initially offered to a peer. The set of local services we offer should
     *  not change after initialization.
     *
     *  An interesting example of this is NODE_NETWORK and initial block
     *  download: a node which starts up from scratch doesn't have any blocks
     *  to serve, but still advertises NODE_NETWORK because it will eventually
     *  fulfill this role after IBD completes. P2P code is written in such a
     *  way that it can gracefully handle peers who don't make good on their
     *  service advertisements. */
    const ServiceFlags m_our_services;
    /** Services this peer offered to us. */
    std::atomic<ServiceFlags> m_their_services{NODE_NONE};
    /** SYSCOIN: Negotiated version used to gate fork-specific inventory relay. */
    std::atomic<int> m_common_version{INIT_PROTO_VERSION};

    /** Protects misbehavior data members */
    Mutex m_misbehavior_mutex;
    /** Accumulated misbehavior score for this peer */
    int m_misbehavior_score GUARDED_BY(m_misbehavior_mutex){0};
    /** Whether this peer should be disconnected and marked as discouraged (unless it has NetPermissionFlags::NoBan permission). */
    bool m_should_discourage GUARDED_BY(m_misbehavior_mutex){false};

    /** Protects block inventory data members */
    Mutex m_block_inv_mutex;
    /** List of blocks that we'll announce via an `inv` message.
     * There is no final sorting before sending, as they are always sent
     * immediately and in the order requested. */
    std::vector<uint256> m_blocks_for_inv_relay GUARDED_BY(m_block_inv_mutex);
    /** Unfiltered list of blocks that we'd like to announce via a `headers`
     * message. If we can't announce via a `headers` message, we'll fall back to
     * announcing via `inv`. */
    std::vector<uint256> m_blocks_for_headers_relay GUARDED_BY(m_block_inv_mutex);
    /** The final block hash that we sent in an `inv` message to this peer.
     * When the peer requests this block, we send an `inv` message to trigger
     * the peer to request the next sequence of block hashes.
     * Most peers use headers-first syncing, which doesn't use this mechanism */
    uint256 m_continuation_block GUARDED_BY(m_block_inv_mutex) {};

    /** This peer's reported block height when we connected */
    std::atomic<int> m_starting_height{-1};

    /** The pong reply we're expecting, or 0 if no pong expected. */
    std::atomic<uint64_t> m_ping_nonce_sent{0};
    /** When the last ping was sent, or 0 if no ping was ever sent */
    std::atomic<std::chrono::microseconds> m_ping_start{0us};
    /** Whether a ping has been requested by the user */
    std::atomic<bool> m_ping_queued{false};

    /** Whether this peer relays txs via wtxid */
    std::atomic<bool> m_wtxid_relay{false};
    /** The feerate in the most recent BIP133 `feefilter` message sent to the peer.
     *  It is *not* a p2p protocol violation for the peer to send us
     *  transactions with a lower fee rate than this. See BIP133. */
    CAmount m_fee_filter_sent GUARDED_BY(NetEventsInterface::g_msgproc_mutex){0};
    /** Timestamp after which we will send the next BIP133 `feefilter` message
      * to the peer. */
    std::chrono::microseconds m_next_send_feefilter GUARDED_BY(NetEventsInterface::g_msgproc_mutex){0};

    /** SYSCOIN: Consensus-certificate relay exists even when TxRelay is absent. */
    mutable Mutex m_pq_certificate_mutex;
    CRollingBloomFilter m_pq_certificate_known_filter
        GUARDED_BY(m_pq_certificate_mutex){64, 0.000001};
    std::vector<CInv> m_pq_certificates_to_send
        GUARDED_BY(m_pq_certificate_mutex);
    ChainLockUploadTracker m_clsig_uploads
        GUARDED_BY(m_pq_certificate_mutex);
    ChainLockUploadTracker m_payment_audit_uploads
        GUARDED_BY(m_pq_certificate_mutex);

    // SYSCOIN: Bind bounded governance page and upload leases to each peer
    // independently of transaction and consensus-certificate relay state.
    struct GovernancePageUpload {
        uint256 scope_hash;
        std::chrono::microseconds expiry{0};
        bool exact_page{false};
        std::shared_ptr<const GovernancePageImmutableSnapshot> snapshot;
        std::size_t entry_index{0};
    };
    // A live INV must remain requestable while two exact page commitments are
    // outstanding, without granting an unbounded generic upload lane.
    static constexpr std::size_t MAX_GOVERNANCE_ORDINARY_UPLOADS{1};
    static constexpr std::size_t MAX_GOVERNANCE_UPLOADS{
        MAX_GOVERNANCE_PAGE_INVENTORY +
        MAX_GOVERNANCE_ORDINARY_UPLOADS};
    static constexpr std::chrono::seconds
        GOVERNANCE_ORDINARY_UPLOAD_LIFETIME{30};
    static constexpr std::size_t MAX_RETIRED_GOVERNANCE_ORDINARY_UPLOADS{
        std::chrono::duration_cast<std::chrono::seconds>(
            GOVERNANCE_PAGE_TRANSFER_TIMEOUT).count() /
        GOVERNANCE_ORDINARY_UPLOAD_LIFETIME.count()};
    struct GovernancePageServeSession {
        uint64_t generation{0};
        std::shared_ptr<const GovernancePageImmutableSnapshot> snapshot;
        uint256 scope_hash;
        uint256 view_id;
        uint256 expected_cursor;
        uint64_t last_nonce{0};
        uint8_t cursor_zero_restarts{0};
        std::chrono::microseconds idle_expiry{0};
        std::chrono::microseconds hard_expiry{0};
    };
    struct GovernancePageServePhase {
        bool object_done{false};
        uint256 last_vote_scope;
        std::chrono::microseconds expiry{0};
    };
    // GOVPAGE is a direct, bounded authorization. Keep the parent scope so a
    // vote can be served from its authoritative VoteFile after LRU eviction.
    mutable Mutex m_governance_page_upload_mutex;
    std::map<CInv, GovernancePageUpload> m_governance_page_uploads
        GUARDED_BY(m_governance_page_upload_mutex);
    // Expiring the active relay lane must not revoke an INV while the
    // receiver can still be occupied by a bounded page transfer. Retired
    // grants remain exact, one-shot, and do not block newer live INVs.
    std::map<CInv, std::chrono::microseconds>
        m_retired_governance_ordinary_uploads
            GUARDED_BY(m_governance_page_upload_mutex);
    std::optional<GovernancePageServeSession>
        m_governance_page_serve_session
            GUARDED_BY(m_governance_page_upload_mutex);
    std::optional<GovernancePageServePhase>
        m_governance_page_serve_phase
            GUARDED_BY(m_governance_page_upload_mutex);
    uint64_t m_next_governance_page_serve_generation
        GUARDED_BY(m_governance_page_upload_mutex){1};
    uint64_t m_last_governance_page_serve_nonce
        GUARDED_BY(m_governance_page_upload_mutex){0};

    struct TxRelay {
        mutable RecursiveMutex m_bloom_filter_mutex;
        /** Whether we relay transactions to this peer. */
        bool m_relay_txs GUARDED_BY(m_bloom_filter_mutex){false};
        /** A bloom filter for which transactions to announce to the peer. See BIP37. */
        std::unique_ptr<CBloomFilter> m_bloom_filter PT_GUARDED_BY(m_bloom_filter_mutex) GUARDED_BY(m_bloom_filter_mutex){nullptr};
  
        mutable RecursiveMutex m_tx_inventory_mutex;
        /** A filter of all the (w)txids that the peer has announced to
         *  us or we have announced to the peer. We use this to avoid announcing
         *  he same (w)txid to a peer that already has the transaction. */
        CRollingBloomFilter m_tx_inventory_known_filter GUARDED_BY(m_tx_inventory_mutex){50000, 0.000001};
        /** Set of transaction ids we still have to announce (txid for
         *  non-wtxid-relay peers, wtxid for wtxid-relay peers). We use the
         *  mempool to sort transactions in dependency order before relay, so
         *  this does not have to be sorted. */
        std::set<uint256> m_tx_inventory_to_send GUARDED_BY(m_tx_inventory_mutex);
        /** Whether the peer has requested us to send our complete mempool. Only
         *  permitted if the peer has NetPermissionFlags::Mempool or we advertise
         *  NODE_BLOOM. See BIP35. */
        bool m_send_mempool GUARDED_BY(m_tx_inventory_mutex){false};
        // SYSCOIN
         /** The mempool sequence num at which we sent the last `inv` message to this peer.
         *  Can relay txs with lower sequence numbers than this (see CTxMempool::info_for_relay). */
        uint64_t m_last_inv_sequence GUARDED_BY(NetEventsInterface::g_msgproc_mutex){1};
        /** The next time after which we will send an `inv` message containing
         *  transaction announcements to this peer. */
        std::chrono::microseconds m_next_inv_send_time GUARDED_BY(m_tx_inventory_mutex){0};

        /** Minimum fee rate with which to filter transaction announcements to this node. See BIP133. */
        std::atomic<CAmount> m_fee_filter_received{0};
        // SYSCOIN
        std::set<CInv> m_tx_inventory_to_send_other GUARDED_BY(m_tx_inventory_mutex);
    };

    /* Initializes a TxRelay struct for this peer. Can be called at most once for a peer. */
    TxRelay* SetTxRelay() EXCLUSIVE_LOCKS_REQUIRED(!m_tx_relay_mutex)
    {
        LOCK(m_tx_relay_mutex);
        Assume(!m_tx_relay);
        m_tx_relay = std::make_unique<Peer::TxRelay>();
        return m_tx_relay.get();
    };

    TxRelay* GetTxRelay() EXCLUSIVE_LOCKS_REQUIRED(!m_tx_relay_mutex)
    {
        return WITH_LOCK(m_tx_relay_mutex, return m_tx_relay.get());
    };

    /** A vector of addresses to send to the peer, limited to MAX_ADDR_TO_SEND. */
    std::vector<CAddress> m_addrs_to_send GUARDED_BY(NetEventsInterface::g_msgproc_mutex);
    /** Probabilistic filter to track recent addr messages relayed with this
     *  peer. Used to avoid relaying redundant addresses to this peer.
     *
     *  We initialize this filter for outbound peers (other than
     *  block-relay-only connections) or when an inbound peer sends us an
     *  address related message (ADDR, ADDRV2, GETADDR).
     *
     *  Presence of this filter must correlate with m_addr_relay_enabled.
     **/
    std::unique_ptr<CRollingBloomFilter> m_addr_known GUARDED_BY(NetEventsInterface::g_msgproc_mutex);
    /** Whether we are participating in address relay with this connection.
     *
     *  We set this bool to true for outbound peers (other than
     *  block-relay-only connections), or when an inbound peer sends us an
     *  address related message (ADDR, ADDRV2, GETADDR).
     *
     *  We use this bool to decide whether a peer is eligible for gossiping
     *  addr messages. This avoids relaying to peers that are unlikely to
     *  forward them, effectively blackholing self announcements. Reasons
     *  peers might support addr relay on the link include that they connected
     *  to us as a block-relay-only peer or they are a light client.
     *
     *  This field must correlate with whether m_addr_known has been
     *  initialized.*/
    std::atomic_bool m_addr_relay_enabled{false};
    /** Whether a getaddr request to this peer is outstanding. */
    bool m_getaddr_sent GUARDED_BY(NetEventsInterface::g_msgproc_mutex){false};
    /** Guards address sending timers. */
    mutable Mutex m_addr_send_times_mutex;
    /** Time point to send the next ADDR message to this peer. */
    std::chrono::microseconds m_next_addr_send GUARDED_BY(m_addr_send_times_mutex){0};
    /** Time point to possibly re-announce our local address to this peer. */
    std::chrono::microseconds m_next_local_addr_send GUARDED_BY(m_addr_send_times_mutex){0};
    /** Whether the peer has signaled support for receiving ADDRv2 (BIP155)
     *  messages, indicating a preference to receive ADDRv2 instead of ADDR ones. */
    std::atomic_bool m_wants_addrv2{false};
    /** Whether this peer has already sent us a getaddr message. */
    bool m_getaddr_recvd GUARDED_BY(NetEventsInterface::g_msgproc_mutex){false};
    /** Number of addresses that can be processed from this peer. Start at 1 to
     *  permit self-announcement. */
    double m_addr_token_bucket GUARDED_BY(NetEventsInterface::g_msgproc_mutex){1.0};
    /** When m_addr_token_bucket was last updated */
    std::chrono::microseconds m_addr_token_timestamp GUARDED_BY(NetEventsInterface::g_msgproc_mutex){GetTime<std::chrono::microseconds>()};
    /** Total number of addresses that were dropped due to rate limiting. */
    std::atomic<uint64_t> m_addr_rate_limited{0};
    /** Total number of addresses that were processed (excludes rate-limited ones). */
    std::atomic<uint64_t> m_addr_processed{0};

    /** Whether we've sent this peer a getheaders in response to an inv prior to initial-headers-sync completing */
    bool m_inv_triggered_getheaders_before_sync GUARDED_BY(NetEventsInterface::g_msgproc_mutex){false};
    
    /** Protects m_getdata_requests **/
    Mutex m_getdata_requests_mutex;
    /** Work queue of items requested by this peer **/
    std::deque<CInv> m_getdata_requests GUARDED_BY(m_getdata_requests_mutex);

    /** Time of the last getheaders message to this peer */
    NodeClock::time_point m_last_getheaders_timestamp GUARDED_BY(NetEventsInterface::g_msgproc_mutex){};
    /** Protects m_headers_sync **/
    Mutex m_headers_sync_mutex;
    /** Headers-sync state for this peer (eg for initial sync, or syncing large
     * reorgs) **/
    std::unique_ptr<HeadersSyncState> m_headers_sync PT_GUARDED_BY(m_headers_sync_mutex) GUARDED_BY(m_headers_sync_mutex) {};

    /** Whether we've sent our peer a sendheaders message. **/
    std::atomic<bool> m_sent_sendheaders{false};
    /** Length of current-streak of unconnecting headers announcements */
    int m_num_unconnecting_headers_msgs GUARDED_BY(NetEventsInterface::g_msgproc_mutex){0};

    /** When to potentially disconnect peer for stalling headers download */
    std::chrono::microseconds m_headers_sync_timeout GUARDED_BY(NetEventsInterface::g_msgproc_mutex){0us};

    /** Whether this peer wants invs or headers (when possible) for block announcements */
    bool m_prefers_headers GUARDED_BY(NetEventsInterface::g_msgproc_mutex){false};
    // SYSCOIN
    /** This peer's a masternode connection */
    std::atomic<bool> m_masternode_connection{false};
    explicit Peer(NodeId id, ServiceFlags our_services)
        : m_id{id}
        , m_our_services{our_services}
    {}

private:
    mutable Mutex m_tx_relay_mutex;

    /** Transaction relay data. May be a nullptr. */
    std::unique_ptr<TxRelay> m_tx_relay GUARDED_BY(m_tx_relay_mutex);
};

using PeerRef = std::shared_ptr<Peer>;

class PeerManager : public CValidationInterface, public NetEventsInterface
{
public:
    struct Options {
        //! Whether this node is running in -blocksonly mode
        bool ignore_incoming_txs{DEFAULT_BLOCKSONLY};
        //! Whether transaction reconciliation protocol is enabled
        bool reconcile_txs{DEFAULT_TXRECONCILIATION_ENABLE};
        //! Maximum number of orphan transactions kept in memory
        uint32_t max_orphan_txs{DEFAULT_MAX_ORPHAN_TRANSACTIONS};
        //! Number of non-mempool transactions to keep around for block reconstruction. Includes
        //! orphan, replaced, and rejected transactions.
        uint32_t max_extra_txs{DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN};
        //! Whether all P2P messages are captured to disk
        bool capture_messages{false};
        //! Whether or not the internal RNG behaves deterministically (this is
        //! a test-only option).
        bool deterministic_rng{false};
    };

    static std::unique_ptr<PeerManager> make(CConnman& connman, AddrMan& addrman,
                                             BanMan* banman, ChainstateManager& chainman,
                                             CTxMemPool& pool, Options opts);
    virtual ~PeerManager() { }

    /**
     * Attempt to manually fetch block from a given peer. We must already have the header.
     *
     * @param[in]  peer_id      The peer id
     * @param[in]  block_index  The blockindex
     * @returns std::nullopt if a request was successfully made, otherwise an error message
     */
    virtual std::optional<std::string> FetchBlock(NodeId peer_id, const CBlockIndex& block_index) = 0;

    /** Begin running background tasks, should only be called once */
    virtual void StartScheduledTasks(CScheduler& scheduler) = 0;

    /** Get statistics from node state */
    virtual bool GetNodeStateStats(NodeId nodeid, CNodeStateStats& stats) const = 0;

    /** SYSCOIN: Bounded post-quantum MNAUTH worker/admission statistics. */
    virtual CMNAuthAsyncStats GetMNAuthAsyncStats() const = 0;

    /** Whether this node ignores txs received over p2p. */
    virtual bool IgnoresIncomingTxs() = 0;

    /** Relay transaction to all peers. */
    virtual void RelayTransaction(const uint256& txid, const uint256& wtxid) = 0;

    /** Send ping message to all peers */
    virtual void SendPings() = 0;

    /** Set the best height */
    virtual void SetBestHeight(int height) = 0;

    // SYSCOIN
    virtual size_t GetRequestedCount(NodeId nodeId) const = 0;
    virtual bool IsRequested(NodeId nodeId, const uint256& hash) const = 0;
    virtual std::optional<uint256> GetRequestedChainLock(NodeId nodeId) const = 0;
    virtual std::optional<uint256> GetRequestedPaymentAudit(
        NodeId nodeId) const = 0;
    virtual bool TakeCancelledChainLockResponse(
        NodeId nodeId, const uint256& logical_id) = 0;
    virtual bool HasCancelledPaymentAuditResponse(NodeId nodeId) const = 0;
    virtual bool TakeCancelledPaymentAuditResponse(
        NodeId nodeId, const uint256& witness_id) = 0;
    /** Bind delivered bytes to one exact governance request attempt. */
    virtual std::optional<GovernanceRequestTracker::ResponseAuthorization>
    BeginGovernanceResponse(NodeId nodeId, const CInv& inv) = 0;
    /** Finish that exact attempt only after semantic admission. */
    virtual bool CompleteGovernanceResponse(
        const GovernanceRequestTracker::ResponseAuthorization& authorization,
        GovernanceRequestTracker::ResponseOutcome outcome) = 0;
    /** Bind a continuation to this connection's immutable serve snapshot. */
    virtual std::optional<
        std::shared_ptr<const GovernancePageImmutableSnapshot>>
    PrepareGovernancePageRequest(
        CNode& node, const CGovernancePageRequest& request) = 0;
    /** Send one bounded page and install exact scoped GETDATA authorization. */
    virtual bool SendGovernancePage(
        CNode& node, const GovernancePageBuildResult& page) = 0;
    virtual bool BeginGovernancePageSession(CNode& node) = 0;
    virtual bool CanUseGovernancePageSource(const CNode& node) const = 0;
    virtual bool SetGovernancePageSessionSource(CNode& node) = 0;
    virtual void EndGovernancePageSession() = 0;
    virtual bool RequestGovernancePage(
        CNode& node, const CGovernancePageRequest& request,
        std::chrono::microseconds expiry) = 0;
    virtual bool IsGovernancePageRequested(
        NodeId node_id, const CGovernancePageResponse& response) const = 0;
    virtual bool ReceiveGovernancePage(
        NodeId node_id, const CGovernancePageResponse& response,
        const std::vector<CInv>& missing) = 0;
    virtual bool RejectGovernancePage(
        NodeId node_id, const CGovernancePageResponse& response) = 0;
    virtual bool FailGovernancePageSource(NodeId expected_peer) = 0;
    virtual std::optional<GovernanceRequestTracker::PageResult>
    TakeGovernancePageResult() = 0;
    virtual void ReceivedResponse(NodeId nodeId, const uint256& hash) = 0;
    /** Cool down a peer which failed an exact PQ ChainLock request. */
    virtual void ReceivedChainLockFailure(NodeId nodeId,
                                          const uint256& hash) = 0;
    virtual void ReceivedPaymentAuditResponse(NodeId nodeId,
                                              const uint256& hash) = 0;
    virtual void ReceivedPaymentAuditFailure(NodeId nodeId,
                                             const uint256& hash) = 0;
    virtual void ForgetPaymentAudit(const uint256& hash) = 0;
    /** Move pending PQ ChainLock requests onto the stable MNAUTH identity. */
    virtual void UpdateChainLockSourceIdentity(
        NodeId nodeId, const uint256& authenticated_pro_tx,
        uint64_t keyed_net_group, bool outbound) = 0;
    /** SYSCOIN: move governance requests onto the stable MNAUTH identity. */
    virtual void UpdateGovernanceSourceIdentity(
        NodeId nodeId, const uint256& authenticated_pro_tx,
        uint64_t keyed_net_group, bool outbound) = 0;
    virtual void ForgetTxHash(NodeId nodeId, const uint256& hash) = 0;
    virtual void PushTxInventory(Peer& peer, const uint256& txid, const uint256& wtxid) = 0;
    virtual void RelayInv(const CInv& inv) = 0;
    virtual void PushTxInventoryOther(Peer& peer, const CInv& inv) = 0;
    virtual PeerRef GetPeerRef(NodeId id) const = 0;
    virtual void AddKnownTx(Peer& peer, const uint256& hash) = 0;
    virtual bool IsBanned(NodeId nodeid) = 0;
    /* Public for unit testing. */
    virtual void UnitTestMisbehaving(NodeId peer_id, int howmuch) = 0;
    // SYSCOIN
    virtual void Misbehaving(Peer& peer, int howmuch, const std::string& message) = 0;

    /**
     * Evict extra outbound peers. If we think our tip may be stale, connect to an extra outbound.
     * Public for unit testing.
     */
    virtual void CheckForStaleTipAndEvictPeers() = 0;

    /** Process a single message from a peer. Public for fuzz testing */
    virtual void ProcessMessage(CNode& pfrom, const std::string& msg_type, CDataStream& vRecv,
                                const std::chrono::microseconds time_received, const std::atomic<bool>& interruptMsgProc) EXCLUSIVE_LOCKS_REQUIRED(g_msgproc_mutex) = 0;

    /** This function is used for testing the stale tip eviction logic, see denialofservice_tests.cpp */
    virtual void UpdateLastBlockAnnounceTime(NodeId node, int64_t time_in_seconds) = 0;
};

// SYSCOIN
// Upstream moved this into net_processing.cpp (13417), however since we use Misbehaving in a number of syscoin specific
// files such as mnauth.cpp and governance.cpp it makes sense to keep it in the header
/** Increase a node's misbehavior score. */
bool IsBanned(NodeId nodeid, BanMan& banman);
unsigned int GetMaxInv();
bool CanServeBlocks(const Peer& peer);
#endif // SYSCOIN_NET_PROCESSING_H
