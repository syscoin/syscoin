// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SYSCOIN_PROTOCOL_H
#define SYSCOIN_PROTOCOL_H

#include <kernel/messagestartchars.h> // IWYU pragma: export
#include <hash.h> // SYSCOIN: governance page view commitments.
#include <netaddress.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>
#include <util/time.h>

#include <array>
#include <chrono> // SYSCOIN: bounded governance page leases.
#include <cstdint>
#include <limits>
#include <optional> // SYSCOIN: governance page commitment validation.
#include <string>
#include <vector> // SYSCOIN: bounded governance page inventory.

/** Message header.
 * (4) message start.
 * (12) command.
 * (4) size.
 * (4) checksum.
 */
class CMessageHeader
{
public:
    static constexpr size_t COMMAND_SIZE = 12;
    static constexpr size_t MESSAGE_SIZE_SIZE = 4;
    static constexpr size_t CHECKSUM_SIZE = 4;
    static constexpr size_t MESSAGE_SIZE_OFFSET = std::tuple_size_v<MessageStartChars> + COMMAND_SIZE;
    static constexpr size_t CHECKSUM_OFFSET = MESSAGE_SIZE_OFFSET + MESSAGE_SIZE_SIZE;
    static constexpr size_t HEADER_SIZE = std::tuple_size_v<MessageStartChars> + COMMAND_SIZE + MESSAGE_SIZE_SIZE + CHECKSUM_SIZE;

    explicit CMessageHeader() = default;

    /** Construct a P2P message header from message-start characters, a command and the size of the message.
     * @note Passing in a `pszCommand` longer than COMMAND_SIZE will result in a run-time assertion error.
     */
    CMessageHeader(const MessageStartChars& pchMessageStartIn, const char* pszCommand, unsigned int nMessageSizeIn);

    std::string GetCommand() const;
    bool IsCommandValid() const;

    SERIALIZE_METHODS(CMessageHeader, obj) { READWRITE(obj.pchMessageStart, obj.pchCommand, obj.nMessageSize, obj.pchChecksum); }

    MessageStartChars pchMessageStart{};
    char pchCommand[COMMAND_SIZE]{};
    uint32_t nMessageSize{std::numeric_limits<uint32_t>::max()};
    uint8_t pchChecksum[CHECKSUM_SIZE]{};
};

/**
 * Syscoin protocol message types. When adding new message types, don't forget
 * to update allNetMessageTypes in protocol.cpp.
 */
namespace NetMsgType {

/**
 * The version message provides information about the transmitting node to the
 * receiving node at the beginning of a connection.
 */
extern const char* VERSION;
/**
 * The verack message acknowledges a previously-received version message,
 * informing the connecting node that it can begin to send other messages.
 */
extern const char* VERACK;
/**
 * The addr (IP address) message relays connection information for peers on the
 * network.
 */
extern const char* ADDR;
/**
 * The addrv2 message relays connection information for peers on the network just
 * like the addr message, but is extended to allow gossiping of longer node
 * addresses (see BIP155).
 */
extern const char *ADDRV2;
/**
 * The sendaddrv2 message signals support for receiving ADDRV2 messages (BIP155).
 * It also implies that its sender can encode as ADDRV2 and would send ADDRV2
 * instead of ADDR to a peer that has signaled ADDRV2 support by sending SENDADDRV2.
 */
extern const char *SENDADDRV2;
/**
 * The inv message (inventory message) transmits one or more inventories of
 * objects known to the transmitting peer.
 */
extern const char* INV;
/**
 * The getdata message requests one or more data objects from another node.
 */
extern const char* GETDATA;
/**
 * The merkleblock message is a reply to a getdata message which requested a
 * block using the inventory type MSG_MERKLEBLOCK.
 * @since protocol version 70001 as described by BIP37.
 */
extern const char* MERKLEBLOCK;
/**
 * The getblocks message requests an inv message that provides block header
 * hashes starting from a particular point in the block chain.
 */
extern const char* GETBLOCKS;
/**
 * The getheaders message requests a headers message that provides block
 * headers starting from a particular point in the block chain.
 * @since protocol version 31800.
 */
extern const char* GETHEADERS;
/**
 * The tx message transmits a single transaction.
 */
extern const char* TX;
/**
 * The headers message sends one or more block headers to a node which
 * previously requested certain headers with a getheaders message.
 * @since protocol version 31800.
 */
extern const char* HEADERS;
/**
 * The block message transmits a single serialized block.
 */
extern const char* BLOCK;
/**
 * The getaddr message requests an addr message from the receiving node,
 * preferably one with lots of IP addresses of other receiving nodes.
 */
extern const char* GETADDR;
/**
 * The mempool message requests the TXIDs of transactions that the receiving
 * node has verified as valid but which have not yet appeared in a block.
 * @since protocol version 60002 as described by BIP35.
 *   Only available with service bit NODE_BLOOM, see also BIP111.
 */
extern const char* MEMPOOL;
/**
 * The ping message is sent periodically to help confirm that the receiving
 * peer is still connected.
 */
extern const char* PING;
/**
 * The pong message replies to a ping message, proving to the pinging node that
 * the ponging node is still alive.
 * @since protocol version 60001 as described by BIP31.
 */
extern const char* PONG;
/**
 * The notfound message is a reply to a getdata message which requested an
 * object the receiving node does not have available for relay.
 * @since protocol version 70001.
 */
extern const char* NOTFOUND;
/**
 * The filterload message tells the receiving peer to filter all relayed
 * transactions and requested merkle blocks through the provided filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 */
extern const char* FILTERLOAD;
/**
 * The filteradd message tells the receiving peer to add a single element to a
 * previously-set bloom filter, such as a new public key.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 */
extern const char* FILTERADD;
/**
 * The filterclear message tells the receiving peer to remove a previously-set
 * bloom filter.
 * @since protocol version 70001 as described by BIP37.
 *   Only available with service bit NODE_BLOOM since protocol version
 *   70011 as described by BIP111.
 */
extern const char* FILTERCLEAR;
/**
 * Indicates that a node prefers to receive new block announcements via a
 * "headers" message rather than an "inv".
 * @since protocol version 70012 as described by BIP130.
 */
extern const char* SENDHEADERS;
/**
 * The feefilter message tells the receiving peer not to inv us any txs
 * which do not meet the specified min fee rate.
 * @since protocol version 70013 as described by BIP133
 */
extern const char* FEEFILTER;
/**
 * Contains a 1-byte bool and 8-byte LE version number.
 * Indicates that a node is willing to provide blocks via "cmpctblock" messages.
 * May indicate that a node prefers to receive new block announcements via a
 * "cmpctblock" message rather than an "inv", depending on message contents.
 * @since protocol version 70014 as described by BIP 152
 */
extern const char* SENDCMPCT;
/**
 * Contains a CBlockHeaderAndShortTxIDs object - providing a header and
 * list of "short txids".
 * @since protocol version 70014 as described by BIP 152
 */
extern const char* CMPCTBLOCK;
/**
 * Contains a BlockTransactionsRequest
 * Peer should respond with "blocktxn" message.
 * @since protocol version 70014 as described by BIP 152
 */
extern const char* GETBLOCKTXN;
/**
 * Contains a BlockTransactions.
 * Sent in response to a "getblocktxn" message.
 * @since protocol version 70014 as described by BIP 152
 */
extern const char* BLOCKTXN;
/**
 * getcfilters requests compact filters for a range of blocks.
 * Only available with service bit NODE_COMPACT_FILTERS as described by
 * BIP 157 & 158.
 */
extern const char* GETCFILTERS;
/**
 * cfilter is a response to a getcfilters request containing a single compact
 * filter.
 */
extern const char* CFILTER;
/**
 * getcfheaders requests a compact filter header and the filter hashes for a
 * range of blocks, which can then be used to reconstruct the filter headers
 * for those blocks.
 * Only available with service bit NODE_COMPACT_FILTERS as described by
 * BIP 157 & 158.
 */
extern const char* GETCFHEADERS;
/**
 * cfheaders is a response to a getcfheaders request containing a filter header
 * and a vector of filter hashes for each subsequent block in the requested range.
 */
extern const char* CFHEADERS;
/**
 * getcfcheckpt requests evenly spaced compact filter headers, enabling
 * parallelized download and validation of the headers between them.
 * Only available with service bit NODE_COMPACT_FILTERS as described by
 * BIP 157 & 158.
 */
extern const char* GETCFCHECKPT;
/**
 * cfcheckpt is a response to a getcfcheckpt request containing a vector of
 * evenly spaced filter headers for blocks on the requested chain.
 */
extern const char* CFCHECKPT;
/**
 * Indicates that a node prefers to relay transactions via wtxid, rather than
 * txid.
 * @since protocol version 70016 as described by BIP 339.
 */
extern const char *WTXIDRELAY;
// SYSCOIN message types
extern const char *SPORK;
extern const char *GETSPORKS;
extern const char *SYNCSTATUSCOUNT;
extern const char *MNGOVERNANCESYNC;
extern const char *MNGOVERNANCEOBJECT;
extern const char *MNGOVERNANCEOBJECTVOTE;
extern const char *GETGOVPAGE;
extern const char *GOVPAGE;
extern const char *CLSIG;
extern const char *GETCLSIG;
extern const char *PQCLSHARE;
extern const char *PQPOSEHAVE;
extern const char *PQPOSERESP;
extern const char *PQPOSESHARE;
extern const char *PQPOSECERT;
extern const char *GETPQPOSE;
extern const char *MNAUTH;
/**
 * Contains a 4-byte version number and an 8-byte salt.
 * The salt is used to compute short txids needed for efficient
 * txreconciliation, as described by BIP 330.
 */
extern const char* SENDTXRCNCL;
}; // namespace NetMsgType

/* Get a vector of all valid message types (see above) */
const std::vector<std::string>& getAllNetMessageTypes();

/** nServices flags */
enum ServiceFlags : uint64_t {
    // NOTE: When adding here, be sure to update serviceFlagToStr too
    // Nothing
    NODE_NONE = 0,
    // NODE_NETWORK means that the node is capable of serving the complete block chain. It is currently
    // set by all Syscoin Core non pruned nodes, and is unset by SPV clients or other light clients.
    NODE_NETWORK = (1 << 0),
    // NODE_BLOOM means the node is capable and willing to handle bloom-filtered connections.
    NODE_BLOOM = (1 << 2),
    // NODE_WITNESS indicates that a node can be asked for blocks and transactions including
    // witness data.
    NODE_WITNESS = (1 << 3),
    // NODE_COMPACT_FILTERS means the node will service basic block filter requests.
    // See BIP157 and BIP158 for details on how this is implemented.
    NODE_COMPACT_FILTERS = (1 << 6),
    // NODE_NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only
    // serving the last 288 (2 day) blocks
    // See BIP159 for details on how this is implemented.
    NODE_NETWORK_LIMITED = (1 << 10),

    // NODE_P2P_V2 means the node supports BIP324 transport
    NODE_P2P_V2 = (1 << 11),

    // Bits 24-31 are reserved for temporary experiments. Just pick a bit that
    // isn't getting used, or one not being used much, and notify the
    // syscoin-development mailing list. Remember that service bits are just
    // unauthenticated advertisements, so your code must be robust against
    // collisions and other cases where nodes may be advertising a service they
    // do not actually support. Other service bits should be allocated via the
    // BIP process.
};

/**
 * Convert service flags (a bitmask of NODE_*) to human readable strings.
 * It supports unknown service flags which will be returned as "UNKNOWN[...]".
 * @param[in] flags multiple NODE_* bitwise-OR-ed together
 */
std::vector<std::string> serviceFlagsToStr(uint64_t flags);

/**
 * Gets the set of service flags which are "desirable" for a given peer.
 *
 * These are the flags which are required for a peer to support for them
 * to be "interesting" to us, ie for us to wish to use one of our few
 * outbound connection slots for or for us to wish to prioritize keeping
 * their connection around.
 *
 * Relevant service flags may be peer- and state-specific in that the
 * version of the peer may determine which flags are required (eg in the
 * case of NODE_NETWORK_LIMITED where we seek out NODE_NETWORK peers
 * unless they set NODE_NETWORK_LIMITED and we are out of IBD, in which
 * case NODE_NETWORK_LIMITED suffices).
 *
 * Thus, generally, avoid calling with peerServices == NODE_NONE, unless
 * state-specific flags must absolutely be avoided. When called with
 * peerServices == NODE_NONE, the returned desirable service flags are
 * guaranteed to not change dependent on state - ie they are suitable for
 * use when describing peers which we know to be desirable, but for which
 * we do not have a confirmed set of service flags.
 *
 * If the NODE_NONE return value is changed, contrib/seeds/makeseeds.py
 * should be updated appropriately to filter for the same nodes.
 */
ServiceFlags GetDesirableServiceFlags(ServiceFlags services);

/** Set the current IBD status in order to figure out the desirable service flags */
void SetServiceFlagsIBDCache(bool status);

/**
 * A shortcut for (services & GetDesirableServiceFlags(services))
 * == GetDesirableServiceFlags(services), ie determines whether the given
 * set of service flags are sufficient for a peer to be "relevant".
 */
static inline bool HasAllDesirableServiceFlags(ServiceFlags services)
{
    return !(GetDesirableServiceFlags(services) & (~services));
}

/**
 * Checks if a peer with the given service flags may be capable of having a
 * robust address-storage DB.
 */
static inline bool MayHaveUsefulAddressDB(ServiceFlags services)
{
    return (services & NODE_NETWORK) || (services & NODE_NETWORK_LIMITED);
}

/** A CService with information about it as peer */
class CAddress : public CService
{
    static constexpr std::chrono::seconds TIME_INIT{100000000};

    /** Historically, CAddress disk serialization stored the CLIENT_VERSION, optionally OR'ed with
     *  the ADDRV2_FORMAT flag to indicate V2 serialization. The first field has since been
     *  disentangled from client versioning, and now instead:
     *  - The low bits (masked by DISK_VERSION_IGNORE_MASK) store the fixed value DISK_VERSION_INIT,
     *    (in case any code exists that treats it as a client version) but are ignored on
     *    deserialization.
     *  - The high bits (masked by ~DISK_VERSION_IGNORE_MASK) store actual serialization information.
     *    Only 0 or DISK_VERSION_ADDRV2 (equal to the historical ADDRV2_FORMAT) are valid now, and
     *    any other value triggers a deserialization failure. Other values can be added later if
     *    needed.
     *
     *  For disk deserialization, ADDRV2_FORMAT in the stream version signals that ADDRV2
     *  deserialization is permitted, but the actual format is determined by the high bits in the
     *  stored version field. For network serialization, the stream version having ADDRV2_FORMAT or
     *  not determines the actual format used (as it has no embedded version number).
     */
    static constexpr uint32_t DISK_VERSION_INIT{220000};
    static constexpr uint32_t DISK_VERSION_IGNORE_MASK{0b00000000'00000111'11111111'11111111};
    /** The version number written in disk serialized addresses to indicate V2 serializations.
     * It must be exactly 1<<29, as that is the value that historical versions used for this
     * (they used their internal ADDRV2_FORMAT flag here). */
    static constexpr uint32_t DISK_VERSION_ADDRV2{1 << 29};
    static_assert((DISK_VERSION_INIT & ~DISK_VERSION_IGNORE_MASK) == 0, "DISK_VERSION_INIT must be covered by DISK_VERSION_IGNORE_MASK");
    static_assert((DISK_VERSION_ADDRV2 & DISK_VERSION_IGNORE_MASK) == 0, "DISK_VERSION_ADDRV2 must not be covered by DISK_VERSION_IGNORE_MASK");

public:
    CAddress() : CService{} {};
    CAddress(CService ipIn, ServiceFlags nServicesIn) : CService{ipIn}, nServices{nServicesIn} {};
    CAddress(CService ipIn, ServiceFlags nServicesIn, NodeSeconds time) : CService{ipIn}, nTime{time}, nServices{nServicesIn} {};

    enum class Format {
        Disk,
        Network,
    };
    struct SerParams : CNetAddr::SerParams {
        const Format fmt;
        SER_PARAMS_OPFUNC
    };
    static constexpr SerParams V1_NETWORK{{CNetAddr::Encoding::V1}, Format::Network};
    static constexpr SerParams V2_NETWORK{{CNetAddr::Encoding::V2}, Format::Network};
    static constexpr SerParams V1_DISK{{CNetAddr::Encoding::V1}, Format::Disk};
    static constexpr SerParams V2_DISK{{CNetAddr::Encoding::V2}, Format::Disk};

    SERIALIZE_METHODS_PARAMS(CAddress, obj, SerParams, params)
    {
        bool use_v2{false};
        if (params && params->fmt == Format::Disk) {
            // In the disk serialization format, the encoding (v1 or v2) is determined by a flag version
            // that's part of the serialization itself. ADDRV2_FORMAT in the stream version only determines
            // whether V2 is chosen/permitted at all.
            uint32_t stored_format_version = DISK_VERSION_INIT;
            if (params->enc == Encoding::V2) stored_format_version |= DISK_VERSION_ADDRV2;
            READWRITE(stored_format_version);
            stored_format_version &= ~DISK_VERSION_IGNORE_MASK; // ignore low bits
            if (stored_format_version == 0) {
                use_v2 = false;
            } else if (stored_format_version == DISK_VERSION_ADDRV2 && params->enc == Encoding::V2) {
                // Only support v2 deserialization if V2 is set.
                use_v2 = true;
            } else {
                throw std::ios_base::failure("Unsupported CAddress disk format version");
            }
        } else if(params) {
            assert(params->fmt == Format::Network);
            // In the network serialization format, the encoding (v1 or v2) is determined directly by
            // the value of enc in the stream params, as no explicitly encoded version
            // exists in the stream.
            use_v2 = params->enc == Encoding::V2;
        }

        READWRITE(Using<LossyChronoFormatter<uint32_t>>(obj.nTime));
        // nServices is serialized as CompactSize in V2; as uint64_t in V1.
        if (use_v2) {
            uint64_t services_tmp;
            SER_WRITE(obj, services_tmp = obj.nServices);
            READWRITE(Using<CompactSizeFormatter<false>>(services_tmp));
            SER_READ(obj, obj.nServices = static_cast<ServiceFlags>(services_tmp));
        } else {
            READWRITE(Using<CustomUintFormatter<8>>(obj.nServices));
        }
        // Invoke V1/V2 serializer for CService parent object.
        const auto ser_params{use_v2 ? CNetAddr::V2 : CNetAddr::V1};
        READWRITE(WithParams(ser_params, AsBase<CService>(obj)));
    }

    //! Always included in serialization. The behavior is unspecified if the value is not representable as uint32_t.
    NodeSeconds nTime{TIME_INIT};
    //! Serialized as uint64_t in V1, and as CompactSize in V2.
    ServiceFlags nServices{NODE_NONE};

    friend bool operator==(const CAddress& a, const CAddress& b)
    {
        return a.nTime == b.nTime &&
               a.nServices == b.nServices &&
               static_cast<const CService&>(a) == static_cast<const CService&>(b);
    }
};

/** getdata message type flags */
const uint32_t MSG_WITNESS_FLAG = 1 << 30;
const uint32_t MSG_TYPE_MASK = 0xffffffff >> 2;

/** getdata / inv message types.
 * These numbers are defined by the protocol. When adding a new value, be sure
 * to mention it in the respective BIP.
 */
enum GetDataMsg : uint32_t {
    UNDEFINED = 0,
    MSG_TX = 1,
    MSG_BLOCK = 2,
    MSG_WTX = 5,                                      //!< Defined in BIP 339
    // The following can only occur in getdata. Invs always use TX/WTX or BLOCK.
    MSG_FILTERED_BLOCK = 3,                           //!< Defined in BIP37
    MSG_CMPCT_BLOCK = 4,                              //!< Defined in BIP152
    // SYSCOIN message types
    MSG_SPORK = 11,
    MSG_GOVERNANCE_OBJECT = 12,
    MSG_GOVERNANCE_OBJECT_VOTE = 13,
    // Values 14 through 19 are reserved by the retired BLS/DKG protocol.
    MSG_CLSIG = 20,
    // Value 21 is reserved by the retired standalone BTCC protocol.
    MSG_PQPOSECERT = 22,
    MSG_WITNESS_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG, //!< Defined in BIP144
    MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG,       //!< Defined in BIP144
    // MSG_FILTERED_WITNESS_BLOCK is defined in BIP144 as reserved for future
    // use and remains unused.
    // MSG_FILTERED_WITNESS_BLOCK = MSG_FILTERED_BLOCK | MSG_WITNESS_FLAG,
};

/** inv message data */
class CInv
{
public:
    CInv();
    CInv(uint32_t typeIn, const uint256& hashIn);

    SERIALIZE_METHODS(CInv, obj) { READWRITE(obj.type, obj.hash); }

    // SYSCOIN: Exact fork inventory tracking requires value equality.
    friend bool operator==(const CInv&, const CInv&) = default;
    friend bool operator<(const CInv& a, const CInv& b);
    std::string GetCommand() const;
    std::string ToString() const;

    // Single-message helper methods
    bool IsMsgTx() const { return type == MSG_TX; }
    bool IsMsgBlk() const { return type == MSG_BLOCK; }
    bool IsMsgWtx() const { return type == MSG_WTX; }
    bool IsMsgFilteredBlk() const { return type == MSG_FILTERED_BLOCK; }
    bool IsMsgCmpctBlk() const { return type == MSG_CMPCT_BLOCK; }
    bool IsMsgWitnessBlk() const { return type == MSG_WITNESS_BLOCK; }

    // Combined-message helper methods
    // SYSCOIN
    bool IsGenTxMsg(bool bJustTx = false) const
    {
        const bool bJustTxInternal = type == MSG_TX || type == MSG_WTX || type == MSG_WITNESS_TX;
        if(bJustTx || bJustTxInternal) {
            return bJustTxInternal;
        }
        return type == MSG_SPORK || type == MSG_GOVERNANCE_OBJECT ||
               type == MSG_GOVERNANCE_OBJECT_VOTE || type == MSG_CLSIG ||
               type == MSG_PQPOSECERT;
    }
    bool IsGenBlkMsg() const
    {
        return type == MSG_BLOCK || type == MSG_FILTERED_BLOCK || type == MSG_CMPCT_BLOCK || type == MSG_WITNESS_BLOCK;
    }

    uint32_t type;
    uint256 hash;
};

// SYSCOIN: version 70018 replaces lossy bulk governance inventory relay with
// deterministic, cursor-bound pages. The small fixed bound is also the
// admission budget for the expensive payloads named by one page.
static constexpr int GOVERNANCE_PAGE_PROTO_VERSION{70018};
static constexpr std::size_t MAX_GOVERNANCE_PAGE_INVENTORY{2};
static constexpr std::size_t MAX_GOVERNANCE_PAGE_PAYLOAD_BYTES{
    100ULL * 1024 * 1024};
// A metadata response is small; a silent source must not hold the leased
// governance lane for the much longer payload-transfer allowance.
static constexpr auto GOVERNANCE_PAGE_RESPONSE_TIMEOUT{
    std::chrono::seconds{30}};
// Once a page arrives, this covers receipt and semantic verification of both
// legal payloads. Fifteen minutes lets a full 64 MiB retained page make
// progress on a roughly 0.6 Mbps link.
static constexpr auto GOVERNANCE_PAGE_TRANSFER_TIMEOUT{
    std::chrono::minutes{15}};
// Payload admission refills once per two seconds. A 43,200-item scope can
// therefore drain within a 24-hour immutable-snapshot lease; a larger count
// would be advertised as resumable while being impossible to service before
// its bounded server state expires.
static constexpr uint32_t MAX_GOVERNANCE_PAGE_SCOPE_ITEMS{43'200};

enum GovernancePageStatus : uint8_t {
    GOVERNANCE_PAGE_OK = 0,
    GOVERNANCE_PAGE_VIEW_CHANGED = 1,
    GOVERNANCE_PAGE_RESTART_REQUIRED = 2,
    GOVERNANCE_PAGE_TEMPORARILY_UNAVAILABLE = 3,
    GOVERNANCE_PAGE_SCOPE_TOO_LARGE = 4,
};

[[nodiscard]] constexpr bool SupportsGovernancePages(int version) noexcept
{
    return version >= GOVERNANCE_PAGE_PROTO_VERSION;
}

template <std::size_t MaximumSize>
struct LimitedInvVectorFormatter
{
    template <typename Stream>
    void Ser(Stream& stream, const std::vector<CInv>& inventory)
    {
        if (inventory.size() > MaximumSize) {
            throw std::ios_base::failure("governance page inventory too large");
        }
        WriteCompactSize(stream, inventory.size());
        for (const CInv& inv : inventory) stream << inv;
    }

    template <typename Stream>
    void Unser(Stream& stream, std::vector<CInv>& inventory)
    {
        const std::size_t size{ReadCompactSize(stream)};
        if (size > MaximumSize) {
            throw std::ios_base::failure("governance page inventory too large");
        }
        inventory.clear();
        inventory.reserve(size);
        while (inventory.size() < size) {
            inventory.emplace_back();
            stream >> inventory.back();
        }
    }
};

struct CGovernancePageRequest
{
    // A null scope requests objects; otherwise it requests votes for scope.
    uint256 scope_hash;
    // Exclusive hash cursor. A null cursor starts a scope.
    uint256 cursor;
    // Null only when establishing a deterministic view at cursor zero.
    uint256 view_id;
    uint64_t nonce{0};

    SERIALIZE_METHODS(CGovernancePageRequest, obj)
    {
        READWRITE(obj.scope_hash, obj.cursor, obj.view_id, obj.nonce);
    }

    friend bool operator==(const CGovernancePageRequest&,
                           const CGovernancePageRequest&) = default;
};

struct CGovernancePageResponse
{
    uint256 scope_hash;
    uint256 cursor;
    uint256 request_view_id;
    uint64_t nonce{0};
    uint8_t status{GOVERNANCE_PAGE_OK};
    uint256 view_id;
    uint32_t total_count{0};
    uint256 next_cursor;
    bool done{false};
    std::vector<CInv> inventory;

    SERIALIZE_METHODS(CGovernancePageResponse, obj)
    {
        READWRITE(
            obj.scope_hash, obj.cursor, obj.request_view_id, obj.nonce,
            obj.status, obj.view_id, obj.total_count,
            obj.next_cursor, obj.done,
            Using<LimitedInvVectorFormatter<
                MAX_GOVERNANCE_PAGE_INVENTORY>>(obj.inventory));
    }

    friend bool operator==(const CGovernancePageResponse&,
                           const CGovernancePageResponse&) = default;
};

/**
 * Incremental commitment to one exact ordered governance inventory scope.
 * Entries are appended only after their page has passed semantic admission.
 */
class CGovernancePageViewHasher
{
public:
    CGovernancePageViewHasher(const uint256& scope_hash,
                              uint32_t total_count);

    [[nodiscard]] bool Append(const CInv& inv);
    [[nodiscard]] std::optional<uint256> Finalize();
    [[nodiscard]] uint32_t SeenCount() const noexcept { return m_seen_count; }
    [[nodiscard]] uint32_t TotalCount() const noexcept { return m_total_count; }
    [[nodiscard]] const uint256& LastHash() const noexcept { return m_last_hash; }

private:
    HashWriter m_writer{SER_GETHASH, GOVERNANCE_PAGE_PROTO_VERSION};
    uint256 m_scope_hash;
    uint256 m_last_hash;
    uint32_t m_total_count{0};
    uint32_t m_seen_count{0};
    bool m_finalized{false};
};

[[nodiscard]] std::optional<uint256> ComputeGovernancePageViewHash(
    const uint256& scope_hash, const std::vector<CInv>& inventory);

/** Convert a TX/WITNESS_TX/WTX CInv to a GenTxid. */
GenTxid ToGenTxid(const CInv& inv);

#endif // SYSCOIN_PROTOCOL_H
