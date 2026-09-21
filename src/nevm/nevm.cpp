// Copyright (c) 2019 The Syscoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <nevm/nevm.h>
#include <nevm/sha3.h>
#include <consensus/consensus.h>
#include <primitives/transaction.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <stdexcept>

namespace {

/** RLP(index), expanded to nibbles. Unlike an arbitrary trie, indexed Ethereum
 * lists have prefix-free keys, at most two nibbles per size_t byte plus prefix.
 * Construct keys on demand rather than retaining a copy for every transaction. */
struct IndexedTrieKey {
    static constexpr size_t MAX_NIBBLES{2 * (sizeof(size_t) + 1)};
    std::array<uint8_t, MAX_NIBBLES> nibbles{};
    size_t size{0};

    explicit IndexedTrieKey(size_t index)
    {
        const auto append = [&](uint8_t byte) {
            nibbles[size++] = byte >> 4;
            nibbles[size++] = byte & 0x0f;
        };
        if (index == 0) {
            append(0x80);
        } else if (index < 0x80) {
            append(static_cast<uint8_t>(index));
        } else {
            size_t bytes{0};
            for (size_t remaining{index}; remaining != 0; remaining >>= 8) ++bytes;
            append(static_cast<uint8_t>(0x80 + bytes));
            while (bytes != 0) append(static_cast<uint8_t>(index >> (8 * --bytes)));
        }
    }

    dev::bytes Compact(size_t first, size_t last, bool leaf) const
    {
        if (first > last || last > size) throw std::logic_error("invalid indexed trie path");
        const bool odd{(last - first) % 2 != 0};
        dev::bytes result{static_cast<uint8_t>((leaf ? 0x20 : 0) | (odd ? 0x10 : 0))};
        if (odd) result[0] |= nibbles[first++];
        while (first < last) {
            result.push_back(static_cast<uint8_t>((nibbles[first] << 4) | nibbles[first + 1]));
            first += 2;
        }
        return result;
    }
};

/** A child reference is either an embedded RLP node (<32 bytes) or a hash.
 * Only leaf encoding temporarily copies a transaction; retained values are views
 * of the original block, and every completed child occupies at most 32 bytes. */
dev::bytes IndexedTrieReference(dev::RLPStream& node, bool root)
{
    if (!root && node.out().size() < 32) return node.invalidate();
    return dev::sha3(node.out()).asBytes();
}

void AppendIndexedTrieReference(dev::RLPStream& parent, const dev::bytes& child)
{
    if (child.size() < 32) parent.appendRaw(child);
    else parent.append(child);
}

class IndexedTrie {
    const size_t m_count;
    const bool m_transactions;
    dev::RLP m_zero;
    dev::RLP::iterator m_next;
    size_t m_next_index{1};

    // Lexicographic RLP key order is 1..127, 0, 128.., restricted to the list.
    size_t Index(size_t position) const
    {
        const size_t short_keys{std::min<size_t>(m_count - 1, 0x7f)};
        if (position < short_keys) return position + 1;
        if (position == short_keys) return 0;
        return position;
    }

    dev::bytesConstRef Value(size_t index)
    {
        dev::RLP item;
        if (index == 0) {
            item = m_zero;
        } else {
            if (index != m_next_index++) throw std::logic_error("unordered indexed trie values");
            item = *m_next;
            ++m_next;
        }
        if (item.isList()) return item.data();
        if (!m_transactions) throw std::runtime_error("invalid NEVM withdrawal encoding");
        // EIP-2718: the trie stores type || payload, not the enclosing
        // RLP byte string used to place that value in the block list.
        const auto value{item.toBytesConstRef(dev::RLP::VeryStrict)};
        if (value.size() < 2 || value[0] > 0x7f) {
            throw std::runtime_error("invalid NEVM typed transaction envelope");
        }
        return value;
    }

    dev::bytes Node(size_t first, size_t last, size_t depth, bool root)
    {
        if (first >= last || depth > IndexedTrieKey::MAX_NIBBLES) {
            throw std::logic_error("invalid indexed trie range");
        }
        const size_t index{Index(first)};
        const IndexedTrieKey key{index};
        if (depth > key.size) throw std::logic_error("invalid indexed trie depth");
        if (last - first == 1) {
            dev::RLPStream leaf{2};
            leaf.append(key.Compact(depth, key.size, true));
            leaf.append(Value(index));
            return IndexedTrieReference(leaf, root);
        }

        // Sorted first/last keys determine the entire range's common prefix.
        const IndexedTrieKey end_key{Index(last - 1)};
        size_t shared{depth};
        while (shared < key.size && shared < end_key.size &&
               key.nibbles[shared] == end_key.nibbles[shared]) ++shared;
        if (shared == key.size || shared == end_key.size) {
            throw std::logic_error("indexed trie keys are not prefix-free");
        }
        if (shared != depth) {
            dev::RLPStream extension{2};
            extension.append(key.Compact(depth, shared, false));
            AppendIndexedTrieReference(extension, Node(first, last, shared, false));
            return IndexedTrieReference(extension, root);
        }

        dev::RLPStream branch{17};
        size_t position{first};
        for (uint8_t nibble{0}; nibble < 16; ++nibble) {
            const size_t begin{position};
            while (position < last) {
                const IndexedTrieKey child_key{Index(position)};
                if (depth >= child_key.size || child_key.nibbles[depth] != nibble) break;
                ++position;
            }
            if (position == begin) branch.append(dev::bytesConstRef{});
            else AppendIndexedTrieReference(branch, Node(begin, position, depth + 1, false));
        }
        if (position != last) throw std::logic_error("unordered indexed trie keys");
        // No RLP(index) is a prefix of another; branch values are always empty.
        branch.append(dev::bytesConstRef{});
        return IndexedTrieReference(branch, root);
    }

public:
    // Stream the original list, postponing index zero until after 1..127.
    // This avoids allocations proportional to an untrusted item count.
    IndexedTrie(const dev::RLP& list, bool transactions)
        : m_count{list.itemCountStrict()}, m_transactions{transactions}, m_next{list.begin()}
    {
        if (m_count != 0) {
            m_zero = *m_next;
            ++m_next;
        }
    }

    dev::h256 Root()
    {
        if (m_count == 0) {
            const std::array<uint8_t, 1> empty{0x80};
            return dev::sha3(dev::bytesConstRef{empty.data(), empty.size()});
        }
        return dev::h256{Node(0, m_count, 0, true)};
    }
};

bool MatchesCommittedHash(const dev::h256& hash, const uint256& commitment)
{
    return std::equal(hash.begin(), hash.end(), commitment.begin());
}

} // namespace

bool CheckNEVMBlockPayloadIntegrity(const std::vector<uint8_t>& payload,
                                   const CNEVMHeader& commitment,
                                   std::string& error)
{
    error.clear();
    const auto fail = [&](const std::string& reason) {
        error = reason;
        return false;
    };
    if (payload.empty() || payload.size() > MAX_NEVM_BLOCK_SIZE) {
        return fail("invalid NEVM payload size");
    }
    try {
        // VeryStrict rejects trailing bytes. Iteration also checks canonical
        // lengths of every outer item and every transaction envelope. Those
        // wrappers are not themselves covered by a header/body commitment.
        const dev::RLP block{payload, dev::RLP::VeryStrict};
        const size_t fields{block.itemCountStrict()};
        if (fields != 3 && fields != 4) return fail("unsupported NEVM block layout");
        const dev::RLP header{block[0]};
        const size_t header_fields{header.itemCountStrict()};
        if (header_fields < 15) return fail("incomplete NEVM header");
        // Hash the entire header, including any optional suffix; no decoded
        // re-encoding may silently normalize damaged wire bytes.
        if (!MatchesCommittedHash(dev::sha3(header.data()), commitment.nBlockHash)) {
            return fail("NEVM header hash mismatch");
        }
        const auto uncle_hash{header[1].toHash<dev::h256>(dev::RLP::VeryStrict)};
        const auto tx_root{header[4].toHash<dev::h256>(dev::RLP::VeryStrict)};
        const auto receipt_root{header[5].toHash<dev::h256>(dev::RLP::VeryStrict)};
        if (!MatchesCommittedHash(tx_root, commitment.nTxRoot) ||
            !MatchesCommittedHash(receipt_root, commitment.nReceiptRoot)) {
            return fail("NEVM committed roots mismatch");
        }

        const dev::RLP transactions{block[1]};
        if (IndexedTrie{transactions, /*transactions=*/true}.Root() != tx_root) {
            return fail("NEVM transaction root mismatch");
        }

        const dev::RLP uncles{block[2]};
        if (!uncles.isList() || dev::sha3(uncles.data()) != uncle_hash) {
            return fail("NEVM uncle hash mismatch");
        }

        std::optional<dev::h256> withdrawals_root;
        if (header_fields > 16) {
            // Geth requires a full hash when this optional field is encoded;
            // an empty placeholder is not accepted by its block decoder.
            withdrawals_root = header[16].toHash<dev::h256>(dev::RLP::VeryStrict);
        }
        if (withdrawals_root.has_value() != (fields == 4)) {
            return fail("NEVM withdrawals presence mismatch");
        }
        if (withdrawals_root) {
            const dev::RLP withdrawals{block[3]};
            if (IndexedTrie{withdrawals, /*transactions=*/false}.Root() != *withdrawals_root) {
                return fail("NEVM withdrawals root mismatch");
            }
        }
        return true;
    } catch (const std::exception& exception) {
        return fail(std::string{"invalid NEVM payload encoding: "} + exception.what());
    }
}

static bool MatchProofValue(dev::bytes node_value,
                            const dev::RLP& expected_value,
                            std::optional<uint8_t>* envelope_type)
{
  if(node_value.empty()) {
    return false;
  }

  std::optional<uint8_t> parsed_type;
  // EIP-2718 values are TransactionType || TransactionPayload, where the
  // TransactionType range is inclusive: [0x00, 0x7f]. The consensus parser
  // separately whitelists the authenticated type values it understands.
  if(node_value[0] <= 0x7f) {
    parsed_type = node_value[0];
    node_value.erase(node_value.begin());
  }
  if(node_value != expected_value.data().toBytes()) {
    return false;
  }
  if(envelope_type) {
    *envelope_type = parsed_type;
  }
  return true;
}

int nibblesToTraverse(const std::string &encodedPartialPath, const std::string &path, int pathPtr) {
  if(encodedPartialPath.empty()) {
    return -1;
  }
  std::string partialPath;
  // typecast as the character
  uint8_t partialPathInt; 
  char pathPtrInt[2] = {encodedPartialPath[0], '\0'};
  if(!ParseUInt8(pathPtrInt, &partialPathInt))
    return -1;
  if(partialPathInt == 0 || partialPathInt == 2){
    partialPath = encodedPartialPath.substr(2);
  }else{
    partialPath = encodedPartialPath.substr(1);
  }
  if(partialPath == path.substr(pathPtr, partialPath.size())){
    return partialPath.size();
  }else{
    return -1;
  }
}
bool VerifyProof(dev::bytesConstRef path,
                 const dev::RLP& value,
                 const dev::RLP& parentNodes,
                 const dev::RLP& root,
                 std::optional<uint8_t>* envelope_type) {
  
  dev::RLP currentNode;
  const int len = parentNodes.itemCount();
  dev::RLP nodeKey = root;       
  int pathPtr = 0;

  const std::string pathString = dev::toHex(path);
  int nibbles;
  char pathPtrInt[2];
  uint8_t pathInt;
  for (int i = 0 ; i < len ; i++) {
    currentNode = parentNodes[i];
    if(!nodeKey.payload().contentsEqual(sha3(currentNode.data()).ref().toVector())){
      return false;
    } 

    if(pathPtr > (int)pathString.size()){
      return false;
    }
    switch(currentNode.itemCount()){
      case 17://branch node
        if(pathPtr == (int)pathString.size()){
          // RLP-encoded transaction/receipt indexes are prefix-free, so
          // canonical Ethereum tries terminate these proofs at leaf nodes.
          // Keep generic MPT branch-value handling consistent with leaves.
          return MatchProofValue(currentNode[16].toBytes(), value, envelope_type);
        }
        pathPtrInt[0] = pathString[pathPtr];
        pathPtrInt[1] = '\0';
        if(!ParseUInt8FromHex(pathPtrInt, &pathInt)) {
          return false;
        }
        nodeKey = currentNode[pathInt]; //must == sha3(rlp.encode(currentNode[path[pathptr]]))
        pathPtr += 1;
        break;
      case 2:
        {
        if(!currentNode[0].isData()) {
          return false;
        }
        const dev::bytes compact = currentNode[0].toBytes();
        if(compact.empty()) {
          return false;
        }
        // HP compact encoding (Yellow Paper / Geth):
        // high nibble 0/1 = extension, 2/3 = leaf; low bit = odd path length.
        // Do not infer leaf vs extension from path exhaustion alone.
        const uint8_t hp_flag = compact[0] >> 4;
        if(hp_flag > 3) {
          return false;
        }
        const bool is_odd = (hp_flag & 1) != 0;
        const bool is_leaf = (hp_flag & 2) != 0;
        // Even HP encoding requires a zero padding nibble.
        if(!is_odd && (compact[0] & 0x0f) != 0) {
          return false;
        }
        // Geth does not emit empty extension paths (shared prefix length 0
        // becomes a branch). Reject that noncanonical shape.
        if(!is_leaf && !is_odd && compact.size() == 1) {
          return false;
        }
        const std::string encodedPartialPath = toHex(
            dev::bytesConstRef(compact.data(), compact.size()));
        nibbles = nibblesToTraverse(encodedPartialPath, pathString, pathPtr);
        if(nibbles <= -1) {
          return false;
        }
        pathPtr += nibbles;
        if(is_leaf) {
          if(pathPtr != (int)pathString.size()) {
            return false;
          }
          dev::bytes nodeVec(currentNode[1].toBytes());
          return MatchProofValue(std::move(nodeVec), value, envelope_type);
        }
        // Extension: follow the child. After a nonempty extension the remaining
        // path may be empty when the child is a branch value slot.
        nodeKey = currentNode[1];
        }
        break;
      default:
        return false;
    }
  }
  
  return false;
}

