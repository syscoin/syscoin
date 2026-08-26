// Copyright (c) 2026 The Syscoin Core developers
// Copyright (c) 2026 Nicolas Consigny
// Distributed under the MIT software license, see the accompanying LICENSE file.

#include <crypto/sphincs_c11/sphincs_c11.h>

#include <crypto/sha256.h>
#include <crypto/sha3.h>
#include <support/cleanse.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <utility>
#include <vector>

namespace sphincs_c11 {
namespace {

using Node = std::array<unsigned char, 16>;
using Digest = std::array<unsigned char, 32>;
using Digits = std::array<unsigned char, 43>;
using Tree = std::vector<std::vector<Node>>;

constexpr std::size_t N = 16;
constexpr unsigned H = 16;
constexpr unsigned D = 2;
constexpr unsigned A = 11;
constexpr unsigned K = 13;
constexpr unsigned SUBTREE_H = 8;
constexpr unsigned W = 8;
constexpr unsigned WOTS_LEN = 43;
constexpr unsigned TARGET_SUM = 203;

constexpr std::size_t R_OFFSET = 0;
constexpr std::size_t FORS_VALUES_OFFSET = 16;
constexpr std::size_t FORS_AUTH_OFFSET = 224;
constexpr std::size_t FORS_AUTH_TREE_SIZE = A * N;
constexpr std::size_t HT_OFFSET = 2336;
constexpr std::size_t WOTS_BYTES = WOTS_LEN * N;
constexpr std::size_t HT_AUTH_OFFSET = WOTS_BYTES + 4;
constexpr std::size_t HT_LAYER_SIZE = WOTS_BYTES + 4 + SUBTREE_H * N;

static_assert(D * SUBTREE_H == H, "hypertree parameters must be consistent");
static_assert(HT_OFFSET + D * HT_LAYER_SIZE == SIGNATURE_SIZE, "signature layout mismatch");

enum class AddressType : unsigned char {
    WOTS_HASH = 0,
    WOTS_PK = 1,
    TREE = 2,
    FORS_TREE = 3,
    FORS_ROOTS = 4,
    // SPHINCS+C assigns a separate tweak to message compression so it cannot
    // share the WOTS chain domain even when keypair/chain/hash are all zero.
    WOTS_MESSAGE = 7,
};

class CleanseGuard
{
public:
    CleanseGuard(void* data, std::size_t size) noexcept : m_data(data), m_size(size) {}
    ~CleanseGuard() { memory_cleanse(m_data, m_size); }

    CleanseGuard(const CleanseGuard&) = delete;
    CleanseGuard& operator=(const CleanseGuard&) = delete;

private:
    void* m_data;
    std::size_t m_size;
};

struct Address {
    std::array<unsigned char, 22> bytes{};
};

void PutBE32(unsigned char* out, uint32_t value)
{
    out[0] = static_cast<unsigned char>(value >> 24);
    out[1] = static_cast<unsigned char>(value >> 16);
    out[2] = static_cast<unsigned char>(value >> 8);
    out[3] = static_cast<unsigned char>(value);
}

void PutBE64(unsigned char* out, uint64_t value)
{
    for (unsigned i = 0; i < 8; ++i) {
        out[7 - i] = static_cast<unsigned char>(value >> (8 * i));
    }
}

uint32_t ReadBE32(const unsigned char* in)
{
    return (static_cast<uint32_t>(in[0]) << 24) |
           (static_cast<uint32_t>(in[1]) << 16) |
           (static_cast<uint32_t>(in[2]) << 8) |
           static_cast<uint32_t>(in[3]);
}

Address MakeAddress(unsigned layer, uint64_t tree, AddressType type,
                    uint32_t word1, uint32_t word2, uint32_t word3)
{
    Address address;
    address.bytes[0] = static_cast<unsigned char>(layer);
    PutBE64(address.bytes.data() + 1, tree);
    address.bytes[9] = static_cast<unsigned char>(type);
    PutBE32(address.bytes.data() + 10, word1);
    PutBE32(address.bytes.data() + 14, word2);
    PutBE32(address.bytes.data() + 18, word3);
    return address;
}

Address SetHashAddress(Address address, uint32_t hash_address)
{
    PutBE32(address.bytes.data() + 18, hash_address);
    return address;
}

bool ConstantEquals(const unsigned char* lhs, const unsigned char* rhs, std::size_t size)
{
    unsigned char different = 0;
    for (std::size_t i = 0; i < size; ++i) different |= lhs[i] ^ rhs[i];
    return different == 0;
}

Digest Keccak256(Span<const unsigned char> input)
{
    constexpr std::size_t RATE = 136;
    uint64_t state[25]{};
    CleanseGuard state_guard(state, sizeof(state));

    std::size_t offset = 0;
    while (input.size() - offset >= RATE) {
        for (std::size_t i = 0; i < RATE; ++i) {
            state[i / 8] ^= static_cast<uint64_t>(input[offset + i]) << (8 * (i % 8));
        }
        KeccakF(state);
        offset += RATE;
    }

    const std::size_t remaining = input.size() - offset;
    for (std::size_t i = 0; i < remaining; ++i) {
        state[i / 8] ^= static_cast<uint64_t>(input[offset + i]) << (8 * (i % 8));
    }
    // Legacy Keccak padding, deliberately not the FIPS SHA3 delimiter 0x06.
    state[remaining / 8] ^= UINT64_C(0x01) << (8 * (remaining % 8));
    state[(RATE - 1) / 8] ^= UINT64_C(0x80) << (8 * ((RATE - 1) % 8));
    KeccakF(state);

    Digest output;
    for (std::size_t i = 0; i < output.size(); ++i) {
        output[i] = static_cast<unsigned char>(state[i / 8] >> (8 * (i % 8)));
    }
    return output;
}

Node TweakHash(const PublicSeed& public_seed, const Address& address,
               const Node* values, std::size_t value_count)
{
    static constexpr std::array<unsigned char, 48> ZEROS{};
    CSHA256 hasher;
    CleanseGuard hasher_guard(&hasher, sizeof(hasher));
    Digest digest;
    hasher.Write(public_seed.data(), public_seed.size());
    hasher.Write(ZEROS.data(), ZEROS.size());
    hasher.Write(address.bytes.data(), address.bytes.size());
    for (std::size_t i = 0; i < value_count; ++i) {
        hasher.Write(values[i].data(), values[i].size());
    }
    hasher.Finalize(digest.data());

    Node output;
    std::copy_n(digest.begin(), output.size(), output.begin());
    memory_cleanse(digest.data(), digest.size());
    return output;
}

Node HashF(const PublicSeed& public_seed, const Address& address, const Node& value)
{
    return TweakHash(public_seed, address, &value, 1);
}

Node HashH(const PublicSeed& public_seed, const Address& address,
           const Node& left, const Node& right)
{
    const std::array<Node, 2> values{left, right};
    return TweakHash(public_seed, address, values.data(), values.size());
}

Digest HashMessage(const PublicSeed& public_seed, const Node& public_root,
                   const Node& randomizer, const Message& message)
{
    static constexpr std::array<unsigned char, 16> ZEROS{};
    static const std::array<unsigned char, 32> HMSG_DOMAIN_BYTES = [] {
        std::array<unsigned char, 32> value{};
        value.fill(0xff);
        return value;
    }();

    CSHA256 hasher;
    CleanseGuard hasher_guard(&hasher, sizeof(hasher));
    Digest digest;
    hasher.Write(public_seed.data(), public_seed.size());
    hasher.Write(ZEROS.data(), ZEROS.size());
    hasher.Write(public_root.data(), public_root.size());
    hasher.Write(ZEROS.data(), ZEROS.size());
    hasher.Write(randomizer.data(), randomizer.size());
    hasher.Write(ZEROS.data(), ZEROS.size());
    hasher.Write(message.data(), message.size());
    hasher.Write(HMSG_DOMAIN_BYTES.data(), HMSG_DOMAIN_BYTES.size());
    hasher.Finalize(digest.data());
    return digest;
}

Digest WotsDigest(const PublicSeed& public_seed, unsigned layer, uint64_t tree,
                  uint32_t keypair, const Node& message, uint32_t count)
{
    static constexpr std::array<unsigned char, 48> ZEROS{};
    const Address address = MakeAddress(layer, tree, AddressType::WOTS_MESSAGE,
                                        keypair, 0, 0);
    std::array<unsigned char, 4> count_bytes;
    PutBE32(count_bytes.data(), count);

    CSHA256 hasher;
    CleanseGuard hasher_guard(&hasher, sizeof(hasher));
    Digest digest;
    hasher.Write(public_seed.data(), public_seed.size());
    hasher.Write(ZEROS.data(), ZEROS.size());
    hasher.Write(address.bytes.data(), address.bytes.size());
    hasher.Write(message.data(), message.size());
    hasher.Write(count_bytes.data(), count_bytes.size());
    hasher.Finalize(digest.data());
    return digest;
}

uint32_t ExtractBitsMSB(const Digest& digest, unsigned bit_offset, unsigned width)
{
    uint32_t value = 0;
    for (unsigned i = 0; i < width; ++i) {
        const unsigned bit = bit_offset + i;
        value = (value << 1) | ((digest[bit / 8] >> (7 - bit % 8)) & 1U);
    }
    return value;
}

Digits ExtractWotsDigits(const Digest& digest)
{
    Digits digits;
    for (unsigned i = 0; i < WOTS_LEN; ++i) {
        digits[i] = static_cast<unsigned char>(ExtractBitsMSB(digest, i * 3, 3));
    }
    return digits;
}

unsigned DigitSum(const Digits& digits)
{
    unsigned sum = 0;
    for (unsigned char digit : digits) sum += digit;
    return sum;
}

Node DeriveWotsSecret(const SecretSeed& secret_seed, unsigned layer, uint64_t tree,
                      uint32_t keypair, uint32_t chain)
{
    std::array<unsigned char, 80> input{};
    CleanseGuard input_guard(input.data(), input.size());
    std::copy(secret_seed.begin(), secret_seed.end(), input.begin());
    std::memcpy(input.data() + 32, "wots", 4);
    PutBE32(input.data() + 36, layer);
    // The reference encodes the 64-bit tree value as a 256-bit integer.
    PutBE64(input.data() + 64, tree);
    PutBE32(input.data() + 72, keypair);
    PutBE32(input.data() + 76, chain);
    Digest digest = Keccak256(input);
    CleanseGuard digest_guard(digest.data(), digest.size());

    Node output;
    std::copy_n(digest.begin(), output.size(), output.begin());
    return output;
}

Node DeriveForsSecret(const SecretSeed& secret_seed, uint32_t hypertree_index,
                      uint32_t tree_index, uint32_t leaf_index)
{
    std::array<unsigned char, 48> input{};
    CleanseGuard input_guard(input.data(), input.size());
    std::copy(secret_seed.begin(), secret_seed.end(), input.begin());
    std::memcpy(input.data() + 32, "fors", 4);
    PutBE32(input.data() + 36, hypertree_index);
    PutBE32(input.data() + 40, tree_index);
    PutBE32(input.data() + 44, leaf_index);
    Digest digest = Keccak256(input);
    CleanseGuard digest_guard(digest.data(), digest.size());

    Node output;
    std::copy_n(digest.begin(), output.size(), output.begin());
    return output;
}

Node DeriveRandomizer(const SecretSeed& secret_seed, const Message& message, uint32_t nonce)
{
    std::array<unsigned char, 103> input{};
    CleanseGuard input_guard(input.data(), input.size());
    std::copy(secret_seed.begin(), secret_seed.end(), input.begin());
    std::memcpy(input.data() + 32, "R_grind", 7);
    std::copy(message.begin(), message.end(), input.begin() + 39);
    // nonce is encoded as a 256-bit big-endian value.
    PutBE32(input.data() + 99, nonce);
    Digest digest = Keccak256(input);
    CleanseGuard digest_guard(digest.data(), digest.size());

    Node output;
    std::copy_n(digest.begin(), output.size(), output.begin());
    return output;
}

Node Chain(const PublicSeed& public_seed, Address base, Node value,
           unsigned start_position, unsigned steps)
{
    for (unsigned step = 0; step < steps; ++step) {
        value = HashF(public_seed, SetHashAddress(base, start_position + step), value);
    }
    return value;
}

Node WotsPublicKey(const PublicSeed& public_seed, const SecretSeed& secret_seed,
                   unsigned layer, uint64_t tree, uint32_t keypair)
{
    std::array<Node, WOTS_LEN> tops;
    const Address base = MakeAddress(layer, tree, AddressType::WOTS_HASH, keypair, 0, 0);
    for (unsigned i = 0; i < WOTS_LEN; ++i) {
        Node secret = DeriveWotsSecret(secret_seed, layer, tree, keypair, i);
        CleanseGuard secret_guard(secret.data(), secret.size());
        Address chain_address = base;
        PutBE32(chain_address.bytes.data() + 14, i);
        tops[i] = Chain(public_seed, chain_address, secret, 0, W - 1);
    }
    const Address pk_address = MakeAddress(layer, tree, AddressType::WOTS_PK, keypair, 0, 0);
    return TweakHash(public_seed, pk_address, tops.data(), tops.size());
}

Tree BuildWotsTree(const PublicSeed& public_seed, const SecretSeed& secret_seed,
                   unsigned layer, uint64_t tree)
{
    Tree nodes;
    nodes.emplace_back(1U << SUBTREE_H);
    for (uint32_t keypair = 0; keypair < nodes.front().size(); ++keypair) {
        nodes.front()[keypair] = WotsPublicKey(public_seed, secret_seed, layer, tree, keypair);
    }

    for (unsigned height = 0; height < SUBTREE_H; ++height) {
        const auto& previous = nodes.back();
        std::vector<Node> level(previous.size() / 2);
        for (uint32_t index = 0; index < level.size(); ++index) {
            const Address address = MakeAddress(layer, tree, AddressType::TREE, 0,
                                                height + 1, index);
            level[index] = HashH(public_seed, address, previous[2 * index], previous[2 * index + 1]);
        }
        nodes.push_back(std::move(level));
    }
    return nodes;
}

Tree BuildForsTree(const PublicSeed& public_seed, const SecretSeed& secret_seed,
                   uint32_t fors_tree, uint32_t hypertree_index,
                   uint32_t bottom_tree, uint32_t bottom_leaf)
{
    Tree nodes;
    nodes.emplace_back(1U << A);
    for (uint32_t leaf = 0; leaf < nodes.front().size(); ++leaf) {
        Node secret = DeriveForsSecret(secret_seed, hypertree_index, fors_tree, leaf);
        CleanseGuard secret_guard(secret.data(), secret.size());
        const Address address = MakeAddress(0, bottom_tree, AddressType::FORS_TREE,
                                            bottom_leaf, 0, (fors_tree << A) | leaf);
        nodes.front()[leaf] = HashF(public_seed, address, secret);
    }

    for (unsigned height = 0; height < A; ++height) {
        const auto& previous = nodes.back();
        std::vector<Node> level(previous.size() / 2);
        for (uint32_t index = 0; index < level.size(); ++index) {
            const uint32_t tree_index = (fors_tree << (A - height - 1)) | index;
            const Address address = MakeAddress(0, bottom_tree, AddressType::FORS_TREE,
                                                bottom_leaf, height + 1, tree_index);
            level[index] = HashH(public_seed, address, previous[2 * index], previous[2 * index + 1]);
        }
        nodes.push_back(std::move(level));
    }
    return nodes;
}

bool FindWotsCount(const PublicSeed& public_seed, unsigned layer, uint64_t tree,
                   uint32_t keypair, const Node& message, uint32_t& count,
                   Digits& digits)
{
    for (uint32_t candidate = 0; candidate < GRIND_LIMIT; ++candidate) {
        const Digest digest = WotsDigest(public_seed, layer, tree, keypair, message, candidate);
        Digits candidate_digits = ExtractWotsDigits(digest);
        if (DigitSum(candidate_digits) == TARGET_SUM) {
            count = candidate;
            digits = candidate_digits;
            return true;
        }
    }
    return false;
}

bool WotsSign(const PublicSeed& public_seed, const SecretSeed& secret_seed,
              unsigned layer, uint64_t tree, uint32_t keypair, const Node& message,
              unsigned char* output, uint32_t& count)
{
    Digits digits;
    if (!FindWotsCount(public_seed, layer, tree, keypair, message, count, digits)) return false;

    const Address base = MakeAddress(layer, tree, AddressType::WOTS_HASH, keypair, 0, 0);
    for (unsigned i = 0; i < WOTS_LEN; ++i) {
        Node secret = DeriveWotsSecret(secret_seed, layer, tree, keypair, i);
        CleanseGuard secret_guard(secret.data(), secret.size());
        Address chain_address = base;
        PutBE32(chain_address.bytes.data() + 14, i);
        const Node value = Chain(public_seed, chain_address, secret, 0, digits[i]);
        std::copy(value.begin(), value.end(), output + i * N);
    }
    return true;
}

Node ReadNode(Span<const unsigned char> bytes, std::size_t offset)
{
    Node node;
    std::copy_n(bytes.begin() + offset, node.size(), node.begin());
    return node;
}

void WriteNode(Signature& signature, std::size_t offset, const Node& node)
{
    std::copy(node.begin(), node.end(), signature.begin() + offset);
}

bool ComputeRoot(const PublicSeed& public_seed, const SecretSeed& secret_seed,
                 Node& root, Tree& top_tree)
{
    top_tree = BuildWotsTree(public_seed, secret_seed, D - 1, 0);
    if (top_tree.size() != SUBTREE_H + 1 || top_tree.back().size() != 1) {
        return false;
    }
    root = top_tree.back()[0];
    return true;
}

bool GrindRandomizer(const PublicSeed& public_seed, const SecretSeed& secret_seed,
                     const Node& public_root, const Message& message,
                     Node& randomizer, Digest& message_digest)
{
    for (uint32_t nonce = 0; nonce < GRIND_LIMIT; ++nonce) {
        Node candidate = DeriveRandomizer(secret_seed, message, nonce);
        Digest digest = HashMessage(public_seed, public_root, candidate, message);
        if (ExtractBitsMSB(digest, (K - 1) * A, A) == 0) {
            randomizer = candidate;
            message_digest = digest;
            return true;
        }
    }
    return false;
}

bool SignImpl(const SecretSeed& secret_seed, const PublicSeed& public_seed,
              const Node& public_root, const Tree& top_tree,
              const Message& message, Signature& signature)
{
    Node randomizer;
    Digest message_digest;
    if (!GrindRandomizer(public_seed, secret_seed, public_root, message,
                         randomizer, message_digest)) {
        return false;
    }
    WriteNode(signature, R_OFFSET, randomizer);

    const uint32_t hypertree_index = ExtractBitsMSB(message_digest, K * A, H);
    const uint32_t bottom_leaf = hypertree_index & ((1U << SUBTREE_H) - 1);
    const uint32_t bottom_tree = hypertree_index >> SUBTREE_H;

    std::array<Node, K> fors_roots;
    for (uint32_t tree_index = 0; tree_index < K; ++tree_index) {
        Tree tree = BuildForsTree(public_seed, secret_seed, tree_index,
                                  hypertree_index, bottom_tree, bottom_leaf);
        if (tree.size() != A + 1 || tree.back().size() != 1) return false;

        if (tree_index + 1 < K) {
            const uint32_t selected = ExtractBitsMSB(message_digest, tree_index * A, A);
            Node secret = DeriveForsSecret(secret_seed, hypertree_index, tree_index, selected);
            CleanseGuard secret_guard(secret.data(), secret.size());
            WriteNode(signature, FORS_VALUES_OFFSET + tree_index * N, secret);

            uint32_t path_index = selected;
            for (unsigned height = 0; height < A; ++height) {
                WriteNode(signature,
                          FORS_AUTH_OFFSET + tree_index * FORS_AUTH_TREE_SIZE + height * N,
                          tree[height][path_index ^ 1]);
                path_index >>= 1;
            }
            fors_roots[tree_index] = tree.back()[0];
        } else {
            // The final digest field is ground to zero. Reveal this tree's raw
            // root and hash it once as leaf zero under the final FORS address.
            WriteNode(signature, FORS_VALUES_OFFSET + tree_index * N, tree.back()[0]);
            const Address address = MakeAddress(0, bottom_tree, AddressType::FORS_TREE,
                                                bottom_leaf, 0, tree_index << A);
            fors_roots[tree_index] = HashF(public_seed, address, tree.back()[0]);
        }
    }

    const Address roots_address = MakeAddress(0, bottom_tree, AddressType::FORS_ROOTS,
                                              bottom_leaf, 0, 0);
    Node current = TweakHash(public_seed, roots_address, fors_roots.data(), fors_roots.size());

    uint32_t path = hypertree_index;
    std::size_t signature_offset = HT_OFFSET;
    for (unsigned layer = 0; layer < D; ++layer) {
        const uint32_t leaf = path & ((1U << SUBTREE_H) - 1);
        path >>= SUBTREE_H;
        const uint64_t tree_index = path;

        Tree generated_tree;
        const Tree* tree{&top_tree};
        if (layer + 1 != D) {
            generated_tree = BuildWotsTree(
                public_seed, secret_seed, layer, tree_index);
            tree = &generated_tree;
        }
        if (tree->size() != SUBTREE_H + 1 || tree->back().size() != 1) {
            return false;
        }

        uint32_t count = 0;
        if (!WotsSign(public_seed, secret_seed, layer, tree_index, leaf, current,
                      signature.data() + signature_offset, count)) {
            return false;
        }
        PutBE32(signature.data() + signature_offset + WOTS_BYTES, count);

        uint32_t merkle_index = leaf;
        for (unsigned height = 0; height < SUBTREE_H; ++height) {
            WriteNode(signature, signature_offset + HT_AUTH_OFFSET + height * N,
                      (*tree)[height][merkle_index ^ 1]);
            merkle_index >>= 1;
        }
        current = tree->back()[0];
        signature_offset += HT_LAYER_SIZE;
    }
    return ConstantEquals(current.data(), public_root.data(), N);
}

bool VerifyImpl(const PublicSeed& public_seed, const Node& public_root,
                const Message& message, Span<const unsigned char> signature)
{
    const Node randomizer = ReadNode(signature, R_OFFSET);
    const Digest message_digest = HashMessage(public_seed, public_root, randomizer, message);
    if (ExtractBitsMSB(message_digest, (K - 1) * A, A) != 0) return false;

    const uint32_t hypertree_index = ExtractBitsMSB(message_digest, K * A, H);
    const uint32_t bottom_leaf = hypertree_index & ((1U << SUBTREE_H) - 1);
    const uint32_t bottom_tree = hypertree_index >> SUBTREE_H;

    std::array<Node, K> roots;
    for (uint32_t tree_index = 0; tree_index + 1 < K; ++tree_index) {
        const uint32_t selected = ExtractBitsMSB(message_digest, tree_index * A, A);
        Address address = MakeAddress(0, bottom_tree, AddressType::FORS_TREE,
                                      bottom_leaf, 0, (tree_index << A) | selected);
        Node node = HashF(public_seed, address,
                          ReadNode(signature, FORS_VALUES_OFFSET + tree_index * N));

        uint32_t path_index = selected;
        for (unsigned height = 0; height < A; ++height) {
            const Node sibling = ReadNode(signature,
                                          FORS_AUTH_OFFSET + tree_index * FORS_AUTH_TREE_SIZE + height * N);
            const uint32_t parent = path_index >> 1;
            address = MakeAddress(0, bottom_tree, AddressType::FORS_TREE, bottom_leaf,
                                  height + 1,
                                  (tree_index << (A - height - 1)) | parent);
            node = (path_index & 1) ? HashH(public_seed, address, sibling, node)
                                    : HashH(public_seed, address, node, sibling);
            path_index = parent;
        }
        roots[tree_index] = node;
    }

    const Address forced_zero_address = MakeAddress(0, bottom_tree, AddressType::FORS_TREE,
                                                    bottom_leaf, 0, (K - 1) << A);
    roots[K - 1] = HashF(public_seed, forced_zero_address,
                         ReadNode(signature, FORS_VALUES_OFFSET + (K - 1) * N));
    const Address roots_address = MakeAddress(0, bottom_tree, AddressType::FORS_ROOTS,
                                              bottom_leaf, 0, 0);
    Node current = TweakHash(public_seed, roots_address, roots.data(), roots.size());

    uint32_t path = hypertree_index;
    std::size_t signature_offset = HT_OFFSET;
    for (unsigned layer = 0; layer < D; ++layer) {
        const uint32_t leaf = path & ((1U << SUBTREE_H) - 1);
        path >>= SUBTREE_H;
        const uint64_t tree_index = path;
        const uint32_t count = ReadBE32(signature.data() + signature_offset + WOTS_BYTES);
        // The consensus profile accepts exactly the counter search space used
        // by its deterministic signer. Treating the remaining uint32 range as
        // canonical would leave an unnecessary implementation/spec gap.
        if (count >= GRIND_LIMIT) return false;
        const Digest digest = WotsDigest(public_seed, layer, tree_index, leaf, current, count);
        const Digits digits = ExtractWotsDigits(digest);
        if (DigitSum(digits) != TARGET_SUM) return false;

        std::array<Node, WOTS_LEN> tops;
        const Address base = MakeAddress(layer, tree_index, AddressType::WOTS_HASH, leaf, 0, 0);
        for (unsigned i = 0; i < WOTS_LEN; ++i) {
            Address chain_address = base;
            PutBE32(chain_address.bytes.data() + 14, i);
            tops[i] = Chain(public_seed, chain_address,
                            ReadNode(signature, signature_offset + i * N),
                            digits[i], W - 1 - digits[i]);
        }
        const Address pk_address = MakeAddress(layer, tree_index, AddressType::WOTS_PK,
                                               leaf, 0, 0);
        Node node = TweakHash(public_seed, pk_address, tops.data(), tops.size());

        uint32_t merkle_index = leaf;
        for (unsigned height = 0; height < SUBTREE_H; ++height) {
            const Node sibling = ReadNode(signature,
                                          signature_offset + HT_AUTH_OFFSET + height * N);
            const uint32_t parent = merkle_index >> 1;
            const Address address = MakeAddress(layer, tree_index, AddressType::TREE,
                                                0, height + 1, parent);
            node = (merkle_index & 1) ? HashH(public_seed, address, sibling, node)
                                      : HashH(public_seed, address, node, sibling);
            merkle_index = parent;
        }
        current = node;
        signature_offset += HT_LAYER_SIZE;
    }

    return signature_offset == signature.size() &&
           ConstantEquals(current.data(), public_root.data(), N);
}

} // namespace

class SecretKey::SigningCache final
{
public:
    explicit SigningCache(Tree&& top_tree_in)
        : top_tree{std::move(top_tree_in)}
    {
    }

    const Tree top_tree;
};

SecretKey::SecretKey() noexcept = default;

SecretKey::~SecretKey()
{
    Clear();
}

SecretKey::SecretKey(SecretKey&& other) noexcept
    : m_bytes(other.m_bytes),
      m_initialized(other.m_initialized),
      m_signing_cache(std::move(other.m_signing_cache))
{
    other.Clear();
}

SecretKey& SecretKey::operator=(SecretKey&& other) noexcept
{
    if (this != &other) {
        Clear();
        m_bytes = other.m_bytes;
        m_initialized = other.m_initialized;
        m_signing_cache = std::move(other.m_signing_cache);
        other.Clear();
    }
    return *this;
}

PublicKey SecretKey::GetPublicKey() const noexcept
{
    PublicKey public_key;
    if (m_initialized) {
        std::copy_n(m_bytes.begin() + SECRET_SEED_SIZE, PUBLIC_KEY_SIZE,
                    public_key.m_bytes.begin());
    }
    return public_key;
}

void SecretKey::Clear() noexcept
{
    m_signing_cache.reset();
    memory_cleanse(m_bytes.data(), m_bytes.size());
    m_initialized = false;
}

bool GenerateKeyPair(const SecretSeed& secret_seed, const PublicSeed& public_seed,
                     PublicKey& public_key, SecretKey& secret_key)
{
    secret_key.Clear();
    public_key.m_bytes.fill(0);
    try {
        Node root;
        Tree top_tree;
        if (!ComputeRoot(public_seed, secret_seed, root, top_tree)) return false;
        auto signing_cache{std::make_unique<SecretKey::SigningCache>(
            std::move(top_tree))};

        std::copy(secret_seed.begin(), secret_seed.end(), secret_key.m_bytes.begin());
        std::copy(public_seed.begin(), public_seed.end(),
                  secret_key.m_bytes.begin() + SECRET_SEED_SIZE);
        std::copy(root.begin(), root.end(),
                  secret_key.m_bytes.begin() + SECRET_SEED_SIZE + PUBLIC_SEED_SIZE);
        secret_key.m_signing_cache = std::move(signing_cache);
        secret_key.m_initialized = true;

        std::copy(public_seed.begin(), public_seed.end(), public_key.m_bytes.begin());
        std::copy(root.begin(), root.end(), public_key.m_bytes.begin() + PUBLIC_SEED_SIZE);
        return true;
    } catch (...) {
        secret_key.Clear();
        public_key.m_bytes.fill(0);
        return false;
    }
}

bool ParsePublicKey(Span<const unsigned char> bytes, PublicKey& public_key)
{
    if (bytes.size() != PUBLIC_KEY_SIZE) {
        public_key.m_bytes.fill(0);
        return false;
    }
    std::copy(bytes.begin(), bytes.end(), public_key.m_bytes.begin());
    return true;
}

bool ParseSecretKey(Span<const unsigned char> bytes, SecretKey& secret_key)
{
    secret_key.Clear();
    if (bytes.size() != SECRET_KEY_SIZE) return false;

    SerializedSecretKey candidate;
    CleanseGuard candidate_guard(candidate.data(), candidate.size());
    std::copy(bytes.begin(), bytes.end(), candidate.begin());

    SecretSeed secret_seed;
    CleanseGuard seed_guard(secret_seed.data(), secret_seed.size());
    PublicSeed public_seed;
    std::copy_n(candidate.begin(), secret_seed.size(), secret_seed.begin());
    std::copy_n(candidate.begin() + SECRET_SEED_SIZE, public_seed.size(), public_seed.begin());

    try {
        Node root;
        Tree top_tree;
        if (!ComputeRoot(public_seed, secret_seed, root, top_tree) ||
            !ConstantEquals(root.data(), candidate.data() + SECRET_SEED_SIZE + PUBLIC_SEED_SIZE, N)) {
            return false;
        }
        auto signing_cache{std::make_unique<SecretKey::SigningCache>(
            std::move(top_tree))};
        secret_key.m_bytes = candidate;
        secret_key.m_signing_cache = std::move(signing_cache);
        secret_key.m_initialized = true;
        return true;
    } catch (...) {
        return false;
    }
}

SerializedPublicKey SerializePublicKey(const PublicKey& public_key) noexcept
{
    return public_key.GetBytes();
}

SerializedSecretKey SerializeSecretKey(const SecretKey& secret_key)
{
    if (!secret_key.m_initialized) return {};
    return secret_key.m_bytes;
}

bool Sign(const SecretKey& secret_key, const Message& message, Signature& signature)
{
    signature.fill(0);
    if (!secret_key.m_initialized || !secret_key.m_signing_cache) return false;

    SecretSeed secret_seed;
    CleanseGuard seed_guard(secret_seed.data(), secret_seed.size());
    PublicSeed public_seed;
    Node public_root;
    std::copy_n(secret_key.m_bytes.begin(), secret_seed.size(), secret_seed.begin());
    std::copy_n(secret_key.m_bytes.begin() + SECRET_SEED_SIZE,
                public_seed.size(), public_seed.begin());
    std::copy_n(secret_key.m_bytes.begin() + SECRET_SEED_SIZE + PUBLIC_SEED_SIZE,
                public_root.size(), public_root.begin());

    try {
        if (SignImpl(secret_seed, public_seed, public_root,
                     secret_key.m_signing_cache->top_tree,
                     message, signature)) {
            return true;
        }
    } catch (...) {
    }
    memory_cleanse(signature.data(), signature.size());
    return false;
}

bool Verify(const PublicKey& public_key, const Message& message,
            Span<const unsigned char> signature)
{
    if (signature.size() != SIGNATURE_SIZE) return false;

    PublicSeed public_seed;
    Node public_root;
    std::copy_n(public_key.m_bytes.begin(), public_seed.size(), public_seed.begin());
    std::copy_n(public_key.m_bytes.begin() + PUBLIC_SEED_SIZE,
                public_root.size(), public_root.begin());
    try {
        return VerifyImpl(public_seed, public_root, message, signature);
    } catch (...) {
        return false;
    }
}

std::vector<unsigned char> VerifyBatch(Span<const VerificationInput> inputs)
{
    std::vector<unsigned char> results(inputs.size(), 0);
    for (std::size_t i = 0; i < inputs.size(); ++i) {
        const VerificationInput& input = inputs[i];
        if (input.public_key != nullptr && input.message != nullptr) {
            results[i] = Verify(*input.public_key, *input.message, input.signature) ? 1 : 0;
        }
    }
    return results;
}

} // namespace sphincs_c11
