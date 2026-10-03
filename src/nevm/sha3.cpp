/*
	This file is part of cpp-ethereum.

	cpp-ethereum is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	cpp-ethereum is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
*/
/** @file SHA3.cpp
 * @author Gav Wood <i@gavwood.com>
 * @date 2014
 */

#include <nevm/sha3.h>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <nevm/rlp.h>
using namespace std;
using namespace dev;

namespace dev
{

namespace blake2s_internal
{

constexpr std::array<uint32_t, 8> IV{
    0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
    0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
};

constexpr std::array<std::array<uint8_t, 16>, 10> SIGMA{{
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
    {{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}},
    {{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}},
    {{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8}},
    {{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}},
    {{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9}},
    {{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}},
    {{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10}},
    {{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}},
    {{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}},
}};

uint32_t ReadLE32(const uint8_t* input)
{
    return static_cast<uint32_t>(input[0]) |
        (static_cast<uint32_t>(input[1]) << 8) |
        (static_cast<uint32_t>(input[2]) << 16) |
        (static_cast<uint32_t>(input[3]) << 24);
}

void WriteLE32(uint8_t* output, uint32_t value)
{
    output[0] = static_cast<uint8_t>(value);
    output[1] = static_cast<uint8_t>(value >> 8);
    output[2] = static_cast<uint8_t>(value >> 16);
    output[3] = static_cast<uint8_t>(value >> 24);
}

constexpr uint32_t RotR(uint32_t value, unsigned int shift)
{
    return (value >> shift) | (value << (32 - shift));
}

// BLAKE2s additions are modulo 2^32; widen first so integer sanitizers do not
// treat the algorithm's required wraparound as an error.
constexpr uint32_t AddModulo32(uint32_t a, uint32_t b,
    uint32_t c = 0) noexcept
{
    return static_cast<uint32_t>(static_cast<uint64_t>(a) + b + c);
}

void Mix(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d,
    uint32_t x, uint32_t y)
{
    a = AddModulo32(a, b, x);
    d = RotR(d ^ a, 16);
    c = AddModulo32(c, d);
    b = RotR(b ^ c, 12);
    a = AddModulo32(a, b, y);
    d = RotR(d ^ a, 8);
    c = AddModulo32(c, d);
    b = RotR(b ^ c, 7);
}

void Compress(std::array<uint32_t, 8>& state, const uint8_t* block,
    uint64_t bytes, bool final)
{
    std::array<uint32_t, 16> message{};
    std::array<uint32_t, 16> work{};
    for (size_t i = 0; i < message.size(); ++i) {
        message[i] = ReadLE32(block + 4 * i);
    }
    for (size_t i = 0; i < state.size(); ++i) {
        work[i] = state[i];
        work[i + 8] = IV[i];
    }
    work[12] ^= static_cast<uint32_t>(bytes);
    work[13] ^= static_cast<uint32_t>(bytes >> 32);
    if (final) work[14] = ~work[14];

    for (const auto& permutation : SIGMA) {
        Mix(work[0], work[4], work[8], work[12],
            message[permutation[0]], message[permutation[1]]);
        Mix(work[1], work[5], work[9], work[13],
            message[permutation[2]], message[permutation[3]]);
        Mix(work[2], work[6], work[10], work[14],
            message[permutation[4]], message[permutation[5]]);
        Mix(work[3], work[7], work[11], work[15],
            message[permutation[6]], message[permutation[7]]);
        Mix(work[0], work[5], work[10], work[15],
            message[permutation[8]], message[permutation[9]]);
        Mix(work[1], work[6], work[11], work[12],
            message[permutation[10]], message[permutation[11]]);
        Mix(work[2], work[7], work[8], work[13],
            message[permutation[12]], message[permutation[13]]);
        Mix(work[3], work[4], work[9], work[14],
            message[permutation[14]], message[permutation[15]]);
    }
    for (size_t i = 0; i < state.size(); ++i) {
        state[i] ^= work[i] ^ work[i + 8];
    }
}

void Hash(uint8_t* output, const uint8_t* input, size_t input_size)
{
    std::array<uint32_t, 8> state{IV};
    // Digest length 32, key length 0, fanout 1, depth 1.
    state[0] ^= 0x01010020U;
    uint64_t bytes{0};
    while (input_size > 64) {
        bytes += 64;
        Compress(state, input, bytes, false);
        input += 64;
        input_size -= 64;
    }
    std::array<uint8_t, 64> final_block{};
    if (input_size != 0) std::memcpy(final_block.data(), input, input_size);
    bytes += input_size;
    Compress(state, final_block.data(), bytes, true);
    for (size_t i = 0; i < state.size(); ++i) {
        WriteLE32(output + 4 * i, state[i]);
    }
}

} // namespace blake2s_internal

h256 EmptySHA3 = sha3(bytesConstRef());
h256 EmptyListSHA3 = sha3(rlpList());

namespace keccak
{

/** libkeccak-tiny
 *
 * A single-file implementation of SHA-3 and SHAKE.
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */

#define decshake(bits) \
  int shake##bits(uint8_t*, size_t, const uint8_t*, size_t);

#define decsha3(bits) \
  int sha3_##bits(uint8_t*, size_t, const uint8_t*, size_t);

decshake(128)
decshake(256)
decsha3(224)
decsha3(256)
decsha3(384)
decsha3(512)

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
static const uint8_t rho[24] = \
  { 1,  3,   6, 10, 15, 21,
	28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43,
	62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = \
  {10,  7, 11, 17, 18, 3,
	5, 16,  8, 21, 24, 4,
   15, 23, 19, 13, 12, 2,
   20, 14, 22,  9, 6,  1};
static const uint64_t RC[24] = \
  {1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
   0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
   0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
   0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
   0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
   0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
  v = 0;            \
  REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static inline void keccakf(void* state) {
  uint64_t* a = (uint64_t*)state;
  uint64_t b[5] = {0};
  uint64_t t = 0;
  uint8_t x, y;

  for (int i = 0; i < 24; i++) {
	// Theta
	FOR5(x, 1,
		 b[x] = 0;
		 FOR5(y, 5,
			  b[x] ^= a[x + y]; ))
	FOR5(x, 1,
		 FOR5(y, 5,
			  a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
	// Rho and pi
	t = a[1];
	x = 0;
	REPEAT24(b[0] = a[pi[x]];
			 a[pi[x]] = rol(t, rho[x]);
			 t = b[0];
			 x++; )
	// Chi
	FOR5(y,
	   5,
	   FOR5(x, 1,
			b[x] = a[y + x];)
	   FOR5(x, 1,
			a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
	// Iota
	a[0] ^= RC[i];
  }
}

/******** The FIPS202-defined functions. ********/

/*** Some helper macros. ***/

#define _(S) do { S } while (0)
#define FOR(i, ST, L, S) \
  _(for (size_t i = 0; i < L; i += ST) { S; })
#define mkapply_ds(NAME, S)                                          \
  static inline void NAME(uint8_t* dst,                              \
						  const uint8_t* src,                        \
						  size_t len) {                              \
	FOR(i, 1, len, S);                                               \
  }
#define mkapply_sd(NAME, S)                                          \
  static inline void NAME(const uint8_t* src,                        \
						  uint8_t* dst,                              \
						  size_t len) {                              \
	FOR(i, 1, len, S);                                               \
  }

mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
mkapply_sd(setout, dst[i] = src[i])  // setout

#define P keccakf
#define Plen 200

// Fold P*F over the full blocks of an input.
#define foldP(I, L, F) \
  while (L >= rate) {  \
	F(a, I, rate);     \
	P(a);              \
	I += rate;         \
	L -= rate;         \
  }

/** The sponge-based hash construction. **/
static inline int hash(uint8_t* out, size_t outlen,
					   const uint8_t* in, size_t inlen,
					   size_t rate, uint8_t delim) {
  if ((out == nullptr) || ((in == nullptr) && inlen != 0) || (rate >= Plen)) {
	return -1;
  }
  uint8_t a[Plen] = {0};
  // Absorb input.
  foldP(in, inlen, xorin);
  // Xor in the DS and pad frame.
  a[inlen] ^= delim;
  a[rate - 1] ^= 0x80;
  // Xor in the last block.
  xorin(a, in, inlen);
  // Apply P
  P(a);
  // Squeeze output.
  foldP(out, outlen, setout);
  setout(a, out, outlen);
  memset(a, 0, 200);
  return 0;
}

/*** Helper macros to define SHA3 and SHAKE instances. ***/
#define defshake(bits)                                            \
  int shake##bits(uint8_t* out, size_t outlen,                    \
				  const uint8_t* in, size_t inlen) {              \
	return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);  \
  }
#define defsha3(bits)                                             \
  int sha3_##bits(uint8_t* out, size_t outlen,                    \
				  const uint8_t* in, size_t inlen) {              \
	if (outlen > (bits/8)) {                                      \
	  return -1;                                                  \
	}                                                             \
	return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x01);  \
  }

/*** FIPS202 SHAKE VOFs ***/
defshake(128)
defshake(256)

/*** FIPS202 SHA3 FOFs ***/
defsha3(224)
defsha3(256)
defsha3(384)
defsha3(512)

}

bool sha3(bytesConstRef _input, bytesRef o_output)
{
	// FIXME: What with unaligned memory?
	if (o_output.size() != 32)
		return false;
	keccak::sha3_256(o_output.data(), 32, _input.data(), _input.size());
//	keccak::keccak(ret.data(), 32, (uint64_t const*)_input.data(), _input.size());
	return true;
}

bool blake2s256(bytesConstRef _input, bytesRef o_output)
{
	if (o_output.size() != 32) {
		return false;
	}
    blake2s_internal::Hash(o_output.data(), _input.data(), _input.size());
	return true;
}

}
