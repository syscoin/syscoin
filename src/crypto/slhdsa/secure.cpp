// Copyright (c) 2026 The Syscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/slhdsa/secure.h>

#include <cstddef>
#include <cstdint>

#if defined(_MSC_VER)
#include <Windows.h>
#endif

void syscoin_slhdsa_secure_zero(void* ptr, size_t len)
{
#if defined(_MSC_VER)
    SecureZeroMemory(ptr, len);
#else
    volatile std::uint8_t* out = static_cast<volatile std::uint8_t*>(ptr);
    while (len-- != 0) {
        *out++ = 0;
    }
#endif
}
