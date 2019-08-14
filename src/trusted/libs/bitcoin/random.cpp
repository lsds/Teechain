// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "random.h"

#include "crypto/sha512.h"
#include "support/cleanse.h"

#include "serialize.h"        // for begin_ptr(vec)
#include "utilstrencodings.h" // for GetTime()

#include <stdlib.h>
#include <limits>

static void RandFailure()
{
    abort();
}

void RandAddSeed()
{
    // Does Nothing -- Randomness comes from SGX PRNG
}

static void RandAddSeedPerfmon()
{
    RandAddSeed();
}

/** Get 32 bytes of system entropy. */
static void GetOSRand(unsigned char *ent32)
{
    // Get Random from SGX
    sgx_read_rand((unsigned char *) ent32, 32);
}

void GetRandBytes(unsigned char* buf, int num)
{
    // Get Random from SGX
    sgx_read_rand((unsigned char *) buf, num);
}

void GetStrongRandBytes(unsigned char* out, int num)
{
    CSHA512 hasher;
    unsigned char buf[64];

    // First source: OpenSSL's RNG
    RandAddSeedPerfmon();
    GetRandBytes(buf, 32);
    hasher.Write(buf, 32);

    // Second source: OS RNG
    GetOSRand(buf);
    hasher.Write(buf, 32);

    // Produce output
    hasher.Finalize(buf);
    memcpy(out, buf, num);
    memory_cleanse(buf, 64);
}

uint64_t GetRand(uint64_t nMax)
{
    if (nMax == 0)
        return 0;

    // The range of the random source must be a multiple of the modulus
    // to give every possible output value an equal possibility
    uint64_t nRange = (std::numeric_limits<uint64_t>::max() / nMax) * nMax;
    uint64_t nRand = 0;
    do {
        GetRandBytes((unsigned char*)&nRand, sizeof(nRand));
    } while (nRand >= nRange);
    return (nRand % nMax);
}

int GetRandInt(int nMax)
{
    return GetRand(nMax);
}

uint256 GetRandHash()
{
    uint256 hash;
    GetRandBytes((unsigned char*)&hash, sizeof(hash));
    return hash;
}

FastRandomContext::FastRandomContext(bool fDeterministic)
{
    // The seed values have some unlikely fixed points which we avoid.
    if (fDeterministic) {
        Rz = Rw = 11;
    } else {
        uint32_t tmp;
        do {
            GetRandBytes((unsigned char*)&tmp, 4);
        } while (tmp == 0 || tmp == 0x9068ffffU);
        Rz = tmp;
        do {
            GetRandBytes((unsigned char*)&tmp, 4);
        } while (tmp == 0 || tmp == 0x464fffffU);
        Rw = tmp;
    }
}

