#ifndef SIMPLEFIPS202_H
#define SIMPLEFIPS202_H

#include <stdint.h>

typedef unsigned char u8;
typedef unsigned long long u64;
typedef unsigned int ui;

// Core sponge function
void Keccak(ui r, ui c,
            const u8 *in, u64 inLen,
            u8 sfx,
            u8 *out, u64 outLen);

// XOFs
void FIPS202_SHAKE128(const u8 *in, u64 inLen, u8 *out, u64 outLen);
void FIPS202_SHAKE256(const u8 *in, u64 inLen, u8 *out, u64 outLen);

// Fixed‑length hashes
void FIPS202_SHA3_224(const u8 *in, u64 inLen, u8 *out);
void FIPS202_SHA3_256(const u8 *in, u64 inLen, u8 *out);
void FIPS202_SHA3_384(const u8 *in, u64 inLen, u8 *out);
void FIPS202_SHA3_512(const u8 *in, u64 inLen, u8 *out);

#endif // SIMPLEFIPS202_H
