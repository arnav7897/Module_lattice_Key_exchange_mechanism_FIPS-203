#ifndef SIMPLEFIPS202_H
#define SIMPLEFIPS202_H

#include <stdint.h>

typedef uint8_t ui8;
typedef unsigned long long u64;
typedef unsigned int ui;

// Core sponge function
void Keccak(ui r, ui c,
             ui8 *in, u64 inLen,
            ui8 sfx,
            ui8 *out, u64 outLen);

// XOFs
void FIPS202_SHAKE128( ui8 *in, u64 inLen, ui8 *out, u64 outLen);
void FIPS202_SHAKE256( ui8 *in, u64 inLen, ui8 *out, u64 outLen);

// Fixed‑length hashes
void FIPS202_SHA3_224( ui8 *in, u64 inLen, ui8 *out);
void FIPS202_SHA3_256( ui8 *in, u64 inLen, ui8 *out);
void FIPS202_SHA3_384( ui8 *in, u64 inLen, ui8 *out);
void FIPS202_SHA3_512( ui8 *in, u64 inLen, ui8 *out);

#endif // SIMPLEFIPS202_H
