// base.cpp
#include "ml-kem/base.hpp"
#include <cmath>

/*************************************************
* Name:        BitToByte
*
* Description: Converts a vector of bits (LSB-first) to a vector of bytes.
*              Pads the bit vector to a multiple of 8, then groups
*              each 8 bits into a byte.
*
* Arguments:   - vector<bool>& a: vector of bits (LSB-first)
*
* Returns:     - vector<ui8>: resulting byte array
**************************************************/
vector<ui8> BitToByte( vector<bool> &a) {
    size_t new_size = ((a.size() + 7) / 8) * 8;
    vector<bool> bits = a;
    bits.resize(new_size, 0);

    vector<ui8> result(new_size / 8, 0);
    for (size_t i = 0; i < bits.size(); i++) {
        result[i / 8] |= (bits[i] << (i % 8));
    }
    return result;
}

/*************************************************
* Name:        ByteToBit
*
* Description: Converts a vector of bytes to a vector of bits (LSB-first).
*              Each byte is split into 8 bits.
*
* Arguments:   - vector<ui8>& a: input byte array
*
* Returns:     - vector<bool>: bit representation of input
**************************************************/
vector<bool> ByteToBit( vector<ui8> &a) {
    vector<bool> result(a.size() * 8, 0);
    for (size_t i = 0; i < a.size() * 8; i++) {
        result[i] = (a[i / 8] >> (i % 8)) & 1;
    }
    return result;
}

/*************************************************
* Name:        ByteEncode
*
* Description: Encodes a polynomial in Z_q^256 into a byte array
*              using `d` bits per coefficient. Handles negative coefficients
*              by lifting them into [0, Q).
*
* Arguments:   - vector<i16>& f: input polynomial with 256 coefficients
*              - int d: number of bits per coefficient
*
* Returns:     - vector<ui8>: encoded byte array
**************************************************/
vector<ui8> ByteEncode(vector<i16> &f, int d) {
    vector<bool> b(256 * d, 0);
    for (int i = 0; i < 256; i++) {
        i16 a = f[i];
        if (a < 0) a += Kyber_Q;
        for (int j = 0; j < d; j++) {
            b[i * d + j] = a % 2;
            a /= 2;
        }
    }
    return BitToByte(b);
}

/*************************************************
* Name:        ByteDecode
*
* Description: Decodes a byte array into a polynomial of 256 coefficients.
*              Each coefficient is interpreted using `d` bits.
*              If d < 12, modulus is 2^d; else modulus is Kyber_Q.
*
* Arguments:   - vector<ui8>& b: input byte array
*              - int d: number of bits per coefficient
*
* Returns:     - vector<i16>: decoded polynomial in Z_m^256
**************************************************/
vector<i16> ByteDecode(vector<ui8> &b, int d) {
    vector<bool> bit = ByteToBit(b);
    if (bit.size() != 256 * d) bit.resize(256 * d, 0);

    vector<i16> f(256, 0);
    int m = (d < 12) ? (1 << d) : Kyber_Q;
    for (int i = 0; i < 256; i++) {
        for (int j = 0; j < d; j++) {
            f[i] |= (bit[i * d + j] << j);
        }
        f[i] %= m;
    }
    return f;
}

/*************************************************
* Name:        Compress
*
* Description: Compresses polynomial coefficients from [0, Q) into [0, 2^d).
*              Rounds the result to the nearest integer using midpoint rounding.
*
* Arguments:   - vector<i16>& a: input polynomial
*              - int d: target bit width
*
* Returns:     - vector<i16>: compressed coefficients
**************************************************/
vector<i16> Compress(vector<i16>& a, int d) {
    int factor = 1 << d;  // 2^d
    vector<i16> result(a.size());
    for (int i = 0; i < a.size(); i++) {
        int x = a[i];
        if (x < 0) x += Kyber_Q; // Ensure x ∈ [0, q)
        
        // Nearest integer: round((x * 2^d) / q)
        int64_t scaled = static_cast<int64_t>(x) * factor;
        int rounded = (scaled + Kyber_Q / 2) / Kyber_Q;
        result[i] = rounded % factor;  // mod 2^d
    }
    return result;
}

/*************************************************
* Name:        Decompress
*
* Description: Expands compressed coefficients from [0, 2^d) back into [0, Q).
*              Uses midpoint rounding during scaling.
*
* Arguments:   - vector<i16>& a: compressed polynomial
*              - int d: bit width used in compression
*
* Returns:     - vector<i16>: decompressed coefficients in [0, Q)
**************************************************/
vector<i16> Decompress( vector<i16>& a, int d) {
    int result_size = a.size();
    vector<i16> result(result_size);
    int shift = 1 << (d - 1);  // for rounding
    for (int i = 0; i < result_size; i++) {
        int val = a[i];
        result[i] = ((val * Kyber_Q) + shift) >> d;
    }
    return result;
}
