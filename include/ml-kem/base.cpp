// base.cpp
#include "ml-kem/base.hpp"
#include <cmath>

// Convert bits to bytes (LSB-first)
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

// Convert bytes to bits (LSB-first)
vector<bool> ByteToBit( vector<ui8> &a) {
    vector<bool> result(a.size() * 8, 0);
    for (size_t i = 0; i < a.size() * 8; i++) {
        result[i] = (a[i / 8] >> (i % 8)) & 1;
    }
    return result;
}

// ByteEncode: Encode Z_q^256 into bytes using d bits per coefficient
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

// ByteDecode: Decode bytes into Z_m^256, m = 2^d or Q
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

// Compress: scale from [0, Q) -> [0, 2^d)
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
