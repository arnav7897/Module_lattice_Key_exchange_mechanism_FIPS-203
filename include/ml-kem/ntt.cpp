#include "ntt.hpp"

// Modulus used in posyber
constexpr int16_t Q = Kyber_Q;
constexpr int16_t QINV = 62209;   // -q^{-1} mod 2^16 (precomputed)
constexpr int32_t V = (1 << 26) / Q + 1;  // For Barrett reduction

// NTT Zetas for posyber
constexpr int16_t zetas[128] = {
    2285, 2571, 2645, 1254, 395, 1125, 1751, 2647,
    2995, 878, 2443, 2005, 3050, 3121, 1223, 652,
    2774, 1855, 289, 228, 2483, 287, 2778, 3054,
    2092, 324, 622, 1577, 182, 962, 2127, 1855,
    1727, 3143, 3183, 3254, 817, 2928, 102, 1755,
    203, 1846, 3080, 2659, 1065, 1302, 1721, 2044,
    358, 2220, 3203, 1441, 264, 383, 2124, 2667,
    449, 227, 233, 587, 2003, 2030, 308, 2587,
    2367, 3082, 266, 1223, 652, 2774, 1855, 289,
    228, 2483, 287, 2778, 3054, 2092, 324, 622,
    1577, 182, 962, 2127, 1855, 1727, 3143, 3183,
    3254, 817, 2928, 102, 1755, 203, 1846, 3080,
    2659, 1065, 1302, 1721, 2044, 358, 2220, 3203,
    1441, 264, 383, 2124, 2667, 449, 227, 233,
    587, 2003, 2030, 308, 2587
};

constexpr int16_t zetas_inv[128] = {
    1125, 2645, 2571, 2285, 652, 1223, 3121, 3050,
    2005, 2443, 878, 2995, 2647, 1751, 1125, 395,
    1254, 2645, 2571, 2285, 652, 1223, 2774, 1855,
    289, 228, 2483, 287, 2778, 3054, 2092, 324,
    622, 1577, 182, 962, 2127, 1855, 1727, 3143,
    3183, 3254, 817, 2928, 102, 1755, 203, 1846,
    3080, 2659, 1065, 1302, 1721, 2044, 358, 2220,
    3203, 1441, 264, 383, 2124, 2667, 449, 227,
    233, 587, 2003, 2030, 308, 2587, 2367, 3082,
    266, 1223, 652, 2774, 1855, 289, 228, 2483,
    287, 2778, 3054, 2092, 324, 622, 1577, 182,
    962, 2127, 1855, 1727, 3143, 3183, 3254, 817,
    2928, 102, 1755, 203, 1846, 3080, 2659, 1065,
    1302, 1721, 2044, 358, 2220, 3203, 1441, 264,
    383, 2124, 2667, 449, 227, 233, 587, 2003,
    2030, 308, 2587
};

int16_t montgomery_reduce(int32_t a) {
    int16_t t = (int16_t)(a * QINV);
    t = (a - (int32_t)t * Q) >> 16;
    return t;
}

int16_t barrett_reduce(int16_t a) {
    int32_t t = ((int32_t)V * a + (1 << 25)) >> 26;
    return a - t * Q;
}

vector<i16> ntt(vector<int16_t>& x) {
    vector<i16> a = x;
    int len = 128;
    int pos = 0;
    while (len >= 1) { // O(log len)
        for (int start = 0; start < 256; start += 2 * len) { //o(n/len)
            for (int j = 0; j < len; j++) { //O(len)
                int16_t zeta = zetas[pos++];
                int16_t t = montgomery_reduce((int32_t)zeta * a[start + j + len]);
                a[start + j + len] = barrett_reduce(a[start + j] - t);
                a[start + j] = barrett_reduce(a[start + j] + t);
            }
        }
        len >>= 1;
    }
    return a;
}

void invntt(vector<int16_t>& a) {
    int len = 1;
    int pos = 127;
    while (len <= 128) {
        for (int start = 0; start < 256; start += 2 * len) {
            for (int j = 0; j < len; j++) {
                int16_t t = a[start + j];
                a[start + j] = barrett_reduce(t + a[start + j + len]);
                a[start + j + len] = montgomery_reduce((int32_t)(t - a[start + j + len]) * zetas_inv[pos--]);
            }
        }
        len <<= 1;
    }

    int16_t inv_n = 1441;  // 256^{-1} mod 3329
    for (int i = 0; i < 256; ++i)
        a[i] = montgomery_reduce((int32_t)a[i] * inv_n);
}

vector<i16> poly_mul(vector<i16>& a, vector<i16>& b) {
    vector<i16> fa = a, fb = b;
    fa = ntt(a);
    fb = ntt(b);
    for (int i = 0; i < Kyber_N; ++i)
        fa[i] = montgomery_reduce((int32_t)fa[i] * fb[i]);
    invntt(fa);
    return fa;
}
