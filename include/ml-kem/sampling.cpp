#include "sampling.hpp"

vector<i16> NTT_sample(vector<ui8> &random, ui8 i, ui8 j_index) {
    ui8 seed[34];
    for (int index = 0; index < 32; index++) {
        seed[index] = random[index];
    }
    seed[32] = i;
    seed[33] = j_index;

    ui8 out[768];
    FIPS202_SHAKE128(seed, 34, out, 768);

    vector<i16> result;
    int j = 0, pos = 0;
    while (j < 256) {
        int d1 = out[pos] + 256 * (out[pos + 1] & 0x0F);
        int d2 = (out[pos + 1] >> 4) + 16 * out[pos + 2];

        if (d1 < Kyber_Q) result.push_back(d1), j++;
        if (d2 < Kyber_Q && j < 256) result.push_back(d2), j++;

        pos += 3;
    }
    
    return result;
}


/**
Input: byte array 𝐵 ∈ 𝔹^64𝜂.
Output: array 𝑓 ∈ ℤ^256_𝑞 . ▷ the coefficients of the sampled polynomial 

 * Binomial_sample: centered‑binomial distribution with parameter eta
 * Input:  random  = exactly 64*eta bytes of cryptographic randomness
 *         eta     = parameter (e.g. eta1 or eta2)
 * Output: length‑256 polynomial f in Z_q whose coefficients are
 *         (sum of eta bits) – (sum of next eta bits), mapped mod q
 */
vector<i16> Binomial_sample(vector<ui8>& random, int eta) {
    // 1) Exact‐length check
    size_t needed = 64 * eta;
    if (random.size() != needed) {
        throw invalid_argument(
            "Binomial_sample: random.size() must be exactly 64*eta bytes");
    }

    // 2) Unpack bytes → bits (LSB first)
    vector<bool> bits;
    bits.reserve(needed * 8);
    for (ui8 byte : random) {
        for (int b = 0; b < 8; ++b) {
            bits.push_back((byte >> b) & 1);
        }
    }

    // 3) Consume 2*eta bits per coefficient
    vector<i16> f(Kyber_N);
    size_t idx = 0;
    for (int i = 0; i < Kyber_N; ++i) {
        int sum0 = 0, sum1 = 0;
        // first eta bits
        for (int j = 0; j < eta; ++j) {
            sum0 += bits[idx + j];
        }
        // next eta bits
        for (int j = 0; j < eta; ++j) {
            sum1 += bits[idx + eta + j];
        }
        idx += 2 * eta;

        // centered difference in [-(eta), +eta]
        int diff = sum0 - sum1;
        // map negative to [0, q)
        if (diff < 0) diff += Kyber_Q;
        f[i] = i16(diff);
    }

    return f;
}