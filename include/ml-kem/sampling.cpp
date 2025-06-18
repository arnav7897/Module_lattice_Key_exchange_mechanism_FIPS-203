#include "sampling.hpp"

vector<i16> NTT_sample(vector<ui8> &random, ui8 i, ui8 j_index) {
    random.push_back(i);
    random.push_back(j_index);

    ui8 seed[34];
    for(int i = 0; i < 34; i++) {
        seed[i] = random[i];
    }

    ui8 out[768];
    FIPS202_SHAKE128(seed, 34, out, 768);

    vector<i16> result;
    int j = 0, pos = 0;
    while(j < 256) {
        int d1 = out[pos] + 256 * (out[pos + 1] % 16);
        int d2 = floor(out[pos + 1] / 16) + 16 * out[pos + 2];

        if (d1 < Kyber_Q) {
            result.push_back(d1);
            j++;
        }

        if (d2 < Kyber_Q && j < 256) {
            result.push_back(d2);
            j++;
        }

        pos += 3;  // advance to avoid infinite loop
    }

    return result;
}

/**
Input: byte array 𝐵 ∈ 𝔹^64𝜂.
Output: array 𝑓 ∈ ℤ^256_𝑞 . ▷ the coefficients of the sampled polynomial 
**/
vector<i16> Binomial_sample(vector<ui8> &random, int eta){
    if (random.size() < 64*eta){
        size_t old_size = random.size();
        size_t new_size = 64*eta;
        random.resize(new_size,0);
        for(int i = old_size;i<new_size;i++){
            random[i]= rand()%256;
        }
    }
    vector<bool> bit = ByteToBit(random);
    vector<i16> result(256,0);
    for(int i = 0;i<256;i++){
        int a=0,b=0;
        for(int j =0 ; j<eta ; j++){
            a = a + bit[2*i*eta + j];
        }
        for(int j=0 ; j<eta ; j++){
            b = b + bit[2*i*eta +j + eta];
        }
        result[i] = ((a - b)%Kyber_Q + Kyber_Q)%Kyber_Q;  // ▷ 0 ≤ 𝑓[𝑖] ≤ 𝜂 or 𝑞 − 𝜂 ≤ 𝑓[𝑖] ≤ 𝑞 − 1
    }
    return result;
}