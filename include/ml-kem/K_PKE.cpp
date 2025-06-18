#include "K_PKE.hpp"

pair<vector<ui8>, vector<ui8>> K_PKE_KeyGen(vector<ui8>& seed) {
    // Validate seed size
    if (seed.size() != 32) {
        printf("Error: seed must be exactly 32 bytes.\n");
        return {};
    }

    // Step 1: Expand seed using SHA3-512
    ui8 in[32], out[64];
    for (int i = 0; i < 32; i++) {
        in[i] = seed[i];
    }

    FIPS202_SHA3_512(in, 32, out);  // 64-byte output

    vector<ui8> a_seed(32), s_seed(32);
    for (int i = 0; i < 32; i++) {
        a_seed[i] = out[i];
        s_seed[i] = out[i + 32];
    }

    // Step 2: Generate matrix A ∈ ℤ_q^{k×k}, each poly is NTT'd
    vector<vector<vector<i16>>> A(k, vector<vector<i16>>(k, vector<i16>(Kyber_N, 0))); 
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < k; j++) {
            A[i][j] = NTT_sample(a_seed, static_cast<ui8>(i), static_cast<ui8>(j));
        }
    }

    // Step 3: Sample secret s and error e from centered binomial distribution
    int n = 0;
    ui8 s_in[33];
    ui8 s_out[64 * eta1];
    for (int i = 0; i < 32; i++) {
        s_in[i] = s_seed[i];
    }

    vector<vector<i16>> s(k, vector<i16>(Kyber_N, 0));
    vector<vector<i16>> e(k, vector<i16>(Kyber_N, 0));
    vector<ui8> sample(64 * eta1, 0);

    for (int i = 0; i < k; i++) {
        s_in[32] = n++;
        FIPS202_SHAKE256(s_in, 33, s_out, 64 * eta1);
        for (int j = 0; j < 64 * eta1; j++) {
            sample[j] = s_out[j];
        }
        s[i] = Binomial_sample(sample, eta1);
    }

    for (int i = 0; i < k; i++) {
        s_in[32] = n++;
        FIPS202_SHAKE256(s_in, 33, s_out, 64 * eta1);
        for (int j = 0; j < 64 * eta1; j++) {
            sample[j] = s_out[j];
        }
        e[i] = Binomial_sample(sample, eta1);
    }

    // Step 4: Compute NTT(s) and NTT(e)
    vector<vector<i16>> s_ntt(k, vector<i16>(Kyber_N, 0));
    vector<vector<i16>> e_ntt(k, vector<i16>(Kyber_N, 0));
    for (int i = 0; i < k; i++) {
        s_ntt[i] = ntt(s[i]);
        e_ntt[i] = ntt(e[i]);
    }

    // Step 5: Compute t = A * s + e in NTT domain
    vector<vector<i16>> t_ntt(k, vector<i16>(Kyber_N, 0));
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < k; j++) {
            for (int l = 0; l < Kyber_N; l++) {
                t_ntt[i][l] = (t_ntt[i][l] + A[i][j][l] * s_ntt[j][l]) % Kyber_Q;
            }
        }
    }

    for (int i = 0; i < k; i++) {
        for (int l = 0; l < Kyber_N; l++) {
            t_ntt[i][l] = (t_ntt[i][l] + e_ntt[i][l]) % Kyber_Q;
        }
    }

    // Step 6: Encode keys
    vector<ui8> public_key(384 * k + 32, 0); // 384 bytes per poly + 32 bytes for a_seed
    vector<ui8> private_key(384 * k, 0);

    for (int i = 0; i < k; i++) {
        vector<ui8> temp = ByteEncode(t_ntt[i], 12);
        for (int j = 0; j < 384; j++) {
            public_key[384 * i + j] = temp[j];
        }
    }

    for (int i = 0; i < 32; i++) {
        public_key[384 * k + i] = a_seed[i];  // Append a_seed directly
    }

    for (int i = 0; i < k; i++) {
        vector<ui8> temp = ByteEncode(s_ntt[i], 12);
        for (int j = 0; j < 384; j++) {
            private_key[384 * i + j] = temp[j];
        }
    }

    // Step 7: Return key pair
    pair<vector<ui8>, vector<ui8>> result = {private_key, public_key};
    return result;
}

