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

// Input: encryption key ekPKE ∈ ᵔ1^384k+32.
// Input: message m ∈ ᵔ1^32.
// Input: randomness r ∈ ᵔ1^32.
// Output: ciphertext c ∈ ᵔ1^32(duk+dv).
vector<ui8> K_PKE_Encrypt(vector<ui8> &public_key, vector<ui8> &msg, vector<ui8> &random) {

    // Step 1: Extract t (public vector) and seed from public key
    vector<vector<ui8>> t_part(k, vector<ui8>(384, 0));
    vector<ui8> a_seed(32, 0);
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < 384; j++)
            t_part[i][j] = public_key[i * 384 + j];
    }
    for (int i = 0; i < 32; i++) {
        a_seed[i] = public_key[384 * k + i];
    }
    
    // Decode t to get t_cap ∈ Z_q^k x 256
    vector<vector<i16>> t_cap(k, vector<i16>(256, 0));
    for (int i = 0; i < k; i++) {
        t_cap[i] = ByteDecode(t_part[i], 12);
    }

    // Step 2: Generate matrix A ∈ Z_q^{k x k}, sampled and NTT'd
    vector<vector<vector<i16>>> A(k, vector<vector<i16>>(k, vector<i16>(Kyber_N, 0)));
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < k; j++) {
            A[i][j] = NTT_sample(a_seed, static_cast<ui8>(i), static_cast<ui8>(j));
        }
    }

    // Step 3: Sample secret y and error e1 from CBD_eta1 and e2 from CBD_eta2
    int n = 0;
    ui8 y_in[33];
    ui8 y_out[64 * eta1];
    vector<ui8> sample(64 * eta1, 0);

    // Copy randomness input
    for (int i = 0; i < 32; i++) y_in[i] = random[i];

    vector<vector<i16>> y(k, vector<i16>(Kyber_N, 0));
    vector<vector<i16>> e1(k, vector<i16>(Kyber_N, 0));
    for (int i = 0; i < k; i++) {
        y_in[32] = n++;
        FIPS202_SHAKE256(y_in, 33, y_out, 64 * eta1);
        for (int j = 0; j < 64 * eta1; j++) sample[j] = y_out[j];
        y[i] = Binomial_sample(sample, eta1);
    }

    sample.resize(64 * eta2);
    for (int i = 0; i < k; i++) {
        y_in[32] = n++;
        FIPS202_SHAKE256(y_in, 33, y_out, 64 * eta2);
        for (int j = 0; j < 64 * eta2; j++) sample[j] = y_out[j];
        e1[i] = Binomial_sample(sample, eta2);
    }

    // Step 4: Sample error vector e2 ∈ Z_q^256
    vector<i16> e2(256);
    y_in[32] = n++;
    FIPS202_SHAKE256(y_in, 33, y_out, 64 * eta2);
    for (int j = 0; j < 64 * eta2; j++) sample[j] = y_out[j];
    e2 = Binomial_sample(sample, eta2);

    // Step 5: Apply NTT on y
    vector<vector<i16>> y_ntt(k, vector<i16>(Kyber_N, 0));
    for (int i = 0; i < k; i++) y_ntt[i] = ntt(y[i]);

    // Step 6: Compute u = InvNTT(Transpose(A) * y) + e1
    vector<vector<i16>> u(k, vector<i16>(Kyber_N, 0));
    for (int i = 0; i < k; i++) {
        vector<i32> acc(Kyber_N, 0);
        for (int n = 0; n < Kyber_N; n++) {
            for (int j = 0; j < k; j++) {
                acc[n] += static_cast<i32>(A[j][i][n]) * static_cast<i32>(y[j][n]);
            }
        }
        vector<i16> temp(Kyber_N);
        for (int n = 0; n < Kyber_N; n++) {
            temp[n] = static_cast<i16>((acc[n] % Kyber_Q + Kyber_Q) % Kyber_Q);
        }
        invntt(temp);
        for (int n = 0; n < Kyber_N; n++) {
            int32_t res = static_cast<i32>(temp[n]) + static_cast<i32>(e1[i][n]);
            u[i][n] = static_cast<i16>((res % Kyber_Q + Kyber_Q) % Kyber_Q);
        }
    }

    // Step 7: Decode message to μ ∈ Z_q^256
    vector<i16> m_intermediate = ByteDecode(msg, 1);
    vector<i16> mu = Decompress(m_intermediate, 1);

    // Step 8: Compute v = InvNTT(t^T * y_ntt) + e2 + μ
    vector<i16> v(256, 0);
    vector<i32> v_acc(256, 0);
    for (int i = 0; i < k; i++) {
        for (int j = 0; j < 256; j++) {
            v_acc[j] += static_cast<i32>(t_cap[i][j]) * static_cast<i32>(y_ntt[i][j]);
        }
    }
    for (int i = 0; i < 256; i++) {
        int32_t sum = v_acc[i] + static_cast<i32>(e2[i]) + static_cast<i32>(mu[i]);
        v[i] = static_cast<i16>((sum % Kyber_Q + Kyber_Q) % Kyber_Q);
    }

    // Step 9: Compress u and v, then encode into ciphertext c
    vector<ui8> c(32 * (k * du + dv), 0);
    vector<vector<ui8>> c1(k, vector<ui8>(32 * du, 0));
    vector<ui8> c2(32 * dv, 0);

    for (int i = 0; i < k; i++) {
        vector<i16> comp_u = Compress(u[i], du);
        c1[i] = ByteEncode(comp_u, du);
    }
    vector<i16> comp_v = Compress(v, dv);
    c2 = ByteEncode(comp_v, dv);

    for (int i = 0; i < k; i++) {
        for (int j = 0; j < 32 * du; j++) {
            c[i * 32 * du + j] = c1[i][j];
        }
    }
    for (int j = 0; j < 32 * dv; j++) {
        c[k * 32 * du + j] = c2[j];
    }

    return c;
}

vector<ui8> K_PKE_Decrypt(vector<ui8> &secret_key, vector<ui8> &cipher_text){
    
}