#include "K_PKE.hpp"

#include <cstring>

pair<vector<ui8>, vector<ui8>> K_PKE_KeyGen(vector<ui8>& seed) {
    if (seed.size() != 32) {

        return {};
    }

    // Step 1: seed expansion
    ui8 in[32], out[64];
    memcpy(in, seed.data(), 32);
    FIPS202_SHA3_512(in, 32, out);

    vector<ui8> a_seed(32), s_seed(32);
    memcpy(a_seed.data(), out, 32);
    memcpy(s_seed.data(), out + 32, 32);

    // Step 2: generate matrix A
    vector<vector<vector<i16>>> A(Kyber_k, vector<vector<i16>>(Kyber_k, vector<i16>(Kyber_N)));
    for (int i = 0; i < Kyber_k; i++) {
        for (int j = 0; j < Kyber_k; j++) {
            A[i][j] = NTT_sample(a_seed, static_cast<ui8>(j), static_cast<ui8>(i));
        }
    }

    // Step 3: Sample s and e
    ui8 s_in[33];
    memcpy(s_in, s_seed.data(), 32);
    ui8 s_out[64 * eta1];
    vector<ui8> sample(64 * eta1);
    vector<vector<i16>> s(Kyber_k, vector<i16>(Kyber_N));
    vector<vector<i16>> e(Kyber_k, vector<i16>(Kyber_N));
    int n = 0;

    for (int i = 0; i < Kyber_k; i++) {
        s_in[32] = n++;
        FIPS202_SHAKE256(s_in, 33, s_out, 64 * eta1);
        memcpy(sample.data(), s_out, sample.size());
        s[i] = Binomial_sample(sample, eta1);
    }

    for (int i = 0; i < Kyber_k; i++) {
        s_in[32] = n++;
        FIPS202_SHAKE256(s_in, 33, s_out, 64 * eta1);
        memcpy(sample.data(), s_out, sample.size());
        e[i] = Binomial_sample(sample, eta1);
    }

    // Step 4: NTT transform and reduce
    for (int i = 0; i < Kyber_k; i++) {
        ntt(s[i]);
        poly_reduce(s[i]);
        ntt(e[i]);
        poly_reduce(e[i]);
    }


    // Step 5: Compute t = As + e
    vector<vector<i16>> t_ntt(Kyber_k, vector<i16>(Kyber_N, 0));
    for (int i = 0; i < Kyber_k; i++) {
        for (int j = 0; j < Kyber_k; j++) {
            vector<i16> temp = poly_multiply_pointwise_mont(A[i][j], s[j]);
            t_ntt[i] = poly_add(t_ntt[i], temp);
        }
        poly_reduce(t_ntt[i]);
        poly_tomont(t_ntt[i]);
    }


    for (int i = 0; i < Kyber_k; i++) {
        t_ntt[i] = poly_add(t_ntt[i], e[i]);
        poly_reduce(t_ntt[i]);
    }

    // Step 6: Encode
    vector<ui8> public_key(384 * Kyber_k + 32, 0);
    vector<ui8> private_key(384 * Kyber_k, 0);

    for (int i = 0; i < Kyber_k; i++) {
        vector<ui8> temp = ByteEncode(t_ntt[i], 12);
        memcpy(public_key.data() + 384 * i, temp.data(), 384);
    }

    memcpy(public_key.data() + 384 * Kyber_k, a_seed.data(), 32);

    for (int i = 0; i < Kyber_k; i++) {
        vector<ui8> temp = ByteEncode(s[i], 12);
        memcpy(private_key.data() + 384 * i, temp.data(), 384);
    }

    return {private_key, public_key};
}

vector<ui8> K_PKE_Encrypt(vector<ui8> &public_key, vector<ui8> &msg, vector<ui8> &random) {
    vector<vector<ui8>> t_part(Kyber_k, vector<ui8>(384, 0));
    vector<ui8> a_seed(32, 0);

    // Extract seed from public key
    memcpy(a_seed.data(), public_key.data() + 384 * Kyber_k, 32);
    for (int i = 0; i < Kyber_k; i++) {
        memcpy(t_part[i].data(), public_key.data() + i * 384, 384);
    }
    // Decode t to get t_cap ∈ Z_q^Kyber_k x Kyber_N
    vector<vector<i16>> t_cap(Kyber_k, vector<i16>(Kyber_N, 0));
    for (int i = 0; i < Kyber_k; i++) {
        t_cap[i] = ByteDecode(t_part[i], 12);
    }

    // Generate matrix A ∈ Z_q^{Kyber_k x Kyber_k}
    vector<vector<vector<i16>>> A(Kyber_k, vector<vector<i16>>(Kyber_k, vector<i16>(Kyber_N, 0)));
    for (int i = 0; i < Kyber_k; i++) {
        for (int j = 0; j < Kyber_k; j++) {
            A[i][j] = NTT_sample(a_seed, static_cast<ui8>(i), static_cast<ui8>(j));
        }
    }

    // Sample secret y and error e1 from CBD_eta1 and e2 from CBD_eta2
    int n = 0; 
    ui8 y_in[33];
    ui8 y_out[64 * eta1];
    vector<ui8> sample(64 * eta1, 0);
    vector<vector<i16>> y(Kyber_k, vector<i16>(Kyber_N, 0));
    vector<vector<i16>> e1(Kyber_k, vector<i16>(Kyber_N, 0));

    for (int i = 0; i < 32; i++) y_in[i] = random[i];

    for (int i = 0; i < Kyber_k; i++) {
        y_in[32] = n++;
        FIPS202_SHAKE256(y_in, 33, y_out, 64 * eta1);
        for (int j = 0; j < 64 * eta1; j++) 
        {
            sample[j] = y_out[j];
        }
        y[i] = Binomial_sample(sample, eta1);
    }

    sample.resize(64 * eta2);
    for (int i = 0; i < Kyber_k; i++) {
        y_in[32] = n++;
        FIPS202_SHAKE256(y_in, 33, y_out, 64 * eta2); 
        e1[i] = Binomial_sample(sample, eta2);
    }

    // Sample error vector e2
    vector<i16> e2(Kyber_N);
    y_in[32] = n++;
    FIPS202_SHAKE256(y_in, 33, y_out, 64 * eta2);
    e2 = Binomial_sample(sample, eta2);

    // Apply NTT to y
    for (int i = 0; i < Kyber_k; i++) {
        ntt(y[i]);
        poly_reduce(y[i]);
    }

    // Compute u = InvNTT(A^T * y), v = InvNTT(t^T * y)
    vector<vector<i16>> u(Kyber_k, vector<i16>(Kyber_N, 0));
    vector<i16> v(Kyber_N, 0);
    for (int i = 0; i < Kyber_k; i++) {
        for (int j = 0; j < Kyber_k; j++) {
            vector<i16> temp_u = poly_multiply_pointwise_mont(A[i][j], y[j]);
            u[i] = poly_add(u[i], temp_u);
        }
        poly_reduce(u[i]);
        invntt(u[i]);
        vector<i16> temp_v = poly_multiply_pointwise_mont(t_cap[i], y[i]);
        v = poly_add(v, temp_v);
    }
    poly_reduce(v);
    invntt(v);
    // Encode message into mu ∈ Z_q^Kyber_N
    vector<i16> m_intermediate = ByteDecode(msg, 1);
    vector<i16> mu = Decompress(m_intermediate, 1);
    // Add errors
    for (int i = 0; i < Kyber_k; i++) {
        u[i] = poly_add(u[i], e1[i]);
        poly_reduce(u[i]);
    }
    v = poly_add(v, e2);
    v = poly_add(v, mu);
    poly_reduce(v);
    // Compress u and v, encode into ciphertext
    vector<ui8> c(32 * (Kyber_k * du + dv), 0); 
    vector<vector<ui8>> c1(Kyber_k, vector<ui8>(32 * du, 0));
    vector<ui8> c2(32 * dv, 0);

    for (int i = 0; i < Kyber_k; i++) {
        vector<i16> comp_u = Compress(u[i], du);
        c1[i] = ByteEncode(comp_u, du); 
    }
    vector<i16> comp_v = Compress(v, dv);
    c2 = ByteEncode(comp_v, dv);
    for (int i = 0; i < Kyber_k; i++) {
        for (int j = 0; j < 32 * du; j++) {
            c[i * 32 * du + j] = c1[i][j];
        }
    }
    for (int j = 0; j < 32 * dv; j++) {
        c[Kyber_k * 32 * du + j] = c2[j];
    }
    return c;
}



vector<ui8> K_PKE_Decrypt(vector<ui8> &secret_key, vector<ui8> &c){
    // step 1: extracting c1,c2 from cipher_text
    vector<vector<ui8>> c1(Kyber_k, vector<ui8>(32 * du, 0));
    vector<ui8> c2(32 * dv, 0);
    for (int i = 0; i < Kyber_k; i++) {
        for (int j = 0; j < 32 * du; j++) {
            c1[i][j] = c[i * 32 * du + j] ;
        }
    }
    for (int j = 0; j < 32 * dv; j++) {
        c2[j] = c[Kyber_k * 32 * du + j] ;
    }

    // step 2: extracting v and u also computing ntt(u) for w  
    vector<i16> v(Kyber_N,0);
    vector<vector<i16>> u(Kyber_k,vector<i16>(Kyber_N,0));
    for (int i = 0; i < Kyber_k; i++) {
        vector<i16> decode_u = ByteDecode(c1[i], du);
        u[i] = Decompress(decode_u, du);
        ntt(u[i]);
        poly_reduce(u[i]);
    }
    vector<i16> decode_v = ByteDecode(c2, dv);
    v = Decompress(decode_v, dv);

    // step 3: decode secret_key
    vector<vector<i16>> s(Kyber_k,vector<i16>(Kyber_N,0));
    for (int i = 0; i < Kyber_k; i++) {
        vector<ui8> temp(secret_key.begin() + i * 384, secret_key.begin() + (i + 1) * 384);
        s[i] = ByteDecode(temp, 12);  // Corrected
    }

// Step 4: Compute inner product of s^T * u
vector<i16> acc(Kyber_N, 0);
    for (int i = 0; i < Kyber_k; i++) {
        vector<i16> temp = poly_multiply_pointwise_mont(s[i],u[i]);
        acc = poly_add(acc,temp);
    }
    poly_reduce(acc);

    // Reduce modulo Q and apply InvNTT
    invntt(acc); 

    // Now subtract from v to get w
    vector<i16> w(Kyber_N);
    for (int i = 0; i < Kyber_N; i++)
        w[i] = v[i] - acc[i] ;
    poly_reduce(w);

    // step 5: extracting msg
    vector<i16> comp_w = Compress(w, 1);
    vector<ui8> msg = ByteEncode(comp_w, 1);

    return msg;
}