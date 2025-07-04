#include "ML-KEM.hpp"
#include<cstring> 
#include <random>
#include<iomanip>

/*************************************************
* Name:        ML_KEM_KeyGen_internal
*
* Description: Internal key generation function for ML-KEM.
*              Computes public and private keys using seed and z.
*
* Arguments:   - vector<ui8> &seed: 32-byte random seed
*              - vector<ui8> &z: 32-byte random value used for fallback
*
* Returns:     - pair of vectors: (public key ek, secret key decaps)
**************************************************/
pair<vector<ui8>,vector<ui8>> ML_KEM_KeyGen_internal(vector<ui8> &seed,vector<ui8> &z){
    auto [dk, ek] = K_PKE_KeyGen(seed);

    ui8 out[32];
    vector<ui8> decaps(768*Kyber_k + 96);   
    FIPS202_SHA3_256(ek.data(),ek.size(),out);
   
    memcpy(decaps.data(),dk.data(),384*Kyber_k);
    memcpy(decaps.data()+384*Kyber_k,ek.data(),384*Kyber_k+32);
    memcpy(decaps.data()+768*Kyber_k+32,out,32);
    memcpy(decaps.data()+768*Kyber_k+64,z.data(),32);
    
    return {ek, decaps};
}

/*************************************************
* Name:        ML_KEM_Encaps_internal
*
* Description: Internal encapsulation function for ML-KEM.
*              Computes ciphertext and session key from public key and message.
*
* Arguments:   - vector<ui8> &public_key: public key of recipient
*              - vector<ui8> &msg: 32-byte random message
*
* Returns:     - pair of vectors: (shared secret K, ciphertext c)
**************************************************/
pair<vector<ui8>,vector<ui8>> ML_KEM_Encaps_internal(vector<ui8> &public_key ,vector<ui8> &msg){
    
    ui8 in[64],out[64];
    vector<ui8> hash(32);
    vector<ui8> K(32);
    vector<ui8> r(32);
    
    FIPS202_SHA3_256(public_key.data(),384*Kyber_k+32,hash.data());
    
    memcpy(in,msg.data(),32);
    memcpy(in+32,hash.data(),32);
    
    FIPS202_SHA3_512(in,64,out);
    
    memcpy(K.data(),out,32);
    memcpy(r.data(),out+32,32);
    
    vector<ui8> c = K_PKE_Encrypt(public_key,msg,r);

    return{K,c};
} 

/*************************************************
* Name:        ML_KEM_Decaps_internal
*
* Description: Internal decapsulation function for ML-KEM.
*              Extracts session key from secret key and ciphertext.
*              If validation fails, returns pseudorandom key from z.
*
* Arguments:   - vector<ui8> &decaps: decapsulation key
*              - vector<ui8> &c: ciphertext
*
* Returns:     - vector<ui8>: shared secret K
**************************************************/
vector<ui8> ML_KEM_Decaps_internal(vector<ui8> &decaps, vector<ui8> &c) {
    vector<ui8> dk(384 * Kyber_k), ek(384 * Kyber_k + 32), hash_ek(32), z(32);

    memcpy(dk.data(), decaps.data(), 384 * Kyber_k);
    memcpy(ek.data(), decaps.data() + 384 * Kyber_k, 384 * Kyber_k + 32);
    memcpy(hash_ek.data(), decaps.data() + 768 * Kyber_k + 32, 32);
    memcpy(z.data(), decaps.data() + 768 * Kyber_k + 64, 32);

    vector<ui8> extracted_msg = K_PKE_Decrypt(dk, c);

    vector<ui8> k_dash(32), r_dash(32), out(64), in(64);
    memcpy(in.data(), extracted_msg.data(), 32);
    memcpy(in.data() + 32, hash_ek.data(), 32);

    FIPS202_SHA3_512(in.data(), 64, out.data());
    memcpy(k_dash.data(), out.data(), 32);
    memcpy(r_dash.data(), out.data() + 32, 32); 

    vector<ui8> c_dash = K_PKE_Encrypt(ek, extracted_msg, r_dash);

    bool flag = (c.size() == c_dash.size());
    for (size_t i = 0; i < c.size() && flag; i++) {
        if (c[i] != c_dash[i]) {
            flag = false;
            break;
        }
    }

    if(flag==false){
        vector<ui8> random_k(32);
        vector<ui8> in_random(32 + c.size());
        memcpy(in_random.data(), z.data(), 32);
        memcpy(in_random.data() + 32, c.data(), c.size());
        
        FIPS202_SHAKE128(in_random.data(), in_random.size(), random_k.data(), 32);
        return random_k;
    }else{
        return k_dash;
    }
}

/*************************************************
* Name:        ML_KEM_KEYGEN
*
* Description: Generates public and secret key pair for ML-KEM using RNG.
*
* Arguments:   None
*
* Returns:     - pair of vectors: (ek, decaps)
**************************************************/
pair<vector<ui8>,vector<ui8>> ML_KEM_KEYGEN(){
    vector<ui8> seed(64),d(32),z(32);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < 64; i++) {
        seed[i] = dis(gen);
    }
    FIPS202_SHAKE128(seed.data(),32,d.data(),32);
    FIPS202_SHAKE128(seed.data()+32,32,z.data(),32);
    if (d.empty() || z.empty()) {
        cerr<<"RNG FAILED "<<endl;
        return {}; 
    }
    auto [ek,dk] = ML_KEM_KeyGen_internal(d,z);
    return {ek,dk};
}

/*************************************************
* Name:        ML_KEM_ENCAPSULATION
*
* Description: High-level encapsulation API for ML-KEM.
*              Takes public key and returns ciphertext and shared secret.
*
* Arguments:   - vector<ui8> &public_key: recipient's public key
*
* Returns:     - pair of vectors: (shared secret K, ciphertext c)
**************************************************/
pair<vector<ui8>,vector<ui8>> ML_KEM_ENCAPSULATION(vector<ui8> &public_key){
    vector<ui8> seed(64),m(32);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < 64; i++) {
        seed[i] = dis(gen);
    }
    FIPS202_SHAKE128(seed.data(),32,m.data(),32);
      if (m.empty()) {
        cerr<<"RNG FAILED to process msg"<<endl;
        return {}; 
    }
    auto[K,c] = ML_KEM_Encaps_internal(public_key,m);
    return {K, c};
}

/*************************************************
* Name:        ML_KEM_DECAPSULATION
*
* Description: High-level decapsulation API for ML-KEM.
*              Takes secret key and ciphertext, returns shared secret.
*
* Arguments:   - vector<ui8> &decaps: private key
*              - vector<ui8> &c: ciphertext
*
* Returns:     - vector<ui8>: shared secret K
**************************************************/
vector<ui8> ML_KEM_DECAPSULATION(vector<ui8> &decaps, vector<ui8> &c){
    vector <ui8> K = ML_KEM_Decaps_internal(decaps,c);
    return K;
}