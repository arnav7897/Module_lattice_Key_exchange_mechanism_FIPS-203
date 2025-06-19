#include "base.hpp"
// we assume that LSB is in 0rth index
vector<ui8> BitToByte(vector<bool> &a){
  if (a.size() % 8 != 0) {
        size_t new_size = ((a.size() + 7) / 8) * 8;
        a.resize(new_size, 0);  
    }
    size_t byte_size = a.size()/8;  
    vector<ui8> result(byte_size, 0);      
    for(int i = 0 ;i<a.size();i++){
         result[i / 8] |= (a[i] << (i % 8));
    }
    return result;
}

vector<bool> ByteToBit(vector<ui8> &a){
    size_t bit_size = a.size()*8;  
    vector<bool> result(bit_size, 0);      
    for(int i = 0 ;i<bit_size;i++){
        result[i] = (a[i / 8] >> (i % 8)) & 1;
    }
    return result;
}
// input integer array 𝐹 ∈ ℤ^256_𝑚 , where 𝑚 = 2^𝑑 if 𝑑 < 12, and 𝑚 = 𝑞 if 𝑑 = 12
// output byte array 𝐵 ∈ 𝔹32𝑑

// for (𝑗 ← 0; 𝑗 < 𝑑; 𝑗++)
// 4: 𝑏[𝑖⋅ 𝑑 + 𝑗] ← 𝑎 mod 2 ▷ 𝑏 ∈ {0,1}256⋅𝑑
// 5: 𝑎 ← (𝑎− 𝑏[𝑖⋅ 𝑑 + 𝑗])/2 ▷ note 𝑎 − 𝑏[𝑖 ⋅ 𝑑 + 𝑗] is always even
// 6: end for
// 7: end for
// 8: 𝐵 ← BitsToBytes(𝑏)
// 9: return 𝐵

vector<ui8> ByteEncode(vector<i16> &f, int d){
    vector<bool> b(256*d,0); // in d bits i can represent 1 integer
    for(int i = 0 ; i<256 ;i++){
        i16 a = f[i];
        for(int j =0 ;j<d;j++){
            b[i*d + j] = a % 2 ; 
            a = (a - b[i*d +j])/2;
        }
    }
    return BitToByte(b);
}

vector<i16> ByteDecode(vector<ui8> &b, int d){
    vector<bool> bit = ByteToBit(b); // bits must be 256*d
    if (bit.size() != 256*d){
        size_t new_size = 256*d;
        bit.resize(new_size, 0);  
    }
    vector<i16> f(256,0); // 256 total vectors i want 
    int m = (d<12)?(1<<d) : Kyber_Q;
    for(int i =0;i<256;i++){
        for(int j =0 ;j<d;j++){
            f[i] |= (bit[i*d+j] << j);
        }
        f[i] = f[i] %m;
    }
    return f;
}
// Compress𝑑 ∶ ℤ_𝑞 ⟶ ℤ_(2^𝑑)
// 𝑥 ⟼ ⌈(2𝑑/𝑞) ⋅ 𝑥⌋ mod 2𝑑 
vector<i16> Compress( vector<i16>& a, int d) {
    int numerator = 1 << d;  // 2^d
    vector<i16> result(a.size());
    for (size_t i = 0; i < a.size(); i++) {
        // Perform rounding and scaling: [0, Q) -> [0, 2^d)
        float scaled = static_cast<float>(a[i]) * numerator / Kyber_Q;
        int rounded = static_cast<int>(round(scaled)) % numerator;
        // Ensure non-negative result (optional, depends on your Q arithmetic)
        if (rounded < 0) rounded += numerator;
        result[i] = static_cast<i16>(rounded);
    }
    return result;
}

vector<i16> Decompress( vector<i16>& a, int d) {
    int numerator = 1 << d;  // 2^d
    vector<i16> result(a.size());
    for (size_t i = 0; i < a.size(); i++) {
        float scaled = static_cast<float>(a[i]) * Kyber_Q / numerator;
        int rounded = static_cast<int>(round(scaled)) % Kyber_Q;
        if (rounded < 0) rounded += Kyber_Q;
        result[i] = static_cast<i16>(rounded);
    }
    return result;
}
