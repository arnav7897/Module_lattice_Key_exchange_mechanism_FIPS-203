#include <iostream>
#include <vector>
#include <random>
#include <cassert>

#include "ml-kem/ntt.hpp"
#include "ml-kem/sampling.hpp"
#include "ml-kem/base.hpp"

using namespace std;

int main() {
    // Generate random polynomial a with values in [0, Kyber_Q)
    vector<i16> a(Kyber_N);
    vector<i16> test(Kyber_N);
    vector<ui8> encoded(Kyber_N);
    vector<i16> compress(Kyber_N);
    vector<i16> msg_extracted(Kyber_N);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<int> dist(0, Kyber_Q - 1);

    cout << "\n===== [TEST] compress() Function =====" << endl;
    for(int i =0 ;i<Kyber_N;i++){
        test[i] = dist(gen);
    }
    encoded = ByteEncode(test,1);
    msg_extracted = ByteDecode(encoded,1);
    for(int i =0 ;i<Kyber_N ;i++){
    if ((msg_extracted[i] & 1) != (test[i] & 1)) {
        printf("ByteDecode mismatch at %d: got %d, expected %d (LSB: %d vs %d)\n",
               i, msg_extracted[i], test[i],
               msg_extracted[i] & 1, test[i] & 1);
    }
    }
vector<i16> original(Kyber_N);
for (int i = 0; i < Kyber_N; i++) {
    original[i] = dist(gen);  // some value in [0, Q)
}
int d = 1;
vector<i16> compressed = Compress(original, d);
vector<i16> decompressed = Decompress(compressed, d);

// Check if the difference is within theoretical error bound
int max_allowed_error = Kyber_Q / (1 << (d + 1));

for (int i = 0; i < Kyber_N; i++) {
    int diff = abs(original[i] - decompressed[i]);
    if (diff > max_allowed_error) {
        printf("Index %d: Original = %d, Decompressed = %d, Diff = %d\n",
               i, original[i], decompressed[i], diff);
    }
}

    cout << "\n===== [TEST] NTT Round Trip =====" << endl;



    for (int i = 0; i < Kyber_N; i++) {
        a[i] = dist(gen);
    }

    




    // Save original copy
    vector<i16> a_orig = a;

    // Perform NTT and then inverse NTT
    vector<i16> A_ntt = ntt(a);
    invntt(A_ntt);

    // Verify a == invntt(ntt(a)) (mod Q)
    bool match = true;
    for (int i = 0; i < Kyber_N; i++) {
        int16_t red = montgomery_reduce(static_cast<int32_t>(A_ntt[i]));
        if ((red - a_orig[i] + Kyber_Q) % Kyber_Q != 0) {
            cout << "Mismatch at index " << i << ": orig=" << a_orig[i]
                 << " got=" << red << endl;
            match = false;
            break;
        }
    }

    if (match) cout << "[PASS] NTT round-trip test passed!" << endl;
    else cout << "[FAIL] NTT round-trip test failed." << endl;

    // ------------------------------------------------------------------------------------

    cout << "\n===== [TEST] NTT_sample() Function =====" << endl;

    // Fake 32-byte seed
    vector<ui8> seed(32);
    for (int i = 0; i < 32; i++) seed[i] = i;

    vector<i16> poly = NTT_sample(seed, 0, 0);

    // Check properties of output
    if (poly.size() != Kyber_N) {
        cout << "[FAIL] NTT_sample() output size mismatch: got " << poly.size() << endl;
        return 1;
    }

    bool all_in_range = true;
    for (int i = 0; i < Kyber_N; i++) {
        if (poly[i] < 0 || poly[i] >= Kyber_Q) {
            cout << "[FAIL] Out-of-range coefficient at index " << i << ": " << poly[i] << endl;
            all_in_range = false;
            break;
        }
    }

    if (all_in_range)
        cout << "[PASS] NTT_sample() produced valid polynomial of size 256 with coeffs ∈ [0, Q)" << endl;
    else
        cout << "[FAIL] Invalid coeffs in NTT_sample()." << endl;

    return 0;
}
