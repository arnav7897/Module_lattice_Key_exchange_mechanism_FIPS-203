#include <iostream>
#include <vector>
#include <cstdlib>
#include <ctime>
#include <cstdint>
#include "ml-kem/sampling.hpp"
using namespace std;

typedef uint8_t ui8;
typedef int16_t i16;

// Declare your NTT_sample function here or include its header

bool test_ntt_roundtrip() {
    vector<ui8> seed(32);
    srand(time(0));
    for (int i = 0; i < 32; i++) seed[i] = rand() % 256;

    vector<i16> original = NTT_sample(seed, 0, 0); // includes montgomery encode
    vector<i16> test = original;

    ntt(test);
    invntt(test);

    bool success = true;
    for (int i = 0; i < 256; i++) {
        // decode from Montgomery domain
        int val = montgomery_reduce(test[i]);
        val = (val % Kyber_Q + Kyber_Q) % Kyber_Q;

        int orig = (original[i] * 1ULL * MONT) % Kyber_Q; // orig is already in Montgomery form
        orig = montgomery_reduce(orig);
        orig = (orig % Kyber_Q + Kyber_Q) % Kyber_Q;

        if (val != orig) {
            printf("Mismatch at index %d: got %d, expected %d ✗\n", i, val, orig);
            success = false;
        }
    }

    return success;
}

int main() {
    if (test_ntt_roundtrip()) {
        cout << " NTT round-trip successful!" << endl;
    } else {
        cout << " NTT round-trip failed!" << endl;
    }
    return 0;
}
