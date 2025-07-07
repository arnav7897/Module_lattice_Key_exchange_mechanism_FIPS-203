#include <iostream>
#include <vector>
#include <iomanip>
#include "ml-kem/ML-KEM.hpp"
using namespace std;
using ui8 = uint8_t;

void print_hex(const vector<ui8>& data) {
    for (auto byte : data) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    cout << endl;
}

int main() {
    auto [public_key, secret_key] = ML_KEM_KEYGEN();
    print_hex(public_key);
    print_hex(secret_key);
    return 0;
}
