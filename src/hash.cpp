#include <iostream>
#include <vector>
#include <random>
#include <iomanip>
#include "ml-kem/K_PKE.hpp"
// Include your Kyber keygen header here
// #include "k_pke.hpp"  // assuming K_PKE_KeyGen is declared there

using namespace std;

// --- Dummy Declaration (remove this when actual function is included)
pair<vector<ui8>, vector<ui8>> K_PKE_KeyGen(vector<ui8>& seed);

// Generate a random 32-byte seed
vector<ui8> random_seed() {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    vector<ui8> seed(32);
    for (int i = 0; i < 32; i++) {
        seed[i] = static_cast<ui8>(dis(gen));
    }
    return seed;
}

// Print a vector as hex
void print_hex(const vector<ui8>& data, size_t bytes = 16) {
    for (size_t i = 0; i < bytes && i < data.size(); i++) {
        cout << hex << setw(2) << setfill('0') << (int)data[i] << " ";
    }
    cout << dec << "\n";
}

int main() {
    vector<ui8> seed = random_seed();

    pair<vector<ui8>, vector<ui8>> keys = K_PKE_KeyGen(seed);
    vector<ui8> key_priv = keys.first;
    vector<ui8> key_pub = keys.second;

    cout << "Private Key Length: " << key_priv.size() << " bytes\n";
    cout << "Public Key Length : " << key_pub.size() << " bytes\n";

    cout << "\nFirst 16 bytes of Private Key:\n";
    print_hex(key_priv);

    cout << "\nFirst 16 bytes of Public Key:\n";
    print_hex(key_pub);

    return 0;
}
