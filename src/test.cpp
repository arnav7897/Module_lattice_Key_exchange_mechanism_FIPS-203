#include <iostream>
#include <vector>
#include <iomanip>
#include "ml-kem/ML-KEM.hpp"

using namespace std;

// Define ui8 if not already defined
using ui8 = uint8_t;

// Forward declarations (assumes these are implemented in your ML-KEM .cpp/.hpp files)
pair<vector<ui8>, vector<ui8>> ML_KEM_KEYGEN();
pair<vector<ui8>, vector<ui8>> ML_KEM_ENCAPSULATION(vector<ui8> &public_key);
vector<ui8> ML_KEM_DECAPSULATION(vector<ui8> &decaps, vector<ui8> &c);

// Helper function to print hex
void print_hex(const string &label, const vector<ui8> &data) {
    cout << label << ": ";
    for (auto byte : data) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    cout << dec << endl;
}

int main() {
    cout << "=== ML-KEM Test ===" << endl;

    // Step 1: Key Generation
    auto [public_key, decaps_key] = ML_KEM_KEYGEN();
    cout << "[✓] Key generation complete" << endl;

    // Step 2: Encapsulation
    auto [shared_key_encaps, ciphertext] = ML_KEM_ENCAPSULATION(public_key);
    cout << "[✓] Encapsulation complete" << endl;

    // Step 3: Decapsulation
    vector<ui8> shared_key_decaps = ML_KEM_DECAPSULATION(decaps_key, ciphertext);
    cout << "[✓] Decapsulation complete" << endl;

    // Step 4: Output all values
    print_hex("Public Key", public_key);
    print_hex("Ciphertext", ciphertext);
    print_hex("Shared Key (Encaps)", shared_key_encaps);
    print_hex("Shared Key (Decaps)", shared_key_decaps);

    // Step 5: Check correctness
    if (shared_key_encaps == shared_key_decaps) {
        cout << "\n✅ Success: Shared keys match!" << endl;
        return 0;
    } else {
        cout << "\n❌ Failure: Shared keys do NOT match!" << endl;
        return 1;
    }
}
