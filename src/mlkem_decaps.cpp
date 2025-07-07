#include <iostream>
#include <vector>
#include <iomanip>
#include "ml-kem/ML-KEM.hpp"
using namespace std;
using ui8 = uint8_t;

vector<ui8> ML_KEM_DECAPSULATION(vector<ui8>& sk, vector<ui8>& ct);

vector<ui8> parse_hex(const string& hexstr) {
    vector<ui8> result;
    for (size_t i = 0; i < hexstr.length(); i += 2) {
        string byte_str = hexstr.substr(i, 2);
        ui8 byte = static_cast<ui8>(stoi(byte_str, nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

void print_hex(const vector<ui8>& data) {
    for (auto byte : data) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte);
    }
    cout << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cerr << "Usage: mlkem_decaps <secret_key_hex> <ciphertext_hex>" << endl;
        return 1;
    }
    vector<ui8> sk = parse_hex(argv[1]);
    vector<ui8> ct = parse_hex(argv[2]);

    vector<ui8> shared_key = ML_KEM_DECAPSULATION(sk, ct);
    print_hex(shared_key);
    return 0;
}
