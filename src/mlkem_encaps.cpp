#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
#include "ml-kem/ML-KEM.hpp"
using namespace std;

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
    if (argc < 2) {
        cerr << "Usage: mlkem_encaps <public_key_hex>" << endl;
        return 1;
    }
    string pk_hex = argv[1];
    vector<ui8> pk = parse_hex(pk_hex);

    auto [shared_key, ciphertext] = ML_KEM_ENCAPSULATION(pk);
    print_hex(shared_key);
    print_hex(ciphertext);
    return 0;
}
