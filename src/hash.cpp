#include <iostream>
#include <vector>
#include <random>
#include <iomanip>
#include "ml-kem/K_PKE.hpp"

using namespace std;

void print_bytes(const string& label, const vector<ui8>& data, size_t limit = 32) {
    cout << label << " (" << data.size() << " bytes): ";
    for (size_t i = 0; i < min(data.size(), limit); ++i) {
        cout << hex << setw(2) << setfill('0') << int(data[i]) << " ";
    }
    if (data.size() > limit) cout << "...";
    cout << dec << "\n";
}

int main() {
    // Generate random seed
    vector<ui8> seed(32), msg(32), r(32);
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);
    for (int i = 0; i < 32; i++) {
        seed[i] = dis(gen);
        msg[i] = dis(gen);
        r[i] = dis(gen);
    }
    print_bytes("message ",msg,32);
    // Key generation
    auto [sk, pk] = K_PKE_KeyGen(seed);

    print_bytes("Public Key", pk, 64);
    print_bytes("Secret Key", sk, 64);

    vector<ui8> cipher_text = K_PKE_Encrypt(pk,msg,r);
    print_bytes("cipher text",cipher_text,64);

    vector<ui8> msg_extracted = K_PKE_Decrypt(sk,cipher_text);
    print_bytes("extracted_message ",msg_extracted,32);
    return 0;
}
