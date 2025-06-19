#include "ml-kem/K_PKE.hpp"
#include <iostream>
#include <cstdlib> 
#include <ctime>    

using namespace std;

int main() {
    srand(static_cast<unsigned>(time(0)));

    vector<ui8> seed(32);
    for (int i = 0; i < 32; i++) seed[i] = rand() % 256;
    auto[key_sk, key_pk] = K_PKE_KeyGen(seed);
    cout << "Private Key Size: " << key_sk.size() << " bytes\n";
    cout << "Public Key Size:  " << key_pk.size() << " bytes\n";

    vector<ui8> message(32);
    for (int i = 0; i < 32; i++) message[i] = rand() % 256;

    vector<ui8> randomness(32);
    for (int i = 0; i < 32; i++) randomness[i] = rand() % 256;

    // Encrypt
    vector<ui8> ciphertext = K_PKE_Encrypt(key_pk, message, randomness);
    cout << "Ciphertext Size:  " << ciphertext.size() << " bytes\n";

    cout << "First 16 bytes of ciphertext: ";
    for (int i = 0; i < 16 && i < ciphertext.size(); i++) {
        printf("%02x ", ciphertext[i]);
    }
    cout << "\n";

    return 0;
}
